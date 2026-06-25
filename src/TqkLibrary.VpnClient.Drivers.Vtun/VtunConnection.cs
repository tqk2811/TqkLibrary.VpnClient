using System.Net;
using Microsoft.Extensions.Logging;
using TqkLibrary.VpnClient.Abstractions.Diagnostics.Enums;
using TqkLibrary.VpnClient.Abstractions.Diagnostics.Extensions;
using TqkLibrary.VpnClient.Abstractions.Drivers;
using TqkLibrary.VpnClient.Abstractions.Drivers.Models;
using TqkLibrary.VpnClient.Abstractions.Net;
using TqkLibrary.VpnClient.Abstractions.Transport.Interfaces;
using TqkLibrary.VpnClient.Drivers.Core;
using TqkLibrary.VpnClient.Drivers.Vtun.Config;
using TqkLibrary.VpnClient.Drivers.Vtun.DataChannel;
using TqkLibrary.VpnClient.Drivers.Vtun.Enums;
using TqkLibrary.VpnClient.Drivers.Vtun.Transport;
using TqkLibrary.VpnClient.Vtun.Wire;
using TqkLibrary.VpnClient.Vtun.Wire.Enums;
using TqkLibrary.VpnClient.Vtun.Wire.Interfaces;

namespace TqkLibrary.VpnClient.Drivers.Vtun
{
    /// <summary>
    /// A complete vtun (vtund-compatible) client to a single host over <c>proto tcp</c>. It opens one TCP connection,
    /// runs the challenge-response authentication (<see cref="VtunControlChannel.AuthenticateAsync"/>), checks the
    /// server-dictated flags name a <c>tun</c> link, then carries bare IP packets as length-prefixed data frames behind a
    /// stable <see cref="Abstractions.Channels.SwappablePacketChannel"/>. A background loop reads frames (data → the L3
    /// channel; <c>VTUN_ECHO_REQ</c> → reply; <c>VTUN_CONN_CLOSE</c>/EOF → link-loss); a keepalive timer sends
    /// <c>VTUN_ECHO_REQ</c> when the link is idle and trips link-loss when the peer goes silent. The supervisor /
    /// auto-reconnect (roadmap F.6) re-establishes a dead tunnel, mirroring the tinc / OpenVPN drivers.
    /// <para>⚠️ vtun's auth keys a Blowfish-ECB challenge with MD5(password); with <c>encrypt no</c> the data plane is
    /// cleartext. Both are legacy/weak — this driver exists only to interoperate with the vtund daemon.</para>
    /// </summary>
    public sealed class VtunConnection : ReconnectingVpnConnection<VtunConnectionState>, IDisposable, IAsyncDisposable
    {
        // vtun's default keepalive is 30s interval / 4 missed before timeout. Use the same idle interval; a missed-echo
        // window of interval × maxfail trips link-loss.
        static readonly TimeSpan KeepaliveTick = TimeSpan.FromSeconds(1);
        const int KeepaliveIntervalSeconds = 30;
        const int KeepaliveMaxFail = 4;

        readonly string _host;
        readonly int _port;
        readonly VtunConfig _config;
        readonly IVtunTransportFactory _transportFactory;
        readonly AddressFamilyPreference _addressFamilyPreference;
        readonly IHostResolver _hostResolver;
        readonly TunnelConfig _tunnelConfig;

        IByteStreamTransport? _stream;
        VtunControlChannel? _control;
        VtunPacketChannel? _channel;
        CancellationTokenSource? _loopCts;
        Task? _receiveTask;
        System.Threading.Timer? _keepaliveTimer;

        long _lastReceivedMs;
        long _lastSentMs;
        volatile bool _dataActive;
        volatile bool _keepaliveRunning;

        /// <summary>
        /// Creates a connection. <paramref name="config"/> is the static profile; <paramref name="transportFactory"/>
        /// opens the TCP connection (an in-process factory drives it offline). <paramref name="loggerFactory"/> receives
        /// diagnostic traces (null = no logging).
        /// </summary>
        public VtunConnection(string host, int port, VtunConfig config, IVtunTransportFactory transportFactory,
            VtunReconnectOptions? reconnectOptions = null,
            AddressFamilyPreference addressFamilyPreference = AddressFamilyPreference.Auto,
            IHostResolver? hostResolver = null,
            Func<long>? clock = null,
            ILoggerFactory? loggerFactory = null)
            : base(VtunDriverConstants.DriverName, reconnectOptions ?? new VtunReconnectOptions(), clock, loggerFactory)
        {
            _host = host ?? throw new ArgumentNullException(nameof(host));
            _port = port;
            _config = config ?? throw new ArgumentNullException(nameof(config));
            _transportFactory = transportFactory ?? throw new ArgumentNullException(nameof(transportFactory));
            _addressFamilyPreference = addressFamilyPreference;
            _hostResolver = hostResolver ?? DnsHostResolver.Default;
            _tunnelConfig = config.ToTunnelConfig();
        }

        /// <summary>The static tunnel configuration (tunnel address, DNS, routes, MTU).</summary>
        public TunnelConfig Config => _tunnelConfig;

        /// <summary>The local tunnel (overlay) address, if configured.</summary>
        public IPAddress? AssignedAddress => _config.TunnelAddress;

        /// <summary>The host flags the server returned (valid after connect).</summary>
        public VtunHostFlags ServerFlags => _control?.ServerFlags ?? VtunHostFlags.None;

        /// <inheritdoc/>
        protected override VtunConnectionState DisconnectedState => VtunConnectionState.Disconnected;
        /// <inheritdoc/>
        protected override VtunConnectionState ConnectingState => VtunConnectionState.Connecting;
        /// <inheritdoc/>
        protected override VtunConnectionState ConnectedState => VtunConnectionState.Connected;
        /// <inheritdoc/>
        protected override VtunConnectionState ReconnectingState => VtunConnectionState.Reconnecting;

        /// <summary>Runs the handshake and returns once the tunnel is carrying traffic.</summary>
        public Task ConnectAsync(CancellationToken cancellationToken = default) => ConnectCoreAsync(cancellationToken);

        // ---- one full tunnel attempt (reused by the first connect and every reconnect) ----

        /// <inheritdoc/>
        protected override async Task EstablishAsync(CancellationToken cancellationToken)
        {
            await CleanupAttemptResourcesAsync().ConfigureAwait(false);
            _dataActive = false;

            IPAddress serverIp = await _hostResolver.ResolveAsync(_host, _addressFamilyPreference, cancellationToken).ConfigureAwait(false);
            _loopCts = CancellationTokenSource.CreateLinkedTokenSource(LifetimeToken, cancellationToken);
            CancellationToken loopToken = _loopCts.Token;

            IByteStreamTransport stream = await _transportFactory.ConnectAsync(new IPEndPoint(serverIp, _port), cancellationToken).ConfigureAwait(false);
            _stream = stream;
            var control = new VtunControlChannel(stream);
            _control = control;

            // 1) Authenticate (greeting → HOST → challenge → response → flags).
            Logger.LogHandshake(DriverName, $"authenticating as host '{_config.HostName}' (challenge-response)");
            VtunHostFlags flags = await control.AuthenticateAsync(_config.HostName, _config.Password, cancellationToken).ConfigureAwait(false);
            Logger.LogHandshake(DriverName, $"authenticated; server flags = {flags}");

            // 2) The driver carries bare IP packets — require a tun link over TCP. (tap/L2 is a stretch goal; ether/pipe/tty
            //    are unsupported here.) The server dictates these, so a mismatch is a server-config problem.
            if ((flags & VtunHostFlags.TypeMask) != VtunHostFlags.Tun)
                throw new VpnConnectionException(
                    $"vtun server selected an unsupported link type ({flags & VtunHostFlags.TypeMask}); this driver supports 'type tun' only.");
            if ((flags & VtunHostFlags.ProtocolMask) == VtunHostFlags.Udp)
                throw new VpnConnectionException("vtun server selected 'proto udp'; this driver supports 'proto tcp' only.");
            if ((flags & (VtunHostFlags.Zlib | VtunHostFlags.Lzo)) != 0)
                throw new VpnConnectionException(
                    $"vtun server enabled an unsupported feature ({flags & (VtunHostFlags.Zlib | VtunHostFlags.Lzo)}); this driver supports 'compress no' only.");

            // 2b) Data-plane encryption: when the server selected 'encrypt', resolve and install the matching transform.
            //     The default cipher (Blowfish-128-ECB / legacy bare-'E') is supported; any other id is named in the error.
            if ((flags & VtunHostFlags.Encrypt) != 0)
            {
                VtunCipher serverCipher = VtunFrameTransformFactory.FromCipherId(control.ServerCipherId);
                IVtunFrameTransform? transform = VtunFrameTransformFactory.TryCreate(serverCipher, _config.Password);
                if (transform is null)
                    throw new VpnConnectionException(
                        $"vtun server selected an unsupported data-plane cipher ({serverCipher}); this driver supports Blowfish-128-ECB ('encrypt yes' / legacy 'E') only.");
                control.DataTransform = transform;
                Logger.LogHandshake(DriverName, $"data-plane encryption enabled: {serverCipher}");
            }

            // 3) Bind the L3 packet channel behind the stable facade.
            long now = Now();
            _lastReceivedMs = now;
            _lastSentMs = now;
            var channel = new VtunPacketChannel(
                send: (packet, ct) => SendDataFrameAsync(packet, ct),
                mtu: _config.Mtu,
                onPacketSent: () => _lastSentMs = Now(),
                onPacketReceived: () => _lastReceivedMs = Now());
            _channel = channel;
            Facade.SetInner(channel);

            _dataActive = true;
            MarkRunning();

            // 4) Start the receive loop and keepalive timer.
            _receiveTask = Task.Run(() => ReceiveLoopAsync(loopToken), loopToken);
            _keepaliveRunning = true;
            _keepaliveTimer = new System.Threading.Timer(_ => _ = KeepaliveTickAsync(), null, KeepaliveTick, KeepaliveTick);

            Logger.LogHandshakeCompleted(DriverName);
            MarkConnected();
        }

        // ---- data plane ----

        ValueTask SendDataFrameAsync(ReadOnlyMemory<byte> ipPacket, CancellationToken cancellationToken)
        {
            VtunControlChannel? control = _control;
            if (control is null || !_dataActive) return default;
            return SendDataFrameCoreAsync(control, ipPacket, cancellationToken);
        }

        async ValueTask SendDataFrameCoreAsync(VtunControlChannel control, ReadOnlyMemory<byte> ipPacket, CancellationToken cancellationToken)
        {
            try
            {
                await control.WriteDataFrameAsync(ipPacket, cancellationToken).ConfigureAwait(false);
                _lastSentMs = Now();
            }
            catch (ObjectDisposedException) { }                  // torn down by a concurrent reconnect
            catch (System.Net.Sockets.SocketException) { }       // transient — the link-loss path handles it
            catch (System.IO.IOException) { }
        }

        async Task ReceiveLoopAsync(CancellationToken cancellationToken)
        {
            VtunControlChannel control = _control!;
            try
            {
                while (!cancellationToken.IsCancellationRequested)
                {
                    VtunFrameHeader header = await control.ReadFrameAsync(cancellationToken).ConfigureAwait(false);
                    _lastReceivedMs = Now();   // any inbound frame (incl. echo) proves the peer is alive
                    switch (header.Type)
                    {
                        case VtunFrameType.Data:
                            _channel?.Deliver(control.LastPayload);
                            break;
                        case VtunFrameType.EchoRequest:
                            // Reply so the peer's keepalive sees us alive (vtun's lfd_linker behaviour).
                            await control.WriteControlFrameAsync(VtunFrameType.EchoReply, cancellationToken).ConfigureAwait(false);
                            break;
                        case VtunFrameType.EchoReply:
                            break; // liveness already recorded above
                        case VtunFrameType.ConnClose:
                            OnLinkLost("vtun server sent CONN_CLOSE");
                            return;
                        case VtunFrameType.BadFrame:
                            Logger.LogPacketDropped(DriverName, VpnDropReason.Malformed, "vtun bad/oversized frame");
                            break;
                    }
                }
            }
            catch (OperationCanceledException) { }
            catch (System.IO.EndOfStreamException) { OnLinkLost("vtun connection closed by peer"); }
            catch (Exception ex)
            {
                Logger.LogPacketDropped(DriverName, VpnDropReason.Unexpected, $"vtun receive loop error: {ex.GetType().Name}: {ex.Message}");
                OnLinkLost("vtun receive loop ended");
            }
        }

        // ---- keepalive: send an echo request when idle; trip link-loss when the peer goes silent ----

        async Task KeepaliveTickAsync()
        {
            if (!_keepaliveRunning) return;
            long now = Now();

            // Peer dead: no inbound frame within interval × maxfail.
            if (now - _lastReceivedMs > KeepaliveIntervalSeconds * KeepaliveMaxFail * 1000L)
            {
                OnLinkLost("vtun keepalive: no data from the server within the timeout.");
                return;
            }
            // Idle: nothing sent for an interval — send an echo request.
            if (now - _lastSentMs >= KeepaliveIntervalSeconds * 1000L)
            {
                VtunControlChannel? control = _control;
                if (control is null) return;
                try
                {
                    await control.WriteControlFrameAsync(VtunFrameType.EchoRequest).ConfigureAwait(false);
                    _lastSentMs = now;
                    Logger.LogKeepalive(DriverName, "sent vtun echo request");
                }
                catch { /* a missed echo trips the timeout later */ }
            }
        }

        // ---- teardown ----

        /// <inheritdoc/>
        public override async Task DisconnectAsync(CancellationToken cancellationToken = default)
        {
            // Best-effort CONN_CLOSE so the server drops the session at once.
            VtunControlChannel? control = _control;
            if (control != null && _dataActive)
            {
                try { await control.WriteControlFrameAsync(VtunFrameType.ConnClose, cancellationToken).ConfigureAwait(false); } catch { }
            }
            await DisconnectCoreAsync().ConfigureAwait(false);
        }

        /// <inheritdoc/>
        protected override async Task CleanupAttemptResourcesAsync()
        {
            StopAttemptLoop();

            CancellationTokenSource? loop = _loopCts;
            _loopCts = null;
            try { loop?.Cancel(); } catch { }

            Task? receive = _receiveTask;
            _receiveTask = null;
            if (receive != null) { try { await receive.ConfigureAwait(false); } catch { } }
            loop?.Dispose();

            IByteStreamTransport? stream = _stream;
            _stream = null;
            if (stream != null) { try { await stream.DisposeAsync().ConfigureAwait(false); } catch { } }

            _control = null;
            _channel = null;
        }

        /// <inheritdoc/>
        protected override void StopAttemptLoop()
        {
            _keepaliveRunning = false;
            _dataActive = false;
            _keepaliveTimer?.Dispose();
            _keepaliveTimer = null;
        }

        /// <inheritdoc/>
        public async ValueTask DisposeAsync()
        {
            try { await DisconnectAsync().ConfigureAwait(false); } catch { }
            await DisposeCoreAsync().ConfigureAwait(false);
        }

        /// <inheritdoc/>
        public void Dispose() => DisposeAsync().AsTask().GetAwaiter().GetResult();
    }
}
