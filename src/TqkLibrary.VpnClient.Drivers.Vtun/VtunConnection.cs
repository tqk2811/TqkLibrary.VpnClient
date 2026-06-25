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
using TqkLibrary.VpnClient.Ethernet;
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
        VtunPacketChannel? _channel;                 // tun mode (L3)
        VtunEthernetChannel? _etherChannel;          // tap mode (L2)
        ArpResolver? _arp;                           // tap mode: ARP/NDISC for the L2<->L3 bridge
        VirtualHost? _virtualHost;                   // tap mode: the Ethernet→IP bridge bound to the facade
        Action<byte[]>? _deliverData;                // routes an inbound data-frame payload to the active channel
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

            // 2) The driver supports 'type tun' (L3 bare IP) and 'type ether' (L2 tap, bridged to L3 via the Ethernet
            //    fabric); pipe/tty are unsupported. The server dictates these, so a mismatch is a server-config problem.
            VtunHostFlags linkType = flags & VtunHostFlags.TypeMask;
            if (linkType != VtunHostFlags.Tun && linkType != VtunHostFlags.Ether)
                throw new VpnConnectionException(
                    $"vtun server selected an unsupported link type ({linkType}); this driver supports 'type tun' and 'type ether' only.");
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

            // 3) Bind the data plane behind the stable facade — tun (L3) or tap (L2 bridged to L3).
            long now = Now();
            _lastReceivedMs = now;
            _lastSentMs = now;
            if (linkType == VtunHostFlags.Ether)
                BindTapChannel();
            else
                BindTunChannel();

            _dataActive = true;
            MarkRunning();

            // 4) Start the receive loop and keepalive timer.
            _receiveTask = Task.Run(() => ReceiveLoopAsync(loopToken), loopToken);
            _keepaliveRunning = true;
            _keepaliveTimer = new System.Threading.Timer(_ => _ = KeepaliveTickAsync(), null, KeepaliveTick, KeepaliveTick);

            Logger.LogHandshakeCompleted(DriverName);
            MarkConnected();
        }

        // ---- data-plane binding (tun L3 vs tap L2) ----

        // tun mode: the data frame payload IS a bare IP packet — bind the L3 channel straight to the facade.
        void BindTunChannel()
        {
            var channel = new VtunPacketChannel(
                send: (packet, ct) => SendDataFrameAsync(packet, ct),
                mtu: _config.Mtu,
                onPacketSent: () => _lastSentMs = Now(),
                onPacketReceived: () => _lastReceivedMs = Now());
            _channel = channel;
            _deliverData = payload => channel.Deliver(payload);
            Facade.SetInner(channel);
        }

        // tap mode: the data frame payload is a raw Ethernet frame — carry it on an L2 channel and bridge it to L3 via
        // the userspace Ethernet fabric (ARP + VirtualHost), exactly like the n2n / SoftEther tap drivers.
        void BindTapChannel()
        {
            MacAddress mac = ResolveMac();
            var channel = new VtunEthernetChannel(
                srcMac: mac.ToArray(),
                send: (frame, ct) => SendDataFrameAsync(frame, ct),
                mtu: _config.Mtu,
                onFrameSent: () => _lastSentMs = Now(),
                onFrameReceived: () => _lastReceivedMs = Now());
            _etherChannel = channel;
            _deliverData = payload => channel.Deliver(payload);

            IPAddress overlay = _config.TunnelAddress ?? IPAddress.Any;
            var arp = new ArpResolver(mac, overlay, channel);
            _arp = arp;
            var virtualHost = new VirtualHost(mac, channel, arp);
            virtualHost.InboundNonIpFrame += arp.HandleInboundFrame; // ARP requests/replies arrive on the non-IP seam
            _virtualHost = virtualHost;

            _tunnelConfig.Mtu = virtualHost.Mtu; // link − 14: the bound stack clamps MSS for the Ethernet header
            Facade.SetInner(virtualHost);
        }

        // The tap MAC: parsed from config, or a deterministic locally-administered MAC derived from the tunnel address.
        MacAddress ResolveMac()
        {
            if (!string.IsNullOrEmpty(_config.MacAddress) && MacAddress.TryParse(_config.MacAddress, out MacAddress parsed))
                return parsed;
            // 02:00:xx:xx:xx:xx — locally-administered/unicast, low 4 octets from the tunnel address (stable per host).
            byte[] octets = new byte[6];
            octets[0] = 0x02;
            byte[] addr = (_config.TunnelAddress ?? IPAddress.Loopback).GetAddressBytes();
            for (int i = 0; i < 4 && i < addr.Length; i++) octets[2 + i] = addr[addr.Length - 4 + i];
            return MacAddress.FromBytes(octets);
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
                            _deliverData?.Invoke(control.LastPayload);
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

            VirtualHost? host = _virtualHost; _virtualHost = null;
            if (host != null) { try { await host.DisposeAsync().ConfigureAwait(false); } catch { } }
            ArpResolver? arp = _arp; _arp = null;
            if (arp != null) { try { await arp.DisposeAsync().ConfigureAwait(false); } catch { } }
            VtunEthernetChannel? ether = _etherChannel; _etherChannel = null;
            if (ether != null) { try { await ether.DisposeAsync().ConfigureAwait(false); } catch { } }

            IByteStreamTransport? stream = _stream;
            _stream = null;
            if (stream != null) { try { await stream.DisposeAsync().ConfigureAwait(false); } catch { } }

            _control = null;
            _channel = null;
            _deliverData = null;
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
