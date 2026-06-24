using System.Buffers.Binary;
using System.Net;
using Microsoft.Extensions.Logging;
using TqkLibrary.VpnClient.Abstractions.Diagnostics.Enums;
using TqkLibrary.VpnClient.Abstractions.Diagnostics.Extensions;
using TqkLibrary.VpnClient.Abstractions.Drivers;
using TqkLibrary.VpnClient.Abstractions.Drivers.Models;
using TqkLibrary.VpnClient.Abstractions.Net;
using TqkLibrary.VpnClient.Abstractions.Transport.Interfaces;
using TqkLibrary.VpnClient.Drivers.Core;
using TqkLibrary.VpnClient.Drivers.ZeroTier.Config;
using TqkLibrary.VpnClient.Drivers.ZeroTier.DataChannel;
using TqkLibrary.VpnClient.Drivers.ZeroTier.Enums;
using TqkLibrary.VpnClient.Drivers.ZeroTier.Transport;
using TqkLibrary.VpnClient.Ethernet;
using TqkLibrary.VpnClient.ZeroTier.Identity.Models;
using TqkLibrary.VpnClient.ZeroTier.Vl1;
using TqkLibrary.VpnClient.ZeroTier.Vl1.Enums;
using TqkLibrary.VpnClient.ZeroTier.Vl1.Models;
using TqkLibrary.VpnClient.ZeroTier.Vl2;
using TqkLibrary.VpnClient.ZeroTier.Vl2.Models;

namespace TqkLibrary.VpnClient.Drivers.ZeroTier
{
    /// <summary>
    /// A complete ZeroTier (VL1/VL2) client. It opens a UDP transport to the upstream node / controller, runs the VL1
    /// <c>HELLO ⇄ OK</c> handshake (Curve25519 identity agreement → Salsa20/12 + Poly1305 session), joins a VL2 network
    /// by asking the controller for its configuration (<c>NETWORK_CONFIG_REQUEST</c> → assigned IP + certificate of
    /// membership), then carries full Ethernet frames as VL2 <c>EXT_FRAME</c> messages behind an L2
    /// <see cref="ZeroTierEthernetChannel"/>. That channel plugs into the userspace Ethernet fabric
    /// (<see cref="ArpResolver"/> on the overlay IP + a <see cref="VirtualHost"/> bridge), which exposes the stable L3
    /// <see cref="ReconnectingVpnConnection{TState}.PacketChannel"/> the IP stack binds — mirroring the n2n / SoftEther
    /// drivers. An <c>ECHO</c> keepalive holds the VL1 path open and the shared supervisor / auto-reconnect (roadmap F.6)
    /// re-establishes a dead tunnel. Not a server / controller — those roles live only in tests. Planet/moon root
    /// discovery is out of scope: the client peers directly with the node/controller in its config.
    /// </summary>
    public sealed class ZeroTierConnection : ReconnectingVpnConnection<ZeroTierConnectionState>, IDisposable, IAsyncDisposable
    {
        readonly string _host;
        readonly int _port;
        readonly ZeroTierConfig _config;
        readonly IZeroTierTransportFactory _transportFactory;
        readonly AddressFamilyPreference _addressFamilyPreference;
        readonly IHostResolver _hostResolver;
        readonly TimeSpan _handshakeTimeout;

        readonly Vl1PacketCodec _packetCodec = new();
        readonly HelloMessageCodec _helloCodec = new();
        readonly OkMessageCodec _okCodec = new();
        readonly NetworkConfigCodec _networkConfigCodec = new();
        readonly Vl2FrameCodec _frameCodec = new();
        readonly byte[] _sessionKey;          // 64-byte VL1 shared key (first 32 = Salsa20 key)
        readonly ZeroTierAddress _localAddress;
        readonly ZeroTierAddress _peerAddress;

        IDatagramTransport? _transport;
        CancellationTokenSource? _loopCts;
        Task? _receiveTask;
        System.Threading.Timer? _timer;
        volatile bool _timerRunning;

        ZeroTierEthernetChannel? _channel;
        ArpResolver? _arp;
        VirtualHost? _host2;
        TunnelConfig? _tunnelConfig;

        TaskCompletionSource<OkHelloMessage>? _okHelloTcs;
        ulong _helloPacketId;
        ulong _helloTimestamp;
        TaskCompletionSource<ZeroTierNetworkConfig>? _networkConfigTcs;

        readonly System.Security.Cryptography.RandomNumberGenerator _rng = System.Security.Cryptography.RandomNumberGenerator.Create();

        /// <summary>
        /// Creates a connection. <paramref name="config"/> is the static client profile (this node's identity + the
        /// peer's, the network id, the optional static overlay IP); <paramref name="transportFactory"/> opens the UDP
        /// socket (an in-process factory drives it offline). <paramref name="clock"/> supplies the millisecond clock
        /// (tests inject a deterministic one); <paramref name="loggerFactory"/> receives diagnostic traces (null = no-op).
        /// </summary>
        public ZeroTierConnection(string host, int port, ZeroTierConfig config, IZeroTierTransportFactory transportFactory,
            ZeroTierReconnectOptions? reconnectOptions = null,
            AddressFamilyPreference addressFamilyPreference = AddressFamilyPreference.Auto,
            IHostResolver? hostResolver = null,
            TimeSpan? handshakeTimeout = null,
            Func<long>? clock = null,
            ILoggerFactory? loggerFactory = null)
            : base(ZeroTierDriverConstants.DriverName, reconnectOptions ?? new ZeroTierReconnectOptions(), clock, loggerFactory)
        {
            _host = host ?? throw new ArgumentNullException(nameof(host));
            _port = port;
            _config = config ?? throw new ArgumentNullException(nameof(config));
            _transportFactory = transportFactory ?? throw new ArgumentNullException(nameof(transportFactory));
            _addressFamilyPreference = addressFamilyPreference;
            _hostResolver = hostResolver ?? DnsHostResolver.Default;
            _handshakeTimeout = handshakeTimeout ?? TimeSpan.FromSeconds(10);

            if (!config.Identity.HasPrivate)
                throw new ArgumentException("ZeroTierConfig.Identity must include a private key (identity.secret).", nameof(config));
            _sessionKey = new Vl1KeyDerivation().DeriveSharedKey(config.Identity.Curve25519Private, config.PeerIdentity.Curve25519Public);
            _localAddress = config.Identity.Address;
            _peerAddress = config.PeerIdentity.Address;
        }

        /// <summary>The static tunnel configuration (overlay address, prefix, DNS, routes, MTU); valid after connect.</summary>
        public TunnelConfig Config => _tunnelConfig ?? throw new InvalidOperationException("not connected");

        /// <summary>The effective overlay (tunnel) IPv4 address (pinned or controller-assigned); valid after connect.</summary>
        public IPAddress AssignedAddress => _tunnelConfig?.AssignedAddress ?? throw new InvalidOperationException("not connected");

        /// <inheritdoc/>
        protected override ZeroTierConnectionState DisconnectedState => ZeroTierConnectionState.Disconnected;
        /// <inheritdoc/>
        protected override ZeroTierConnectionState ConnectingState => ZeroTierConnectionState.Connecting;
        /// <inheritdoc/>
        protected override ZeroTierConnectionState ConnectedState => ZeroTierConnectionState.Connected;
        /// <inheritdoc/>
        protected override ZeroTierConnectionState ReconnectingState => ZeroTierConnectionState.Reconnecting;

        /// <summary>Runs the VL1 handshake + VL2 join and returns once the L2 tunnel is carrying traffic.</summary>
        public Task ConnectAsync(CancellationToken cancellationToken = default) => ConnectCoreAsync(cancellationToken);

        // ---- one full tunnel attempt (reused by the first connect and every reconnect) ----

        /// <inheritdoc/>
        protected override async Task EstablishAsync(CancellationToken cancellationToken)
        {
            await CleanupAttemptResourcesAsync().ConfigureAwait(false);

            IPEndPoint endpoint = await ResolveEndpointAsync(cancellationToken).ConfigureAwait(false);
            _loopCts = CancellationTokenSource.CreateLinkedTokenSource(LifetimeToken, cancellationToken);
            CancellationToken loopToken = _loopCts.Token;

            ZeroTierTransportHandle handle = await _transportFactory.ConnectAsync(endpoint, cancellationToken).ConfigureAwait(false);
            handle.SetReceiver(OnInboundDatagram);
            _transport = handle.Datagram;
            MarkRunning(); // honour a drop detected while the handshake is still in flight
            if (handle.ReceivePump != null)
                _receiveTask = Task.Run(() => handle.ReceivePump(loopToken));

            // --- VL1: HELLO → OK(HELLO) (establishes the path; the OK echoes our timestamp, proving the peer dearmored us) ---
            Logger.LogHandshake(DriverName, $"HELLO {_localAddress} -> {_peerAddress}");
            OkHelloMessage ok = await HelloHandshakeAsync(cancellationToken).ConfigureAwait(false);
            Logger.LogHandshake(DriverName, $"OK(HELLO) from {_peerAddress} (proto v{ok.ProtocolVersion}, {ok.VersionMajor}.{ok.VersionMinor}); VL1 session up");

            // --- VL2: join the network (NETWORK_CONFIG_REQUEST → assigned IP + COM) ---
            IPAddress overlay;
            int prefix;
            byte[]? com;
            if (_config.OverlayAddress is not null)
            {
                // The overlay address is pinned; still ask the controller for the COM (best effort, short wait).
                overlay = _config.OverlayAddress;
                prefix = _config.PrefixLength;
                com = await TryJoinNetworkAsync(cancellationToken).ConfigureAwait(false);
            }
            else
            {
                ZeroTierNetworkConfig netConfig = await JoinNetworkAsync(cancellationToken).ConfigureAwait(false);
                (overlay, prefix) = ResolveOverlayAddress(netConfig);
                com = netConfig.CertificateOfMembership;
                Logger.LogHandshake(DriverName, $"network {_config.NetworkId} joined; controller assigned {overlay}/{prefix}{(com is null ? "" : " (+COM)")}");
            }

            _tunnelConfig = _config.ToTunnelConfig(overlay, prefix);

            // --- L2 data plane: the VL2 session as an Ethernet channel, bridged to L3 via ARP + VirtualHost ---
            byte[] localMac = _frameCodec.DeriveMac(_localAddress, _config.NetworkId);
            var mac = MacAddress.FromBytes(localMac);
            var channel = new ZeroTierEthernetChannel(_packetCodec, _sessionKey, _config.NetworkId,
                _localAddress, _peerAddress, localMac, com,
                (wire, ct) => SendAsync(wire, ct), NextPacketId, _config.Mtu);
            _channel = channel;

            var arp = new ArpResolver(mac, overlay, channel);
            _arp = arp;

            var virtualHost = new VirtualHost(mac, channel, arp);
            virtualHost.InboundNonIpFrame += arp.HandleInboundFrame;
            _host2 = virtualHost;

            _tunnelConfig.Mtu = virtualHost.Mtu;     // link − 14: the bound stack clamps MSS for the Ethernet header
            Facade.SetInner(virtualHost);

            StartKeepAlive();
            Logger.LogHandshake(DriverName, $"overlay {overlay}/{prefix}; L2<->L3 bridge bound");
            Logger.LogHandshakeCompleted(DriverName);
            MarkConnected();
        }

        async Task<IPEndPoint> ResolveEndpointAsync(CancellationToken cancellationToken)
        {
            IPAddress ip = await _hostResolver.ResolveAsync(_host, _addressFamilyPreference, cancellationToken).ConfigureAwait(false);
            return new IPEndPoint(ip, _port);
        }

        // ---- VL1 handshake: send HELLO (cipher 0), await OK(HELLO) (cipher 1) ----

        async Task<OkHelloMessage> HelloHandshakeAsync(CancellationToken cancellationToken)
        {
            var tcs = new TaskCompletionSource<OkHelloMessage>(TaskCreationOptions.RunContinuationsAsynchronously);
            _okHelloTcs = tcs;
            _helloPacketId = NextPacketId();
            _helloTimestamp = (ulong)DateTimeOffset.UtcNow.ToUnixTimeMilliseconds();

            var hello = new HelloMessage
            {
                ProtocolVersion = ZeroTierDriverConstants.ProtocolVersion,
                VersionMajor = ZeroTierDriverConstants.VersionMajor,
                VersionMinor = ZeroTierDriverConstants.VersionMinor,
                VersionRevision = 0,
                Timestamp = _helloTimestamp,
                Identity = _config.Identity,
            };
            byte[] body = _helloCodec.Encode(hello, includePhysicalDestNil: true);
            var header = new Vl1Header
            {
                PacketId = _helloPacketId,
                Destination = _peerAddress,
                Source = _localAddress,
                Cipher = Vl1CipherSuite.Poly1305None, // HELLO is authenticated but not encrypted
                Verb = Vl1Verb.Hello,
            };
            byte[] datagram = _packetCodec.Seal(header, _sessionKey, body);
            await SendAsync(datagram, cancellationToken).ConfigureAwait(false);

            using var timeoutCts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
            timeoutCts.CancelAfter(_handshakeTimeout);
            using (timeoutCts.Token.Register(() => tcs.TrySetCanceled()))
            {
                try { return await tcs.Task.ConfigureAwait(false); }
                catch (OperationCanceledException) when (!cancellationToken.IsCancellationRequested)
                {
                    const string reason = "no OK(HELLO) from the peer within the handshake timeout (MAC/identity rejected).";
                    Logger.LogHandshakeFailed(DriverName, reason);
                    throw new VpnConnectionException("ZeroTier handshake failed: " + reason);
                }
            }
        }

        // ---- VL2 join: send NETWORK_CONFIG_REQUEST, await the controller's config reply ----

        async Task<ZeroTierNetworkConfig> JoinNetworkAsync(CancellationToken cancellationToken)
        {
            var tcs = new TaskCompletionSource<ZeroTierNetworkConfig>(TaskCreationOptions.RunContinuationsAsynchronously);
            _networkConfigTcs = tcs;

            // The controller only answers a NETWORK_CONFIG_REQUEST once it has confirmed our bidirectional path
            // (it WHOISes us / waits for our OK(HELLO)), so the first request can be dropped. Re-send periodically
            // until the config arrives or the overall timeout elapses (mirrors the real ZeroTier client's retry).
            using var timeoutCts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
            timeoutCts.CancelAfter(_config.NetworkConfigTimeout);
            using (timeoutCts.Token.Register(() => tcs.TrySetCanceled()))
            {
                try
                {
                    while (true)
                    {
                        await SendNetworkConfigRequestAsync(cancellationToken).ConfigureAwait(false);
                        Task completed = await Task.WhenAny(tcs.Task, Task.Delay(TimeSpan.FromSeconds(2), timeoutCts.Token)).ConfigureAwait(false);
                        if (completed == tcs.Task) return await tcs.Task.ConfigureAwait(false);
                    }
                }
                catch (OperationCanceledException) when (!cancellationToken.IsCancellationRequested)
                {
                    Logger.LogHandshakeFailed(DriverName, "no network config from the controller (member not authorized, or controller unreachable)");
                    throw new VpnConnectionException("ZeroTier network join timed out: no NETWORK_CONFIG from the controller (is the member authorized?).");
                }
            }
        }

        // Best-effort variant when the overlay address is pinned: returns the COM if the controller replies in time, else null.
        async Task<byte[]?> TryJoinNetworkAsync(CancellationToken cancellationToken)
        {
            var tcs = new TaskCompletionSource<ZeroTierNetworkConfig>(TaskCreationOptions.RunContinuationsAsynchronously);
            _networkConfigTcs = tcs;
            await SendNetworkConfigRequestAsync(cancellationToken).ConfigureAwait(false);

            using var timeoutCts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
            timeoutCts.CancelAfter(_config.NetworkConfigTimeout);
            using (timeoutCts.Token.Register(() => tcs.TrySetCanceled()))
            {
                try { ZeroTierNetworkConfig cfg = await tcs.Task.ConfigureAwait(false); return cfg.CertificateOfMembership; }
                catch (OperationCanceledException) when (!cancellationToken.IsCancellationRequested)
                {
                    Logger.LogPacketDropped(DriverName, VpnDropReason.Unexpected, "no network config within the timeout; continuing with the pinned overlay address and no COM");
                    return null;
                }
            }
        }

        Task SendNetworkConfigRequestAsync(CancellationToken cancellationToken)
        {
            byte[] body = _networkConfigCodec.EncodeRequest(_config.NetworkId);
            var header = new Vl1Header
            {
                PacketId = NextPacketId(),
                Destination = new ZeroTierAddress(_config.NetworkId.ControllerAddress),
                Source = _localAddress,
                Cipher = Vl1CipherSuite.Salsa2012Poly1305,
                Verb = Vl1Verb.NetworkConfigRequest,
            };
            byte[] datagram = _packetCodec.Seal(header, _sessionKey, body);
            Logger.LogHandshake(DriverName, $"NETWORK_CONFIG_REQUEST network={_config.NetworkId} -> controller {header.Destination}");
            return SendAsync(datagram, cancellationToken).AsTask();
        }

        (IPAddress, int) ResolveOverlayAddress(ZeroTierNetworkConfig config)
        {
            foreach (InetAddressValue ip in config.AssignedAddresses)
            {
                if (ip.Address is not null && ip.Address.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork)
                    return (ip.Address, ip.Port > 0 && ip.Port <= 32 ? ip.Port : _config.PrefixLength);
            }
            throw new VpnConnectionException("ZeroTier controller returned no IPv4 address for this member (assign one in the network's IP pool).");
        }

        // ---- inbound demux: route by VL1 verb ----

        void OnInboundDatagram(ReadOnlyMemory<byte> datagram)
        {
            if (!_packetCodec.Open(datagram.Span, _sessionKey, out Vl1Header header, out byte[] payload))
            {
                Logger.LogPacketDropped(DriverName, VpnDropReason.DecryptFailed, $"VL1 packet failed to open ({datagram.Length}B)");
                return;
            }

            switch (header.Verb)
            {
                case Vl1Verb.Ok: OnOk(payload); break;
                case Vl1Verb.NetworkConfig: OnNetworkConfig(payload); break;
                case Vl1Verb.ExtFrame: _channel?.DeliverExtFrame(payload); break;
                case Vl1Verb.Frame: _channel?.DeliverFrame(payload); break;
                case Vl1Verb.Hello: OnHello(header, payload); break;   // a peer-initiated HELLO; reply OK(HELLO) to confirm the path
                case Vl1Verb.Echo: OnEcho(header, payload); break;
                case Vl1Verb.Error: OnError(payload); break;
                default: break;
            }
        }

        void OnOk(byte[] payload)
        {
            // A large OK carrying our network id is the OK(NETWORK_CONFIG_REQUEST) — its in-re header layout varies by
            // ZeroTier version (a 2-byte gap exists on pre-1.6 controllers), so route by content (the embedded config
            // body) rather than the in-re-verb byte. The smaller OK(HELLO) is matched first by its in-re-verb.
            if (_okCodec.TryDecodeCommon(payload, out byte inReVerb, out _) && (Vl1Verb)inReVerb == Vl1Verb.Hello
                && _okCodec.TryDecodeOkHello(payload, out OkHelloMessage okHello))
            {
                if (okHello.TimestampEcho == _helloTimestamp)
                {
                    Logger.LogProtocolStep(DriverName, "OK(HELLO) timestamp echo matches; VL1 session confirmed");
                    _okHelloTcs?.TrySetResult(okHello);
                }
                return;
            }

            // Otherwise, try to extract a network config from the OK payload (the controller's config reply).
            if (_networkConfigTcs != null && payload.Length > NetworkId.SizeInBytes + 2)
                TryCompleteNetworkConfig(payload);
        }

        void OnNetworkConfig(byte[] payload)
        {
            // A pushed NETWORK_CONFIG (verb 0x0c): the body starts at the networkId (no OK common header).
            TryCompleteNetworkConfig(payload);
        }

        // Locate the config body (networkId(8) || dictLen(2 BE) || dict) inside the OK/NETWORK_CONFIG payload by scanning
        // for our 8-byte network id followed by a dictLen that covers the rest, then decode it. Robust to the small,
        // version-dependent header gap before the body.
        void TryCompleteNetworkConfig(byte[] payload)
        {
            byte[] nwid = new byte[NetworkId.SizeInBytes];
            _config.NetworkId.Write(nwid);

            for (int o = 0; o + NetworkId.SizeInBytes + 2 <= payload.Length; o++)
            {
                if (!payload.AsSpan(o, NetworkId.SizeInBytes).SequenceEqual(nwid)) continue;
                int dictLen = (payload[o + 8] << 8) | payload[o + 9];
                if (dictLen == 0) continue;                                              // not the config body
                // The codec clamps an over-long (chunked) dictLen to the bytes present, so accept any non-zero length.
                if (_networkConfigCodec.TryDecodeConfig(payload.AsSpan(o), out ZeroTierNetworkConfig config)
                    && config.HasAssignedAddress)
                {
                    Logger.LogProtocolStep(DriverName, $"network config decoded (dictLen={dictLen}, ips={config.AssignedAddresses.Count}, com={(config.CertificateOfMembership is null ? "no" : "yes")})");
                    _networkConfigTcs?.TrySetResult(config);
                    return;
                }
            }
            Logger.LogPacketDropped(DriverName, VpnDropReason.Unexpected, $"network config did not decode ({payload.Length}B; multi-chunk or unrecognised layout)");
        }

        void OnHello(Vl1Header header, byte[] payload)
        {
            // The peer (root/controller) sends its own HELLO to confirm a bidirectional path. We must answer with an
            // OK(HELLO) — echoing the timestamp from its HELLO — or it never marks us a confirmed peer and will not
            // process our NETWORK_CONFIG_REQUEST. The HELLO body starts with proto/major/minor/revision(2)/timestamp(8).
            if (!_helloCodec.TryDecode(payload, out HelloMessage incoming)) return;

            // OK(HELLO): inReVerb(HELLO) || inRePacketId || timestampEcho || proto/major/minor/revision || physical InetAddress(nil).
            byte[] body = new byte[OkMessageCodec.CommonHeaderLength + 8 + 1 + 1 + 1 + 2 + 1];
            int o = 0;
            body[o++] = (byte)Vl1Verb.Hello;
            BinaryPrimitives.WriteUInt64BigEndian(body.AsSpan(o, 8), header.PacketId); o += 8;
            BinaryPrimitives.WriteUInt64BigEndian(body.AsSpan(o, 8), incoming.Timestamp); o += 8;   // echo the peer's HELLO timestamp
            body[o++] = ZeroTierDriverConstants.ProtocolVersion;
            body[o++] = ZeroTierDriverConstants.VersionMajor;
            body[o++] = ZeroTierDriverConstants.VersionMinor;
            BinaryPrimitives.WriteUInt16BigEndian(body.AsSpan(o, 2), 0); o += 2;                    // revision
            body[o] = 0x00;                                                                          // nil physical destination
            byte[] datagram = SealControl(Vl1Verb.Ok, body);
            Logger.LogProtocolStep(DriverName, $"inbound HELLO from {header.Source}; replying OK(HELLO) to confirm the path");
            _ = SendAsync(datagram);
        }

        void OnEcho(Vl1Header header, byte[] payload)
        {
            // Reply to an ECHO with an OK(ECHO) echoing the payload (liveness), sealed back to the peer.
            byte[] body = new byte[OkMessageCodec.CommonHeaderLength + payload.Length];
            body[0] = (byte)Vl1Verb.Echo;
            BinaryPrimitives.WriteUInt64BigEndian(body.AsSpan(1, 8), header.PacketId);
            payload.CopyTo(body, OkMessageCodec.CommonHeaderLength);
            byte[] datagram = SealControl(Vl1Verb.Ok, body);
            _ = SendAsync(datagram);
        }

        void OnError(byte[] payload)
        {
            byte inReVerb = payload.Length > 0 ? payload[0] : (byte)0;
            byte errorCode = payload.Length > OkMessageCodec.CommonHeaderLength ? payload[OkMessageCodec.CommonHeaderLength] : (byte)0;
            Logger.LogPacketDropped(DriverName, VpnDropReason.Unexpected, $"ERROR in-re verb 0x{inReVerb:x2}, code {errorCode}");
        }

        // ---- send helpers ----

        byte[] SealControl(Vl1Verb verb, byte[] body)
        {
            var header = new Vl1Header
            {
                PacketId = NextPacketId(),
                Destination = _peerAddress,
                Source = _localAddress,
                Cipher = Vl1CipherSuite.Salsa2012Poly1305,
                Verb = verb,
            };
            return _packetCodec.Seal(header, _sessionKey, body);
        }

        ValueTask SendAsync(ReadOnlyMemory<byte> wire, CancellationToken cancellationToken = default)
        {
            IDatagramTransport? transport = _transport;
            if (transport is null) return default;
            return SendCoreAsync(transport, wire, cancellationToken);
        }

        async ValueTask SendCoreAsync(IDatagramTransport transport, ReadOnlyMemory<byte> wire, CancellationToken cancellationToken)
        {
            try { await transport.SendAsync(wire, cancellationToken).ConfigureAwait(false); }
            catch (Exception ex)
            {
                Logger.LogPacketDropped(DriverName, VpnDropReason.Unexpected, $"failed to send datagram: {ex.GetType().Name}: {ex.Message}");
            }
        }

        // ---- keepalive: send ECHO so the peer keeps the VL1 path alive ----

        void StartKeepAlive()
        {
            _timerRunning = true;
            var interval = TimeSpan.FromSeconds(ZeroTierDriverConstants.KeepAliveSeconds);
            _timer = new System.Threading.Timer(_ => _ = KeepAliveTickAsync(), null, interval, interval);
        }

        async Task KeepAliveTickAsync()
        {
            if (!_timerRunning) return;
            try
            {
                byte[] body = new byte[4];
                NextRandomBytesCrypto(body);
                byte[] datagram = SealControl(Vl1Verb.Echo, body);
                await SendAsync(datagram).ConfigureAwait(false);
                Logger.LogKeepalive(DriverName, "ECHO");
            }
            catch { }
        }

        // ---- teardown ----

        /// <inheritdoc/>
        protected override async Task CleanupAttemptResourcesAsync()
        {
            StopAttemptLoop();

            _okHelloTcs?.TrySetCanceled(); _okHelloTcs = null;
            _networkConfigTcs?.TrySetCanceled(); _networkConfigTcs = null;

            CancellationTokenSource? loop = _loopCts;
            _loopCts = null;
            try { loop?.Cancel(); } catch { }

            Task? receive = _receiveTask;
            _receiveTask = null;
            if (receive != null) { try { await receive.ConfigureAwait(false); } catch { } }
            loop?.Dispose();

            VirtualHost? host2 = _host2; _host2 = null;
            if (host2 != null) { try { await host2.DisposeAsync().ConfigureAwait(false); } catch { } }
            ArpResolver? arp = _arp; _arp = null;
            if (arp != null) { try { await arp.DisposeAsync().ConfigureAwait(false); } catch { } }
            ZeroTierEthernetChannel? channel = _channel; _channel = null;
            if (channel != null) { try { await channel.DisposeAsync().ConfigureAwait(false); } catch { } }

            IDatagramTransport? transport = _transport;
            _transport = null;
            if (transport != null) { try { await transport.DisposeAsync().ConfigureAwait(false); } catch { } }
        }

        /// <inheritdoc/>
        protected override void StopAttemptLoop()
        {
            _timerRunning = false;
            _timer?.Dispose();
            _timer = null;
        }

        /// <inheritdoc/>
        public override async Task DisconnectAsync(CancellationToken cancellationToken = default)
            => await DisconnectCoreAsync().ConfigureAwait(false);

        /// <inheritdoc/>
        public async ValueTask DisposeAsync()
        {
            await DisconnectCoreAsync().ConfigureAwait(false);
            await CleanupAttemptResourcesAsync().ConfigureAwait(false);
            await DisposeCoreAsync().ConfigureAwait(false);
            _rng.Dispose();
        }

        /// <inheritdoc/>
        public void Dispose() => DisposeAsync().AsTask().GetAwaiter().GetResult();

        // ---- helpers ----

        ulong NextPacketId()
        {
            byte[] b = new byte[8];
            NextRandomBytesCrypto(b);
            return BinaryPrimitives.ReadUInt64BigEndian(b);
        }

        void NextRandomBytesCrypto(byte[] buffer) => _rng.GetBytes(buffer);
    }
}
