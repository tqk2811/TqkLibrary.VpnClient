using System.Net;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Cryptography.X509Certificates;
using Microsoft.Extensions.Logging;
using TqkLibrary.VpnClient.Abstractions.Channels.Interfaces;
using TqkLibrary.VpnClient.Abstractions.Diagnostics.Extensions;
using TqkLibrary.VpnClient.Abstractions.Drivers;
using TqkLibrary.VpnClient.Abstractions.Drivers.Models;
using TqkLibrary.VpnClient.Abstractions.Net;
using TqkLibrary.VpnClient.Drivers.Core;
using TqkLibrary.VpnClient.Drivers.OpenVpn.Enums;
using TqkLibrary.VpnClient.Drivers.OpenVpn.Models;
using TqkLibrary.VpnClient.Drivers.OpenVpn.Transport;
using TqkLibrary.VpnClient.Ethernet;
using TqkLibrary.VpnClient.Ethernet.Models;
using TqkLibrary.VpnClient.OpenVpn;
using TqkLibrary.VpnClient.OpenVpn.DataChannel;
using TqkLibrary.VpnClient.OpenVpn.Enums;
using TqkLibrary.VpnClient.OpenVpn.Transport;

namespace TqkLibrary.VpnClient.Drivers.OpenVpn
{
    /// <summary>
    /// A complete OpenVPN client (community-server compatible): it picks a UDP or TCP transport, then on that single
    /// transport <b>demultiplexes opcodes</b> — control packets feed the <see cref="OpenVpnControlChannel"/>
    /// (HARD_RESET → TLS → key-method-2 → PUSH_REQUEST), P_DATA_V2 packets feed the AEAD data plane. The negotiated data
    /// channel is bound to an <see cref="OpenVpnTunChannel"/> exposed through a stable <see cref="PacketChannel"/>; a
    /// keepalive ping + ping-restart dead-peer detector run for the tunnel's lifetime, and (when enabled) a dropped
    /// tunnel is re-established behind that same channel. tun-mode binds the data channel straight to an L3 IP channel;
    /// tap-mode bridges the Ethernet data channel down to that same L3 facade through the userspace L2 fabric
    /// (<see cref="OpenVpnTapChannel"/> → <see cref="ArpResolver"/> + <see cref="VirtualHost"/>), using the address a
    /// <c>server-bridge</c> managed pool pushes in <c>ifconfig</c>; a pure DHCP bridge (no pushed ifconfig) still needs
    /// the userspace DHCPv4 client (roadmap L2.5). Not a server — the responder role lives only in tests.
    /// <para>The link-loss → supervisor → reconnect-loop machinery (backoff/jitter, the stable
    /// <see cref="SwappablePacketChannel"/> facade, the lifetime cancellation, state changes + structured logging, the
    /// monotonic clock) lives in <see cref="ReconnectingVpnConnection{TState}"/> (roadmap F.6); this driver keeps only its
    /// protocol logic (<see cref="EstablishAsync"/> / <see cref="CleanupAttemptResourcesAsync"/> / the keepalive timer).
    /// Rekey is a re-establish (fresh keys, packet-id back to 0) — unchanged.</para>
    /// </summary>
    public sealed class OpenVpnConnection : ReconnectingVpnConnection<OpenVpnConnectionState>, IDisposable, IAsyncDisposable
    {
        static readonly TimeSpan KeepaliveTick = TimeSpan.FromSeconds(1);
        const string DriverNameConst = "openvpn";

        readonly string _host;
        readonly int _port;
        readonly OpenVpnDeviceType _device;
        readonly string _optionsString;
        readonly string? _username;
        readonly string? _password;
        readonly X509CertificateCollection? _clientCertificates;
        readonly RemoteCertificateValidationCallback? _serverCertificateValidation;
        readonly IOpenVpnControlWrap? _controlWrap;
        readonly OpenVpnReliabilityOptions? _reliabilityOptions;
        readonly IOpenVpnTransportFactory _transportFactory;
        readonly AddressFamilyPreference _addressFamilyPreference;
        readonly IHostResolver _hostResolver;
        readonly int _tunMtu;
        readonly OpenVpnPeerInfoOptions? _peerInfoOptions;
        readonly string? _fallbackCipher;
        readonly bool _multiHost;
        readonly MacAddress _tapMac;      // a stable locally-administered MAC for the tap endpoint (kept across reconnects)

        IPAddress? _assignedAddress;
        IPAddress? _lastAssignedAddress;
        IPAddress? _assignedDns;
        TunnelConfig _config = new();

        OpenVpnTransportHandle? _transportHandle;
        IOpenVpnTransport? _transport;
        OpenVpnControlChannel? _control;
        OpenVpnDataPlane? _dataPlane;
        OpenVpnCompression? _compression;
        OpenVpnDataLink? _dataLink;       // tun: OpenVpnTunChannel; tap: OpenVpnTapChannel
        VirtualHost? _tapHost;            // tap 1-host only: the L2↔L3 bridge whose IPacketChannel feeds the facade
        ArpResolver? _tapArp;             // tap 1-host only: IPv4 neighbour resolver sharing the tap port
        DhcpV4Configurator? _tapDhcp;     // tap pure-DHCP only: the DHCPv4 client when the server pushes no ifconfig
        MultiHostSession? _multiHostSession;  // tap multi-host only: the broadcast domain (uplink-as-port + N stations)
        OpenVpnKeepalive? _keepalive;
        CancellationTokenSource? _loopCts;
        Task? _receiveTask;
        System.Threading.Timer? _keepaliveTimer;

        volatile bool _dataActive;
        volatile bool _keepaliveRunning;

        /// <summary>
        /// Creates a connection. <paramref name="optionsString"/> is the OCC options string compared during key-method-2;
        /// <paramref name="username"/>/<paramref name="password"/> carry <c>auth-user-pass</c> (both null = none);
        /// <paramref name="clientCertificates"/> authenticate the client (OpenVPN cert auth) when supplied;
        /// <paramref name="serverCertificateValidation"/> validates the server certificate (null = accept any);
        /// <paramref name="controlWrap"/> applies <c>tls-auth</c>/<c>tls-crypt</c>; <paramref name="transportFactory"/>
        /// opens the UDP/TCP socket (an in-process factory drives it offline). <paramref name="peerInfoOptions"/>
        /// customises the advertised <c>IV_*</c> peer-info block (null = defaults; the tun MTU fills <c>IV_MTU</c> when
        /// unset). <paramref name="fallbackCipher"/> is the configured data cipher (the <c>cipher</c> /
        /// <c>data-ciphers-fallback</c> directive) used when the server does not speak NCP (PUSH_REPLY carries no
        /// <c>cipher</c> and the server pushed back no <c>IV_CIPHERS</c>); null falls back to AES-256-GCM.
        /// When <paramref name="multiHost"/> is <c>true</c> a tap-mode tunnel exposes the whole L2 broadcast domain
        /// (the tap channel becomes an uplink port on an in-memory switch and each station leases its own IP), reachable
        /// through <see cref="MultiHostSession"/>; the default (<c>false</c>) keeps the single-host tap bridge (tun-mode
        /// ignores it). <paramref name="clock"/> supplies the keepalive millisecond clock (default: the system tick clock) —
        /// tests inject a deterministic one. <paramref name="loggerFactory"/> receives diagnostic traces
        /// (handshake/NCP/keepalive/reconnect/drop); null logs to a no-op logger.
        /// </summary>
        public OpenVpnConnection(string host, int port, IOpenVpnTransportFactory transportFactory,
            string optionsString = "",
            OpenVpnDeviceType device = OpenVpnDeviceType.Tun,
            string? username = null, string? password = null,
            X509CertificateCollection? clientCertificates = null,
            RemoteCertificateValidationCallback? serverCertificateValidation = null,
            IOpenVpnControlWrap? controlWrap = null,
            OpenVpnReconnectOptions? reconnectOptions = null,
            AddressFamilyPreference addressFamilyPreference = AddressFamilyPreference.Auto,
            IHostResolver? hostResolver = null,
            int tunMtu = 1500,
            OpenVpnReliabilityOptions? reliabilityOptions = null,
            OpenVpnPeerInfoOptions? peerInfoOptions = null,
            string? fallbackCipher = null,
            bool multiHost = false,
            Func<long>? clock = null,
            ILoggerFactory? loggerFactory = null)
            : base(DriverNameConst, reconnectOptions ?? new OpenVpnReconnectOptions(), clock, loggerFactory)
        {
            _host = host ?? throw new ArgumentNullException(nameof(host));
            _port = port;
            _transportFactory = transportFactory ?? throw new ArgumentNullException(nameof(transportFactory));
            _optionsString = optionsString ?? string.Empty;
            _device = device;
            _username = username;
            _password = password;
            _clientCertificates = clientCertificates;
            _serverCertificateValidation = serverCertificateValidation;
            _controlWrap = controlWrap;
            _reliabilityOptions = reliabilityOptions;
            _addressFamilyPreference = addressFamilyPreference;
            _hostResolver = hostResolver ?? DnsHostResolver.Default;
            if (tunMtu < 1) throw new ArgumentOutOfRangeException(nameof(tunMtu));
            _tunMtu = tunMtu;
            _peerInfoOptions = peerInfoOptions;
            _fallbackCipher = string.IsNullOrEmpty(fallbackCipher) ? null : fallbackCipher;
            _multiHost = multiHost;
            _tapMac = GenerateLocalMac();
        }

        // A locally-administered unicast MAC for the virtual tap endpoint: clear the I/G (multicast) bit and set the
        // U/L (locally-administered) bit of octet 0, the rest random — exactly what OpenVPN does for a software TAP.
        MacAddress GenerateLocalMac()
        {
            byte[] bytes = new byte[MacAddress.Size];
            NextRandomBytes(bytes);
            bytes[0] = (byte)((bytes[0] & 0xFE) | 0x02);
            return MacAddress.FromBytes(bytes);
        }

        /// <summary>The tunnel configuration pushed by the server (address, DNS, routes, MTU).</summary>
        public TunnelConfig Config => _config;

        /// <summary>The tunnel IP address the server pushed (valid after connect).</summary>
        public IPAddress AssignedAddress => _assignedAddress ?? IPAddress.Any;

        /// <summary>The first DNS server pushed in PUSH_REPLY, if any.</summary>
        public IPAddress? AssignedDns => _assignedDns;

        /// <summary>This endpoint's virtual MAC on the tap segment (the first/primary station in multi-host tap mode).</summary>
        public MacAddress LinkAddress => _tapMac;

        /// <summary><c>true</c> when this connection exposes the whole L2 broadcast domain (tap uplink-as-port) via <see cref="MultiHostSession"/>.</summary>
        public bool IsMultiHost => _device == OpenVpnDeviceType.Tap && _multiHost;

        /// <summary>
        /// In multi-host tap mode, the broadcast domain riding the tap data channel (the channel attached as an uplink
        /// port, plus N <see cref="EthernetHostSession"/> stations leasing their own IP over the shared switch).
        /// <c>null</c> in single-host / tun mode or before the first connect completes.
        /// </summary>
        public MultiHostSession? MultiHostSession => _multiHostSession;

        /// <summary>Raised after a successful auto-reconnect, carrying the new address and whether it changed.</summary>
        public event Action<OpenVpnReconnectInfo>? Reconnected;

        /// <inheritdoc/>
        protected override OpenVpnConnectionState DisconnectedState => OpenVpnConnectionState.Disconnected;
        /// <inheritdoc/>
        protected override OpenVpnConnectionState ConnectingState => OpenVpnConnectionState.Connecting;
        /// <inheritdoc/>
        protected override OpenVpnConnectionState ConnectedState => OpenVpnConnectionState.Connected;
        /// <inheritdoc/>
        protected override OpenVpnConnectionState ReconnectingState => OpenVpnConnectionState.Reconnecting;

        /// <summary>Runs the full handshake and returns once the server has pushed a tunnel address.</summary>
        public async Task ConnectAsync(CancellationToken cancellationToken = default)
        {
            await ConnectCoreAsync(cancellationToken).ConfigureAwait(false);
            _lastAssignedAddress = _assignedAddress;
        }

        // ---- one full tunnel attempt (reused by the first connect and every reconnect) ----

        /// <inheritdoc/>
        protected override async Task EstablishAsync(CancellationToken cancellationToken)
        {
            await CleanupAttemptResourcesAsync().ConfigureAwait(false);
            _dataActive = false;

            IPAddress serverIp = await _hostResolver.ResolveAsync(_host, _addressFamilyPreference, cancellationToken).ConfigureAwait(false);
            _loopCts = CancellationTokenSource.CreateLinkedTokenSource(LifetimeToken, cancellationToken);
            CancellationToken loopToken = _loopCts.Token;

            OpenVpnTransportHandle handle = await _transportFactory.ConnectAsync(new IPEndPoint(serverIp, _port), cancellationToken).ConfigureAwait(false);
            _transportHandle = handle;
            IOpenVpnTransport transport = handle.Transport;
            _transport = transport;

            // Opcode demux: P_DATA_V2 packets come here; the control channel ignores them and consumes control opcodes.
            transport.DatagramReceived += OnTransportDatagram;

            var control = new OpenVpnControlChannel(transport, keyId: 0, options: _reliabilityOptions, controlWrap: _controlWrap);
            _control = control;

            // Start the receive pump (UDP/TCP socket transports) once both handlers are wired; loopback transports self-pump.
            if (handle.ReceivePump != null)
                _receiveTask = Task.Run(() => handle.ReceivePump(loopToken));

            // --- reset → TLS handshake (inside the reliability layer) ---
            Logger.LogHandshake(DriverName, "HARD_RESET -> TLS handshake on the control channel");
            await control.ConnectAsync(_host, _clientCertificates, _serverCertificateValidation, cancellationToken).ConfigureAwait(false);

            // --- key-method-2 over TLS (peer-info advertises IV_CIPHERS for NCP, plus IV_MTU and informational IV_*) ---
            Logger.LogHandshake(DriverName, "key-method-2 key exchange over TLS (peer-info IV_CIPHERS for NCP)");
            OpenVpnPeerInfoOptions peerInfoOptions = _peerInfoOptions
                // Default peer-info also advertises explicit-exit-notify (we send EXIT_NOTIFY on teardown); a caller that
                // supplied its own options controls IV_PROTO itself, so we don't override it.
                ?? new OpenVpnPeerInfoOptions
                {
                    IvProto = OpenVpnPeerInfo.IvProtoDataV2 | OpenVpnPeerInfo.IvProtoRequestPush | OpenVpnPeerInfo.IvProtoCcExitNotify,
                };
            if (peerInfoOptions.Mtu is null) peerInfoOptions = peerInfoOptions with { Mtu = _tunMtu };
            string peerInfo = OpenVpnPeerInfo.Build(peerInfoOptions);
            OpenVpnKeyMaterial keyMaterial = await control
                .NegotiateKeyMaterialAsync(_optionsString, _username, _password, peerInfo, cancellationToken).ConfigureAwait(false);

            // --- PUSH_REQUEST → PUSH_REPLY (address, routes, DNS, peer-id, keepalive, cipher) ---
            OpenVpnPushReply push = await control.RequestConfigAsync(cancellationToken).ConfigureAwait(false);
            // tun needs a pushed address; tap with no ifconfig is a pure-DHCP bridge (DHCP runs below over the L2 fabric).
            if (push.IfconfigLocal is null && _device != OpenVpnDeviceType.Tap)
            {
                Logger.LogHandshakeFailed(DriverName, "PUSH_REPLY carried no ifconfig (no tunnel address)");
                throw new VpnServerRejectedException("OpenVPN server PUSH_REPLY carried no tunnel address (no ifconfig).");
            }
            Logger.LogHandshake(DriverName, $"PUSH_REPLY: ifconfig {push.IfconfigLocal?.ToString() ?? "(none — pure DHCP)"}, cipher {push.Cipher ?? "(default)"}");

            // --- NCP: honour the server's cipher pick, then slice the data-channel keys for it ---
            OpenVpnDataCipher cipher = ResolveCipher(push.Cipher, control.ServerKeyMethodOptions);
            uint peerId = push.PeerId ?? 0;
            OpenVpnDataChannelKeys keys = keyMaterial.DeriveDataKeys(cipher, isServer: false);
            var dataChannel = new OpenVpnDataChannel(keys, keyId: 0, peerId: peerId, cipher: cipher.CreateCipher());
            var dataPlane = new OpenVpnDataPlane(dataChannel);
            dataPlane.RekeyNeeded += OnRekeyNeeded;
            _dataPlane = dataPlane;

            OpenVpnCompression compression = OpenVpnCompression.FromPushReply(push);
            _compression = compression;

            // The data-channel payload sink is identical for tun and tap; an outbound send also feeds the keepalive timer.
            Func<ReadOnlyMemory<byte>, ValueTask> sink = wire =>
            {
                _keepalive?.OnDataSent(Now());
                return new ValueTask(transport.SendAsync(wire));
            };

            int mtu = _tunMtu;
            TunnelConfig config = push.ToTunnelConfig();

            if (_device == OpenVpnDeviceType.Tap)
            {
                var tap = new OpenVpnTapChannel(dataPlane, compression, sink, _tapMac.ToArray(), mtu);
                _dataLink = tap;             // OnTransportDatagram delivers P_DATA_V2 frames here
                _dataActive = true;          // the data plane must be live so DHCP/ARP frames can flow over the L2 fabric
                if (_multiHost)
                    config = await BridgeTapMultiHostAsync(tap, push, cancellationToken).ConfigureAwait(false);
                else
                    config = await BridgeTapSingleHostAsync(tap, push, config, cancellationToken).ConfigureAwait(false);
            }
            else
            {
                // tun-mode: the data channel carries bare IP packets — bind it straight to the L3 facade.
                var tun = new OpenVpnTunChannel(dataPlane, compression, sink, mtu);
                _dataLink = tun;
                _dataActive = true;
                config.Mtu = mtu;
                Facade.SetInner(tun);
            }

            _config = config;
            _assignedAddress = config.AssignedAddress;
            _assignedDns = config.DnsServers.Count > 0 ? config.DnsServers[0] : null;
            StartKeepalive(push.Ping ?? 0, push.PingRestart ?? 0);
        }

        // NCP cipher selection, in priority order:
        //  1) the server pushed a `cipher` in PUSH_REPLY (normal NCP) — honour it (unsupported ⇒ fail).
        //  2) no pushed cipher, but the server echoed an IV_CIPHERS list in its key-method-2 reply — pick the first
        //     mutually-supported entry in the server's order (its preference wins).
        //  3) NCP-less server (neither of the above) — fall back to the configured `cipher`/`data-ciphers-fallback`.
        //  4) nothing configured — AES-256-GCM (OpenVPN's default data cipher).
        OpenVpnDataCipher ResolveCipher(string? pushed, string? serverKeyMethodOptions)
        {
            if (!string.IsNullOrEmpty(pushed))
            {
                if (OpenVpnDataCipher.TryResolve(pushed, out OpenVpnDataCipher cipher)) return cipher;
                throw new VpnConnectionException(
                    $"OpenVPN server selected an unsupported data cipher '{pushed}' (NCP). Supported: {OpenVpnDataCipher.AdvertisedList}.");
            }

            string? serverList = OpenVpnDataCipher.ExtractIvCiphers(serverKeyMethodOptions);
            if (OpenVpnDataCipher.TryResolveServerList(serverList, out OpenVpnDataCipher fromServer))
            {
                Logger.LogHandshake(DriverName, $"NCP-less PUSH_REPLY; chose '{fromServer.Name}' from the server's IV_CIPHERS offer");
                return fromServer;
            }

            if (_fallbackCipher != null)
            {
                if (OpenVpnDataCipher.TryResolve(_fallbackCipher, out OpenVpnDataCipher configured))
                {
                    Logger.LogHandshake(DriverName, $"NCP-less server; falling back to the configured cipher '{configured.Name}'");
                    return configured;
                }
                throw new VpnConnectionException(
                    $"OpenVPN configured fallback cipher '{_fallbackCipher}' is unsupported (no NCP). Supported: {OpenVpnDataCipher.AdvertisedList}.");
            }

            return OpenVpnDataCipher.Aes256Gcm;
        }

        // ---- tap single-host bridge: one VirtualHost + ARP on the tap channel, bridged down to the L3 facade ----

        async Task<TunnelConfig> BridgeTapSingleHostAsync(OpenVpnTapChannel tap, OpenVpnPushReply push, TunnelConfig config, CancellationToken cancellationToken)
        {
            IPAddress address;
            if (push.IfconfigLocal != null)
            {
                // server-bridge managed pool: the address comes from the pushed ifconfig. ARP is IPv4-only (L2.3), so an
                // IPv6 tunnel address needs NDISC (roadmap L2.4) and is refused here.
                if (push.IfconfigLocal.AddressFamily != AddressFamily.InterNetwork)
                    throw new VpnConnectionException(
                        "OpenVPN tap-mode bridges IPv4 only (ARP); an IPv6 tunnel address needs NDISC (roadmap L2.4).");
                address = push.IfconfigLocal;
            }
            else
            {
                // pure-DHCP bridge: the server pushed no ifconfig, so lease an IPv4 over the tap segment (L2.5) — the
                // DHCP server behind the bridge serves us, exactly like SoftEther's SecureNAT.
                Logger.LogHandshake(DriverName, "tap pure-DHCP: no pushed ifconfig; requesting a DHCPv4 lease over the L2 segment");
                var dhcp = new DhcpV4Configurator(_tapMac, tap);
                _tapDhcp = dhcp;
                tap.InboundFrame += dhcp.HandleInboundFrame;     // feed inbound frames to DHCP for the OFFER/ACK
                TunnelConfig leased;
                try { leased = await dhcp.ConfigureAsync(cancellationToken).ConfigureAwait(false); }
                finally { tap.InboundFrame -= dhcp.HandleInboundFrame; }

                if (leased.AssignedAddress is null || leased.AssignedAddress.AddressFamily != AddressFamily.InterNetwork)
                    throw new VpnConnectionException("OpenVPN tap pure-DHCP did not lease an IPv4 address (the bridge serves IPv4 via DHCP; ARP is IPv4-only).");
                config = leased;
                address = leased.AssignedAddress;
            }

            var arp = new ArpResolver(_tapMac, address, tap);
            var host = new VirtualHost(_tapMac, tap, arp);
            host.InboundNonIpFrame += arp.HandleInboundFrame;    // ARP replies/requests arrive on the non-IP seam
            if (_tapDhcp != null)
                host.InboundIpPacket += _tapDhcp.HandleInboundFrame;   // a renewal DHCP reply rides ordinary IPv4
            _tapArp = arp;
            _tapHost = host;
            config.Mtu = host.Mtu;                               // link − 14: the bound stack clamps MSS for the Ethernet header
            Facade.SetInner(host);
            return config;
        }

        // ---- tap multi-host bridge: the tap channel is an uplink port; the primary station leases over the shared switch ----

        async Task<TunnelConfig> BridgeTapMultiHostAsync(OpenVpnTapChannel tap, OpenVpnPushReply push, CancellationToken cancellationToken)
        {
            var adapter = new EthernetAdapter(new EthernetAdapterOptions { SwitchMtu = _tunMtu });
            adapter.ConnectUplink(tap);                          // detached when the adapter (switch) is disposed
            var session = new MultiHostSession(adapter, ownsAdapter: true);
            _multiHostSession = session;
            Logger.LogHandshake(DriverName, "tap multi-host: attached the tap data channel as an uplink port on the L2 broadcast domain");

            // The primary station feeds the connection's stable L3 facade. It takes the pushed ifconfig when present
            // (server-bridge managed pool), else leases over the shared switch like any additional station.
            EthernetHostSession primary = await AddStationAsync(_tapMac, push.IfconfigLocal, cancellationToken).ConfigureAwait(false);
            Facade.SetInner(primary.PacketChannel);
            Logger.LogHandshake(DriverName, $"tap multi-host: primary station {primary.Config.AssignedAddress}; broadcast domain bound");
            return primary.Config;
        }

        /// <summary>
        /// Adds a station to the multi-host tap broadcast domain with MAC <paramref name="mac"/>. When
        /// <paramref name="staticAddress"/> is non-null the station uses it statically (a server-bridge pushed ifconfig);
        /// otherwise it leases its own IPv4 over the shared switch (the bridge's DHCP server serving it). Surfaced as an
        /// <see cref="EthernetHostSession"/>.
        /// </summary>
        /// <exception cref="InvalidOperationException">This connection is not in multi-host tap mode.</exception>
        public async ValueTask<EthernetHostSession> AddStationAsync(MacAddress mac, IPAddress? staticAddress = null, CancellationToken cancellationToken = default)
        {
            MultiHostSession? session = _multiHostSession;
            if (session is null)
                throw new InvalidOperationException("This OpenVPN connection is not in multi-host tap mode; construct it with multiHost: true and dev tap to add stations.");

            if (staticAddress != null && staticAddress.AddressFamily != AddressFamily.InterNetwork)
                throw new VpnConnectionException("OpenVPN tap multi-host bridges IPv4 only (ARP); an IPv6 station address needs NDISC (roadmap L2.4).");

            if (staticAddress != null)
            {
                // Static station: no DHCP, the address is known up front.
                EthernetHostSession station = session.AddStation(mac, port =>
                {
                    var arp = new ArpResolver(mac, staticAddress, port);
                    return new EthernetHostSpec(arp) { NonIpFrameHandler = arp.HandleInboundFrame };
                }, new TunnelConfig { AssignedAddress = staticAddress, PrefixLength = 24 });
                return station;
            }

            // DHCP station: ARP starts on 0.0.0.0; once the lease lands we set the real address so it answers ARP for itself.
            ArpResolver? arpRef = null;
            EthernetHostSession leased = await session.AddStationAsync(mac, port =>
            {
                var arp = new ArpResolver(mac, IPAddress.Any, port);
                arpRef = arp;
                var dhcp = new DhcpV4Configurator(mac, port);
                return new EthernetHostSpec(arp)
                {
                    Configurator = dhcp,
                    NonIpFrameHandler = arp.HandleInboundFrame,      // ARP rides the non-IP seam
                    IpPacketHandler = dhcp.HandleInboundFrame,       // DHCP rides inside ordinary IPv4
                };
            }, cancellationToken).ConfigureAwait(false);

            if (leased.Config.AssignedAddress is null || leased.Config.AssignedAddress.AddressFamily != AddressFamily.InterNetwork)
            {
                await session.RemoveStationAsync(mac).ConfigureAwait(false);
                throw new VpnConnectionException("OpenVPN tap multi-host DHCP did not lease an IPv4 address for the station (the bridge serves IPv4 via DHCP; ARP is IPv4-only).");
            }
            arpRef?.SetLocalAddress(leased.Config.AssignedAddress);  // ARP now answers for the leased address
            return leased;
        }

        // ---- opcode demux: route inbound P_DATA_V2 to the data plane (control packets are the channel's job) ----

        void OnTransportDatagram(ReadOnlyMemory<byte> datagram)
        {
            if (!_dataActive) return;
            ReadOnlySpan<byte> span = datagram.Span;
            if (span.Length < 1 || OpenVpnPacketCodec.ReadOpcode(span[0]) != OpenVpnOpcode.DataV2) return;

            _keepalive?.OnDataReceived(Now()); // any inbound data packet (incl. the peer's ping) proves it is alive
            _dataLink?.Deliver(span);             // decrypt + decompress + (drop ping) + raise InboundIpPacket
        }

        // ---- keepalive: send the ping magic when idle; restart the tunnel when the peer goes silent ----

        void StartKeepalive(int pingSeconds, int pingRestartSeconds)
        {
            _keepalive = new OpenVpnKeepalive(pingSeconds, pingRestartSeconds, Now());
            _keepaliveRunning = true;
            Logger.LogHandshakeCompleted(DriverName);
            MarkConnected();
            if (pingSeconds > 0 || pingRestartSeconds > 0)
                _keepaliveTimer = new System.Threading.Timer(_ => _ = KeepaliveTickAsync(), null, KeepaliveTick, KeepaliveTick);
        }

        async Task KeepaliveTickAsync()
        {
            if (!_keepaliveRunning) return;
            long now = Now();
            OpenVpnKeepalive? ka = _keepalive;
            if (ka is null) return;

            if (ka.IsPeerDead(now))
            {
                OnLinkLost("ping-restart: no data from the OpenVPN server within the keepalive timeout.");
                return;
            }
            if (ka.ShouldSendPing(now))
            {
                try { await SendPingAsync(now).ConfigureAwait(false); } catch { /* a missed ping trips ping-restart later */ }
            }
        }

        // Seals the keepalive ping on the live data channel and sends it (same path user data takes, minus the IP layer).
        async Task SendPingAsync(long now)
        {
            OpenVpnDataPlane? dp = _dataPlane;
            OpenVpnCompression? comp = _compression;
            IOpenVpnTransport? transport = _transport;
            if (dp is null || comp is null || transport is null) return;

            byte[] wire = dp.Protect(comp.WrapOutgoing(OpenVpnPing.Magic)); // synchronous: no span crosses the await
            await transport.SendAsync(wire).ConfigureAwait(false);
            _keepalive?.OnDataSent(now);
            Logger.LogKeepalive(DriverName, "sent OpenVPN keepalive ping");
        }

        // ---- rekey: the data-channel packet-id is nearing 2^32; re-establish before the GCM nonce could repeat ----
        // (Make-before-break soft-reset — a 2nd TLS handshake on a new key_id then OpenVpnDataPlane.Swap — is future work;
        // a full re-establish is the honest, correct fallback: fresh keys, packet-id restarts at 0, no nonce reuse.)
        void OnRekeyNeeded()
        {
            Logger.LogRekey(DriverName, "data-channel packet-id nearing exhaustion; re-establishing the session");
            OnLinkLost("data-channel rekey: packet-id approaching exhaustion; re-establishing the session.");
        }

        // ---- link-loss handling + auto-reconnect supervisor live in ReconnectingVpnConnection (roadmap F.6). ----
        // The keepalive ping-restart / rekey paths call the inherited OnLinkLost, which arms the shared ReconnectLoopAsync.

        /// <inheritdoc/>
        protected override void OnReconnected()
        {
            IPAddress newAddress = _assignedAddress ?? IPAddress.Any;
            bool changed = _lastAssignedAddress != null && !newAddress.Equals(_lastAssignedAddress);
            _lastAssignedAddress = newAddress;
            Reconnected?.Invoke(new OpenVpnReconnectInfo(newAddress, changed));
        }

        // ---- teardown ----

        /// <summary>
        /// Tears the tunnel down permanently. First sends OpenVPN's <c>explicit-exit-notify</c> (<c>EXIT_NOTIFY</c>) over
        /// the control channel best-effort (time-boxed) so the server drops the session at once instead of waiting for its
        /// keepalive timeout, then runs the shared teardown (stop timers/receive loop, dispose transport/channels). The
        /// exit-notify never blocks or fails teardown.
        /// </summary>
        public override async Task DisconnectAsync(CancellationToken cancellationToken = default)
        {
            OpenVpnControlChannel? control = _control;
            if (control != null && _dataActive)
            {
                Logger.LogHandshake(DriverName, "sending explicit-exit-notify (EXIT_NOTIFY) before teardown");
                using var exitCts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
                exitCts.CancelAfter(TimeSpan.FromSeconds(2)); // best-effort: never let a stuck write delay teardown
                try { await control.SendExitNotifyAsync(exitCts.Token).ConfigureAwait(false); } catch { }
            }
            await DisconnectCoreAsync().ConfigureAwait(false);
        }

        /// <inheritdoc/>
        protected override async Task CleanupAttemptResourcesAsync()
        {
            StopAttemptLoop();

            IOpenVpnTransport? transport = _transport;
            if (transport != null) transport.DatagramReceived -= OnTransportDatagram;

            OpenVpnControlChannel? control = _control;
            _control = null;
            try { control?.Dispose(); } catch { }

            CancellationTokenSource? loop = _loopCts;
            _loopCts = null;
            try { loop?.Cancel(); } catch { }

            Task? receive = _receiveTask;
            _receiveTask = null;
            if (receive != null) { try { await receive.ConfigureAwait(false); } catch { } }
            loop?.Dispose();

            OpenVpnTransportHandle? handle = _transportHandle;
            _transportHandle = null;
            if (handle?.Underlying != null) { try { await handle.Underlying.DisposeAsync().ConfigureAwait(false); } catch { } }

            // tap multi-host fabric: disposing the session disposes the owned adapter (switch + every station + the uplink
            // port). The uplink port never disposes our tap data channel, so it is torn down with the transport above.
            MultiHostSession? multiHost = _multiHostSession;
            _multiHostSession = null;
            if (multiHost != null) { try { await multiHost.DisposeAsync().ConfigureAwait(false); } catch { } }

            // tap single-host fabric: disposing the host detaches + disposes the tap port; the resolver releases pending ARP.
            VirtualHost? tapHost = _tapHost;
            _tapHost = null;
            if (tapHost != null) { try { await tapHost.DisposeAsync().ConfigureAwait(false); } catch { } }

            ArpResolver? tapArp = _tapArp;
            _tapArp = null;
            if (tapArp != null) { try { await tapArp.DisposeAsync().ConfigureAwait(false); } catch { } }

            DhcpV4Configurator? tapDhcp = _tapDhcp;
            _tapDhcp = null;
            if (tapDhcp != null) { try { await tapDhcp.DisposeAsync().ConfigureAwait(false); } catch { } }

            _transport = null;
            _dataLink = null;
            _dataPlane = null;
            _compression = null;
            _keepalive = null;
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
