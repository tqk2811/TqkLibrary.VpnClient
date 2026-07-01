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
using TqkLibrary.VpnClient.Drivers.OpenVpn.Models;
using TqkLibrary.VpnClient.Drivers.OpenVpn.Transport;
using TqkLibrary.VpnClient.Ethernet;
using TqkLibrary.VpnClient.Ethernet.Helpers;
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
    /// monotonic clock) lives in <see cref="ReconnectingVpnConnection"/> (roadmap F.6); this driver keeps only its
    /// protocol logic (<see cref="EstablishAsync"/> / <see cref="CleanupAttemptResourcesAsync"/> / the keepalive timer).
    /// Rekey is a re-establish (fresh keys, packet-id back to 0) — unchanged.</para>
    /// </summary>
    public sealed class OpenVpnConnection : ReconnectingVpnConnection, IDisposable, IAsyncDisposable
    {
        static readonly TimeSpan KeepaliveTick = TimeSpan.FromSeconds(1);
        static readonly IPAddress LinkLocalPrefix = IPAddress.Parse("fe80::");   // the fe80::/64 IPv6 link-local prefix (RFC 4291 §2.5.6)
        const string DriverNameConst = "openvpn";

        readonly string _host;
        readonly int _port;
        readonly OpenVpnDeviceType _device;
        readonly string _optionsString;
        readonly string? _username;
        readonly string? _password;
        readonly X509CertificateCollection? _clientCertificates;
        readonly string? _clientCertPem;      // tls-ekm only: the BC control channel builds its TLS credential from PEM
        readonly string? _clientKeyPem;
        readonly RemoteCertificateValidationCallback? _serverCertificateValidation;
        readonly OpenVpnKeyDerivationMode _keyDerivation;
        readonly IOpenVpnControlWrap? _controlWrap;
        readonly OpenVpnReliabilityOptions? _reliabilityOptions;
        readonly IOpenVpnTransportFactory _transportFactory;
        readonly AddressFamilyPreference _addressFamilyPreference;
        readonly IHostResolver _hostResolver;
        readonly int _tunMtu;
        readonly OpenVpnPeerInfoOptions? _peerInfoOptions;
        readonly string? _fallbackCipher;
        readonly string? _dataAuth;       // the --auth HMAC for the non-AEAD CBC data channel (null = SHA1 default)
        readonly bool _multiHost;
        readonly bool _enableIpv6;        // opt-in: also run SLAAC/DHCPv6 + NDISC v6 on the tap bridge (default IPv4-only)
        readonly Ipv6AddressConfiguratorOptions? _ipv6Options;
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
        NdiscResolver? _tapNdisc;         // tap 1-host only: IPv6 neighbour resolver (when enableIpv6) sharing the tap port
        DhcpV4Configurator? _tapDhcp;     // tap pure-DHCP only: the DHCPv4 client when the server pushes no ifconfig
        Ipv6AddressConfigurator? _tapIpv6Config;  // tap 1-host only: the SLAAC/DHCPv6 client (when enableIpv6)
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
        /// <c>cipher</c> and the server pushed back no <c>IV_CIPHERS</c>); null falls back to AES-256-GCM. When that
        /// fallback is a non-AEAD AES-CBC cipher, <paramref name="dataAuth"/> is the <c>--auth</c> HMAC paired with it
        /// (null = HMAC-SHA1, OpenVPN's default).
        /// When <paramref name="multiHost"/> is <c>true</c> a tap-mode tunnel exposes the whole L2 broadcast domain
        /// (the tap channel becomes an uplink port on an in-memory switch and each station leases its own IP), reachable
        /// through <see cref="MultiHostSession"/>; the default (<c>false</c>) keeps the single-host tap bridge (tun-mode
        /// ignores it). When <paramref name="enableIpv6"/> is <c>true</c> a tap-mode bridge additionally runs IPv6
        /// autoconfiguration (SLAAC from a Router Advertisement, or stateful DHCPv6 — L2.6
        /// <see cref="Ipv6AddressConfigurator"/>) plus NDISC v6 neighbour resolution (<see cref="NdiscResolver"/>) over the
        /// same L2 segment, pushing <see cref="TunnelConfig.AssignedAddressV6"/>/<see cref="TunnelConfig.PrefixLengthV6"/>
        /// when the bridge hands out an IPv6 address; it is best-effort, so an IPv4-only bridge still connects (the default
        /// <c>false</c> keeps the wire IPv4-only, and tun-mode ignores it). <paramref name="ipv6Options"/> tunes the
        /// SLAAC/DHCPv6 exchange. <paramref name="clock"/> supplies the keepalive millisecond clock (default: the system tick
        /// clock) — tests inject a deterministic one. <paramref name="loggerFactory"/> receives diagnostic traces
        /// (handshake/NCP/keepalive/reconnect/drop); null logs to a no-op logger.
        /// </summary>
        public OpenVpnConnection(string host, int port, IOpenVpnTransportFactory transportFactory,
            string optionsString = "",
            OpenVpnDeviceType device = OpenVpnDeviceType.Tun,
            string? username = null, string? password = null,
            X509CertificateCollection? clientCertificates = null,
            RemoteCertificateValidationCallback? serverCertificateValidation = null,
            OpenVpnKeyDerivationMode keyDerivation = OpenVpnKeyDerivationMode.Tls1Prf,
            string? clientCertPem = null,
            string? clientKeyPem = null,
            IOpenVpnControlWrap? controlWrap = null,
            OpenVpnReconnectOptions? reconnectOptions = null,
            AddressFamilyPreference addressFamilyPreference = AddressFamilyPreference.Auto,
            IHostResolver? hostResolver = null,
            int tunMtu = 1500,
            OpenVpnReliabilityOptions? reliabilityOptions = null,
            OpenVpnPeerInfoOptions? peerInfoOptions = null,
            string? fallbackCipher = null,
            string? dataAuth = null,
            bool multiHost = false,
            bool enableIpv6 = false,
            Ipv6AddressConfiguratorOptions? ipv6Options = null,
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
            _clientCertPem = clientCertPem;
            _clientKeyPem = clientKeyPem;
            _serverCertificateValidation = serverCertificateValidation;
            _keyDerivation = keyDerivation;
            _controlWrap = controlWrap;
            _reliabilityOptions = reliabilityOptions;
            _addressFamilyPreference = addressFamilyPreference;
            _hostResolver = hostResolver ?? DnsHostResolver.Default;
            if (tunMtu < 1) throw new ArgumentOutOfRangeException(nameof(tunMtu));
            _tunMtu = tunMtu;
            _peerInfoOptions = peerInfoOptions;
            _fallbackCipher = string.IsNullOrEmpty(fallbackCipher) ? null : fallbackCipher;
            _dataAuth = string.IsNullOrEmpty(dataAuth) ? null : dataAuth;
            _multiHost = multiHost;
            _enableIpv6 = enableIpv6;
            _ipv6Options = ipv6Options;
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

        /// <summary>
        /// The tunnel IPv6 address autoconfigured over the tap bridge (SLAAC or DHCPv6), or <c>null</c> when IPv6 is
        /// disabled, the bridge is IPv4-only, or the device is tun. Mirrors <see cref="TunnelConfig.AssignedAddressV6"/>.
        /// </summary>
        public IPAddress? AssignedAddressV6 => _config.AssignedAddressV6;

        /// <summary><c>true</c> when this connection also runs IPv6 autoconfiguration (SLAAC/DHCPv6) + NDISC v6 on the tap bridge.</summary>
        public bool IsIpv6Enabled => _enableIpv6 && _device == OpenVpnDeviceType.Tap;

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

            var control = new OpenVpnControlChannel(transport, keyId: 0, options: _reliabilityOptions, controlWrap: _controlWrap,
                keyDerivation: _keyDerivation);
            _control = control;

            // Start the receive pump (UDP/TCP socket transports) once both handlers are wired; loopback transports self-pump.
            if (handle.ReceivePump != null)
                _receiveTask = Task.Run(() => handle.ReceivePump(loopToken));

            // --- reset → TLS handshake (inside the reliability layer) ---
            // tls-ekm runs the control TLS over BouncyCastle (exposes the RFC 5705 exporter); cert auth then comes from PEM.
            string engine = _keyDerivation == OpenVpnKeyDerivationMode.TlsEkm ? "BouncyCastle (tls-ekm)" : "SslStream";
            Logger.LogHandshake(DriverName, $"HARD_RESET -> TLS handshake on the control channel ({engine})");
            await control.ConnectAsync(_host, _clientCertificates, _serverCertificateValidation,
                clientCertPem: _clientCertPem, clientKeyPem: _clientKeyPem, cancellationToken: cancellationToken).ConfigureAwait(false);

            // --- key-method-2 over TLS (peer-info advertises IV_CIPHERS for NCP, plus IV_MTU and informational IV_*) ---
            Logger.LogHandshake(DriverName, "key-method-2 key exchange over TLS (peer-info IV_CIPHERS for NCP)");
            OpenVpnPeerInfoOptions peerInfoOptions = _peerInfoOptions
                // Default peer-info also advertises explicit-exit-notify (we send EXIT_NOTIFY on teardown); a caller that
                // supplied its own options controls IV_PROTO itself, so we don't override it.
                ?? new OpenVpnPeerInfoOptions
                {
                    IvProto = OpenVpnPeerInfo.IvProtoDataV2 | OpenVpnPeerInfo.IvProtoRequestPush | OpenVpnPeerInfo.IvProtoCcExitNotify,
                };
            // tls-ekm: advertise the tls-key-export capability so the server may negotiate it (and reply key-derivation tls-ekm).
            if (_keyDerivation == OpenVpnKeyDerivationMode.TlsEkm && (peerInfoOptions.IvProto & OpenVpnPeerInfo.IvProtoTlsKeyExport) == 0)
                peerInfoOptions = peerInfoOptions with { IvProto = peerInfoOptions.IvProto | OpenVpnPeerInfo.IvProtoTlsKeyExport };
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

            // --- NCP / fallback: pick the data cipher and build the matching channel (AEAD or non-AEAD CBC) ---
            // P_DATA_V2 (peer-id) when the server assigned one; P_DATA_V1 (no peer-id) for an older server (SoftEther).
            uint peerId = push.PeerId ?? 0;
            bool dataV2 = push.PeerId.HasValue;
            IOpenVpnDataChannel dataChannel = BuildDataChannel(push.Cipher, control.ServerKeyMethodOptions, keyMaterial, peerId, dataV2);
            var dataPlane = new OpenVpnDataPlane(dataChannel);
            dataPlane.RekeyNeeded += OnRekeyNeeded;
            _dataPlane = dataPlane;

            OpenVpnCompression compression = OpenVpnCompression.FromPushReply(push);
            _compression = compression;

            // The data-channel payload sink is identical for tun and tap; an outbound send also feeds the keepalive timer.
            // It reads the *current* transport (a reconnect swaps in a fresh one and disposes the old socket): a write that
            // races the reconnect window — e.g. a TCP-stack RTO retransmit firing on a timer — is dropped rather than
            // thrown, so a disposed/closed socket never crashes a fire-and-forget timer callback (TCP retransmits later).
            Func<ReadOnlyMemory<byte>, ValueTask> sink = async wire =>
            {
                _keepalive?.OnDataSent(Now());
                IOpenVpnTransport? current = _transport;
                if (current is null || !_dataActive) return;   // reconnecting: no live data plane right now — drop
                try { await current.SendAsync(wire).ConfigureAwait(false); }
                catch (ObjectDisposedException) { }                       // socket torn down by a concurrent reconnect
                catch (System.Net.Sockets.SocketException) { }            // transient send failure — link-loss path handles it
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

        // Builds the data channel for the negotiated/fallback cipher, slicing the matching keys from key2:
        //  1) the server pushed a `cipher` (normal NCP) — honour it (unsupported AEAD ⇒ fail).
        //  2) no pushed cipher, but the server echoed an IV_CIPHERS list — pick the first mutually-supported entry.
        //  3) NCP-less server — fall back to the configured `cipher`: AES-GCM/ChaCha (AEAD) or AES-CBC (+ --auth HMAC).
        //  4) nothing configured — AES-256-GCM (OpenVPN's default).
        IOpenVpnDataChannel BuildDataChannel(string? pushed, string? serverKeyMethodOptions, OpenVpnKeyMaterial keyMaterial, uint peerId, bool dataV2)
        {
            // (1) server pushed a cipher — it must be one we support (NCP negotiates AEAD ciphers).
            if (!string.IsNullOrEmpty(pushed))
            {
                if (OpenVpnDataCipher.TryResolve(pushed, out OpenVpnDataCipher cipher))
                    return BuildAead(cipher, keyMaterial, peerId, dataV2);
                if (OpenVpnCbcCipher.TryResolve(pushed, out OpenVpnCbcCipher cbcPushed))
                    return BuildCbc(cbcPushed, keyMaterial, peerId, dataV2, "PUSH_REPLY");
                throw new VpnConnectionException(
                    $"OpenVPN server selected an unsupported data cipher '{pushed}'. Supported AEAD: {OpenVpnDataCipher.AdvertisedList}; CBC: AES-128/192/256-CBC.");
            }

            // (2) server echoed an IV_CIPHERS offer in its key-method-2 reply — pick the first we support.
            string? serverList = OpenVpnDataCipher.ExtractIvCiphers(serverKeyMethodOptions);
            if (OpenVpnDataCipher.TryResolveServerList(serverList, out OpenVpnDataCipher fromServer))
            {
                Logger.LogHandshake(DriverName, $"NCP-less PUSH_REPLY; chose '{fromServer.Name}' from the server's IV_CIPHERS offer");
                return BuildAead(fromServer, keyMaterial, peerId, dataV2);
            }

            // (3) NCP-less server — use the configured cipher (AEAD or CBC).
            if (_fallbackCipher != null)
            {
                if (OpenVpnDataCipher.TryResolve(_fallbackCipher, out OpenVpnDataCipher configured))
                {
                    Logger.LogHandshake(DriverName, $"NCP-less server; falling back to the configured AEAD cipher '{configured.Name}'");
                    return BuildAead(configured, keyMaterial, peerId, dataV2);
                }
                if (OpenVpnCbcCipher.TryResolve(_fallbackCipher, out OpenVpnCbcCipher cbc))
                    return BuildCbc(cbc, keyMaterial, peerId, dataV2, "configured fallback");
                throw new VpnConnectionException(
                    $"OpenVPN configured fallback cipher '{_fallbackCipher}' is unsupported (no NCP). Supported AEAD: {OpenVpnDataCipher.AdvertisedList}; CBC: AES-128/192/256-CBC.");
            }

            // (4) nothing configured — OpenVPN's default.
            return BuildAead(OpenVpnDataCipher.Aes256Gcm, keyMaterial, peerId, dataV2);
        }

        OpenVpnDataChannel BuildAead(OpenVpnDataCipher cipher, OpenVpnKeyMaterial keyMaterial, uint peerId, bool dataV2)
        {
            OpenVpnDataChannelKeys keys = keyMaterial.DeriveDataKeys(cipher, isServer: false);
            return new OpenVpnDataChannel(keys, keyId: 0, peerId: peerId, cipher: cipher.CreateCipher(), dataV2: dataV2);
        }

        OpenVpnCbcDataChannel BuildCbc(OpenVpnCbcCipher cipher, OpenVpnKeyMaterial keyMaterial, uint peerId, bool dataV2, string source)
        {
            string authName = _dataAuth ?? "SHA1";
            Logger.LogHandshake(DriverName, $"NCP-less server; using the {source} CBC cipher '{cipher.Name}' with HMAC-{authName} (P_DATA_{(dataV2 ? "V2" : "V1")})");
            OpenVpnCbcDataKeys keys = keyMaterial.DeriveCbcDataKeys(cipher, OpenVpnDataAuth.KeySizeBytes(_dataAuth), isServer: false);
            return new OpenVpnCbcDataChannel(keys, cipher.CreateCipher(), OpenVpnDataAuth.CreateIntegrity(_dataAuth), keyId: 0, peerId: peerId, dataV2: dataV2);
        }

        // ---- tap single-host bridge: one VirtualHost + ARP on the tap channel, bridged down to the L3 facade ----

        async Task<TunnelConfig> BridgeTapSingleHostAsync(OpenVpnTapChannel tap, OpenVpnPushReply push, TunnelConfig config, CancellationToken cancellationToken)
        {
            IPAddress address;
            if (push.IfconfigLocal != null)
            {
                // server-bridge managed pool: the v4 address comes from the pushed ifconfig (OpenVPN pushes an IPv4
                // ifconfig; an IPv6 address — when enableIpv6 — is autoconfigured by SLAAC/DHCPv6 over the same segment below).
                if (push.IfconfigLocal.AddressFamily != AddressFamily.InterNetwork)
                    throw new VpnConnectionException(
                        "OpenVPN tap-mode bridges IPv4 over ARP; the pushed ifconfig address must be IPv4 (IPv6 is autoconfigured by SLAAC/DHCPv6).");
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
            _tapArp = arp;

            // --- IPv6 (opt-in): run NDISC v6 + SLAAC/DHCPv6 on the same tap segment, best-effort. An IPv4-only bridge
            //     yields no v6 address, which is fine — the tunnel still comes up on IPv4. Mirrors the SoftEther bridge. ---
            INeighborResolver resolver = arp;
            Action<ReadOnlyMemory<byte>>? ipSeam = null;
            if (_enableIpv6)
            {
                IPAddress linkLocal = LinkLocalAddress(_tapMac);
                var ndisc = new NdiscResolver(_tapMac, linkLocal, tap);
                _tapNdisc = ndisc;
                var ipv6Config = new Ipv6AddressConfigurator(_tapMac, linkLocal, tap, ndisc, _ipv6Options);
                _tapIpv6Config = ipv6Config;
                resolver = new DualStackNeighborResolver(arp, ndisc, ownsInnerResolvers: false);
                ipSeam = p => { ndisc.HandleInboundFrame(p); ipv6Config.HandleInboundFrame(p); };   // NDISC + DHCPv6 ride inside ordinary IPv6
                await ConfigureIpv6BestEffortAsync(tap, config, ipv6Config, cancellationToken).ConfigureAwait(false);
            }

            var host = new VirtualHost(_tapMac, tap, resolver);
            host.InboundNonIpFrame += arp.HandleInboundFrame;    // ARP replies/requests arrive on the non-IP seam
            if (_tapDhcp != null)
                host.InboundIpPacket += _tapDhcp.HandleInboundFrame;   // a renewal DHCP reply rides ordinary IPv4
            if (ipSeam != null)
                host.InboundIpPacket += ipSeam;                  // NDISC/DHCPv6 ride inside ordinary IPv6
            _tapHost = host;
            config.Mtu = host.Mtu;                               // link − 14: the bound stack clamps MSS for the Ethernet header
            Facade.SetInner(host);
            string v6 = config.AssignedAddressV6 != null ? $" + IPv6 {config.AssignedAddressV6}" : "";
            Logger.LogHandshake(DriverName, $"tap bridge bound on {address}{v6}");
            return config;
        }

        // Forms the host's IPv6 link-local address (fe80::/64 + Modified EUI-64 of the MAC, RFC 4291 §2.5.1) — the source
        // NDISC/SLAAC/DHCPv6 send from before any global address is configured. Reuses the SLAAC interface-identifier codec.
        static IPAddress LinkLocalAddress(MacAddress mac)
            => SlaacAddress.Combine(LinkLocalPrefix, 64, SlaacAddress.ModifiedEui64(mac));

        // Runs SLAAC/DHCPv6 over the tap segment and merges any IPv6 address/DNS/route into the v4 config. Best-effort: a
        // bridge that does not advertise IPv6 (no RA, no DHCPv6) leaves the config IPv4-only rather than failing the tunnel.
        // Mirrors SoftEtherConnection.ConfigureIpv6BestEffortAsync.
        async Task ConfigureIpv6BestEffortAsync(OpenVpnTapChannel tap, TunnelConfig config, Ipv6AddressConfigurator ipv6Config, CancellationToken cancellationToken)
        {
            Logger.LogHandshake(DriverName, "requesting IPv6 autoconfiguration over the tap segment (RS/RA -> SLAAC or DHCPv6)");
            // During the exchange the VirtualHost is not yet bound, so feed inbound frames (RA + DHCPv6 reply) straight from
            // the tap channel; once the bridge is up they ride VirtualHost.InboundIpPacket instead.
            NdiscResolver? ndisc = _tapNdisc;
            if (ndisc != null) tap.InboundFrame += ndisc.HandleInboundFrame;
            tap.InboundFrame += ipv6Config.HandleInboundFrame;
            try
            {
                TunnelConfig v6 = await ipv6Config.ConfigureAsync(cancellationToken).ConfigureAwait(false);
                config.AssignedAddressV6 = v6.AssignedAddressV6;
                config.PrefixLengthV6 = v6.PrefixLengthV6;
                foreach (IPAddress dns in v6.DnsServers)
                    config.DnsServers.Add(dns);
                foreach (string route in v6.Routes)
                    config.Routes.Add(route);
                Logger.LogHandshake(DriverName, $"IPv6 autoconfiguration succeeded: {v6.AssignedAddressV6}/{v6.PrefixLengthV6}");
            }
            catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
            {
                throw;
            }
            catch (Exception ex)
            {
                // No RA / no DHCPv6 lease (IPv4-only bridge): keep IPv4 working, drop only the IPv6 leg.
                Logger.LogHandshake(DriverName, $"IPv6 autoconfiguration skipped ({ex.GetType().Name}: {ex.Message}); continuing IPv4-only");
            }
            finally
            {
                if (ndisc != null) tap.InboundFrame -= ndisc.HandleInboundFrame;
                tap.InboundFrame -= ipv6Config.HandleInboundFrame;
            }
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
        /// otherwise it leases its own IPv4 over the shared switch (the bridge's DHCP server serving it). When the
        /// connection has IPv6 enabled the station also runs SLAAC/DHCPv6 + NDISC v6 on the shared switch (best-effort).
        /// Surfaced as an <see cref="EthernetHostSession"/>.
        /// </summary>
        /// <exception cref="InvalidOperationException">This connection is not in multi-host tap mode.</exception>
        public async ValueTask<EthernetHostSession> AddStationAsync(MacAddress mac, IPAddress? staticAddress = null, CancellationToken cancellationToken = default)
        {
            MultiHostSession? session = _multiHostSession;
            if (session is null)
                throw new InvalidOperationException("This OpenVPN connection is not in multi-host tap mode; construct it with multiHost: true and dev tap to add stations.");

            if (staticAddress != null && staticAddress.AddressFamily != AddressFamily.InterNetwork)
                throw new VpnConnectionException("OpenVPN tap multi-host bridges IPv4 only (ARP); an IPv6 station address needs NDISC (roadmap L2.4).");

            if (staticAddress != null && !_enableIpv6)
            {
                // Static IPv4-only station: no configurator, the address is known up front.
                EthernetHostSession station = session.AddStation(mac, port =>
                {
                    var arp = new ArpResolver(mac, staticAddress, port);
                    return new EthernetHostSpec(arp) { NonIpFrameHandler = arp.HandleInboundFrame };
                }, new TunnelConfig { AssignedAddress = staticAddress, PrefixLength = 24 });
                return station;
            }

            // A station whose v4 address comes from DHCP starts ARP on 0.0.0.0; once the lease lands we set the real
            // address so it answers ARP for itself. A static-v4 station already knows its address.
            ArpResolver? arpRef = null;
            EthernetHostSession leased = await session.AddStationAsync(mac, port =>
            {
                var arp = new ArpResolver(mac, staticAddress ?? IPAddress.Any, port);
                arpRef = arp;

                if (!_enableIpv6)
                {
                    // DHCPv4-only station (staticAddress is null here).
                    var dhcp = new DhcpV4Configurator(mac, port);
                    return new EthernetHostSpec(arp)
                    {
                        Configurator = dhcp,
                        NonIpFrameHandler = arp.HandleInboundFrame,      // ARP rides the non-IP seam
                        IpPacketHandler = dhcp.HandleInboundFrame,       // DHCP rides inside ordinary IPv4
                    };
                }

                // Dual-stack station: ARP for v4 + NDISC for v6. The IPv4 leg is DHCPv4 (required) when no static address
                // was pushed, or a pre-set static address (so its configurator is the SLAAC/DHCPv6 leg only); the IPv6 leg
                // is SLAAC/DHCPv6 (best-effort). Mirrors SoftEtherConnection.AddStationAsync.
                IPAddress linkLocal = LinkLocalAddress(mac);
                var ndisc = new NdiscResolver(mac, linkLocal, port);
                var ipv6Config = new Ipv6AddressConfigurator(mac, linkLocal, port, ndisc, _ipv6Options);
                var dualResolver = new DualStackNeighborResolver(arp, ndisc);                        // owns ARP + NDISC
                IAddressConfigurator configurator = staticAddress != null
                    ? new BestEffortIpv6Configurator(ipv6Config)                                     // static v4: only the v6 leg runs
                    : new DualStackAddressConfigurator(new DhcpV4Configurator(mac, port), new BestEffortIpv6Configurator(ipv6Config));
                DhcpV4Configurator? dhcpForSeam = configurator is DualStackAddressConfigurator dual ? (DhcpV4Configurator)dual.Ipv4 : null;
                return new EthernetHostSpec(dualResolver)
                {
                    Configurator = configurator,
                    NonIpFrameHandler = arp.HandleInboundFrame,          // ARP rides the non-IP seam
                    // NDISC (incl. RA), DHCPv4 (when present) and DHCPv6 all ride inside ordinary IP.
                    IpPacketHandler = p =>
                    {
                        ndisc.HandleInboundFrame(p);
                        dhcpForSeam?.HandleInboundFrame(p);
                        ipv6Config.HandleInboundFrame(p);
                    },
                };
            }, cancellationToken).ConfigureAwait(false);

            // A static-v4 station carries its pushed address (the configurator only ran the v6 leg); a DHCP station leased one.
            IPAddress? v4 = staticAddress ?? leased.Config.AssignedAddress;
            if (v4 != null && leased.Config.AssignedAddress is null)
            {
                leased.Config.AssignedAddress = staticAddress;          // static v4: merge it back (the v6 configurator left it null)
                if (leased.Config.PrefixLength == 0) leased.Config.PrefixLength = 24;
            }
            if (v4 is null || v4.AddressFamily != AddressFamily.InterNetwork)
            {
                await session.RemoveStationAsync(mac).ConfigureAwait(false);
                throw new VpnConnectionException("OpenVPN tap multi-host DHCP did not lease an IPv4 address for the station (the bridge serves IPv4 via DHCP; ARP is IPv4-only).");
            }
            arpRef?.SetLocalAddress(v4);                                // ARP now answers for the station's v4 address
            return leased;
        }

        // Wraps an Ipv6AddressConfigurator so a bridge that advertises no IPv6 (no RA / no DHCPv6 lease) yields an empty
        // IPv6 config instead of throwing — letting a station keep its IPv4 leg on an IPv4-only bridge. Cancellation still
        // propagates. Mirrors SoftEtherConnection.BestEffortIpv6Configurator.
        sealed class BestEffortIpv6Configurator : IAddressConfigurator, IAsyncDisposable
        {
            readonly Ipv6AddressConfigurator _inner;
            public BestEffortIpv6Configurator(Ipv6AddressConfigurator inner) => _inner = inner;

            public async ValueTask<TunnelConfig> ConfigureAsync(CancellationToken cancellationToken = default)
            {
                try { return await _inner.ConfigureAsync(cancellationToken).ConfigureAwait(false); }
                catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested) { throw; }
                catch { return new TunnelConfig(); }   // IPv4-only bridge: no v6 address, drop only the IPv6 leg
            }

            public ValueTask DisposeAsync() => _inner.DisposeAsync();
        }

        // ---- opcode demux: route inbound P_DATA_V2 to the data plane (control packets are the channel's job) ----

        void OnTransportDatagram(ReadOnlyMemory<byte> datagram)
        {
            if (!_dataActive) return;
            ReadOnlySpan<byte> span = datagram.Span;
            if (span.Length < 1) return;
            OpenVpnOpcode op = OpenVpnPacketCodec.ReadOpcode(span[0]);
            if (op != OpenVpnOpcode.DataV2 && op != OpenVpnOpcode.DataV1) return; // control packets are the channel's job

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

            NdiscResolver? tapNdisc = _tapNdisc;
            _tapNdisc = null;
            if (tapNdisc != null) { try { await tapNdisc.DisposeAsync().ConfigureAwait(false); } catch { } }

            DhcpV4Configurator? tapDhcp = _tapDhcp;
            _tapDhcp = null;
            if (tapDhcp != null) { try { await tapDhcp.DisposeAsync().ConfigureAwait(false); } catch { } }

            Ipv6AddressConfigurator? tapIpv6Config = _tapIpv6Config;
            _tapIpv6Config = null;
            if (tapIpv6Config != null) { try { await tapIpv6Config.DisposeAsync().ConfigureAwait(false); } catch { } }

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
