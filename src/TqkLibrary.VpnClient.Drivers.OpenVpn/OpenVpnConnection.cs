using System.Net;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Cryptography.X509Certificates;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;
using TqkLibrary.VpnClient.Abstractions.Channels;
using TqkLibrary.VpnClient.Abstractions.Channels.Interfaces;
using TqkLibrary.VpnClient.Abstractions.Diagnostics.Enums;
using TqkLibrary.VpnClient.Abstractions.Diagnostics.Extensions;
using TqkLibrary.VpnClient.Abstractions.Drivers;
using TqkLibrary.VpnClient.Abstractions.Drivers.Models;
using TqkLibrary.VpnClient.Abstractions.Net;
using TqkLibrary.VpnClient.Drivers.OpenVpn.Enums;
using TqkLibrary.VpnClient.Drivers.OpenVpn.Models;
using TqkLibrary.VpnClient.Drivers.OpenVpn.Transport;
using TqkLibrary.VpnClient.Ethernet;
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
    /// </summary>
    public sealed class OpenVpnConnection : IDisposable, IAsyncDisposable
    {
        static readonly TimeSpan KeepaliveTick = TimeSpan.FromSeconds(1);
        const string DriverName = "openvpn";

        readonly ILogger _logger;
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
        readonly OpenVpnReconnectOptions _opts;
        readonly AddressFamilyPreference _addressFamilyPreference;
        readonly IHostResolver _hostResolver;
        readonly int _tunMtu;
        readonly OpenVpnPeerInfoOptions? _peerInfoOptions;
        readonly Func<long> _clock;

        readonly SwappablePacketChannel _facade = new();
        readonly CancellationTokenSource _lifetimeCts = new();
        readonly Random _random = new();
        readonly MacAddress _tapMac;      // a stable locally-administered MAC for the tap endpoint (kept across reconnects)
        readonly object _stateLock = new();

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
        VirtualHost? _tapHost;            // tap only: the L2↔L3 bridge whose IPacketChannel feeds the facade
        ArpResolver? _tapArp;             // tap only: IPv4 neighbour resolver sharing the tap port
        OpenVpnKeepalive? _keepalive;
        CancellationTokenSource? _loopCts;
        Task? _receiveTask;
        System.Threading.Timer? _keepaliveTimer;

        volatile bool _dataActive;
        volatile bool _keepaliveRunning;
        volatile bool _userTeardown;
        bool _supervisorActive;       // guarded by _stateLock
        Task? _supervisor;
        OpenVpnConnectionState _state = OpenVpnConnectionState.Disconnected;

        /// <summary>
        /// Creates a connection. <paramref name="optionsString"/> is the OCC options string compared during key-method-2;
        /// <paramref name="username"/>/<paramref name="password"/> carry <c>auth-user-pass</c> (both null = none);
        /// <paramref name="clientCertificates"/> authenticate the client (OpenVPN cert auth) when supplied;
        /// <paramref name="serverCertificateValidation"/> validates the server certificate (null = accept any);
        /// <paramref name="controlWrap"/> applies <c>tls-auth</c>/<c>tls-crypt</c>; <paramref name="transportFactory"/>
        /// opens the UDP/TCP socket (an in-process factory drives it offline). <paramref name="peerInfoOptions"/>
        /// customises the advertised <c>IV_*</c> peer-info block (null = defaults; the tun MTU fills <c>IV_MTU</c> when
        /// unset). <paramref name="clock"/> supplies the keepalive millisecond clock (default: the system tick clock) —
        /// tests inject a deterministic one. <paramref name="loggerFactory"/> receives diagnostic traces
        /// (handshake/NCP/keepalive/reconnect/drop); null logs to <see cref="NullLogger"/> (a no-op).
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
            Func<long>? clock = null,
            ILoggerFactory? loggerFactory = null)
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
            _opts = reconnectOptions ?? new OpenVpnReconnectOptions();
            _addressFamilyPreference = addressFamilyPreference;
            _hostResolver = hostResolver ?? DnsHostResolver.Default;
            if (tunMtu < 1) throw new ArgumentOutOfRangeException(nameof(tunMtu));
            _tunMtu = tunMtu;
            _peerInfoOptions = peerInfoOptions;
            _clock = clock ?? DefaultClock;
            _tapMac = GenerateLocalMac(_random);
            _logger = (loggerFactory ?? NullLoggerFactory.Instance).CreateLogger("TqkLibrary.VpnClient.Drivers.OpenVpn");
        }

        // A locally-administered unicast MAC for the virtual tap endpoint: clear the I/G (multicast) bit and set the
        // U/L (locally-administered) bit of octet 0, the rest random — exactly what OpenVPN does for a software TAP.
        static MacAddress GenerateLocalMac(Random random)
        {
            byte[] bytes = new byte[MacAddress.Size];
            random.NextBytes(bytes);
            bytes[0] = (byte)((bytes[0] & 0xFE) | 0x02);
            return MacAddress.FromBytes(bytes);
        }

        /// <summary>The stable L3 packet channel (valid after a successful connect; survives reconnect).</summary>
        public IPacketChannel PacketChannel => _facade;

        /// <summary>The tunnel configuration pushed by the server (address, DNS, routes, MTU).</summary>
        public TunnelConfig Config => _config;

        /// <summary>The tunnel IP address the server pushed (valid after connect).</summary>
        public IPAddress AssignedAddress => _assignedAddress ?? IPAddress.Any;

        /// <summary>The first DNS server pushed in PUSH_REPLY, if any.</summary>
        public IPAddress? AssignedDns => _assignedDns;

        /// <summary>Raised whenever the connection state changes (handshake progress, drop, reconnect).</summary>
        public event Action<OpenVpnConnectionState>? StateChanged;

        /// <summary>Raised after a successful auto-reconnect, carrying the new address and whether it changed.</summary>
        public event Action<OpenVpnReconnectInfo>? Reconnected;

        /// <summary>The current lifecycle state.</summary>
        public OpenVpnConnectionState State => _state;

        /// <summary>Runs the full handshake and returns once the server has pushed a tunnel address.</summary>
        public async Task ConnectAsync(CancellationToken cancellationToken = default)
        {
            SetState(OpenVpnConnectionState.Connecting);
            await EstablishAsync(cancellationToken).ConfigureAwait(false);
            _lastAssignedAddress = _assignedAddress;
        }

        // ---- one full tunnel attempt (reused by the first connect and every reconnect) ----

        async Task EstablishAsync(CancellationToken cancellationToken)
        {
            await CleanupAttemptResourcesAsync().ConfigureAwait(false);
            _dataActive = false;

            IPAddress serverIp = await _hostResolver.ResolveAsync(_host, _addressFamilyPreference, cancellationToken).ConfigureAwait(false);
            _loopCts = CancellationTokenSource.CreateLinkedTokenSource(_lifetimeCts.Token, cancellationToken);
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
            _logger.LogHandshake(DriverName, "HARD_RESET -> TLS handshake on the control channel");
            await control.ConnectAsync(_host, _clientCertificates, _serverCertificateValidation, cancellationToken).ConfigureAwait(false);

            // --- key-method-2 over TLS (peer-info advertises IV_CIPHERS for NCP, plus IV_MTU and informational IV_*) ---
            _logger.LogHandshake(DriverName, "key-method-2 key exchange over TLS (peer-info IV_CIPHERS for NCP)");
            OpenVpnPeerInfoOptions peerInfoOptions = _peerInfoOptions ?? new OpenVpnPeerInfoOptions();
            if (peerInfoOptions.Mtu is null) peerInfoOptions = peerInfoOptions with { Mtu = _tunMtu };
            string peerInfo = OpenVpnPeerInfo.Build(peerInfoOptions);
            OpenVpnKeyMaterial keyMaterial = await control
                .NegotiateKeyMaterialAsync(_optionsString, _username, _password, peerInfo, cancellationToken).ConfigureAwait(false);

            // --- PUSH_REQUEST → PUSH_REPLY (address, routes, DNS, peer-id, keepalive, cipher) ---
            OpenVpnPushReply push = await control.RequestConfigAsync(cancellationToken).ConfigureAwait(false);
            if (push.IfconfigLocal is null)
            {
                _logger.LogHandshakeFailed(DriverName, "PUSH_REPLY carried no ifconfig (no tunnel address)");
                throw new VpnServerRejectedException(_device == OpenVpnDeviceType.Tap
                    ? "OpenVPN tap-mode PUSH_REPLY carried no ifconfig: a pure DHCP bridge needs the userspace DHCPv4 client (roadmap L2.5). This driver bridges tap only with a server-bridge managed pool that pushes ifconfig."
                    : "OpenVPN server PUSH_REPLY carried no tunnel address (no ifconfig).");
            }
            _logger.LogHandshake(DriverName, $"PUSH_REPLY: ifconfig {push.IfconfigLocal}, cipher {push.Cipher ?? "(default)"}");

            // --- NCP: honour the server's cipher pick, then slice the data-channel keys for it ---
            OpenVpnDataCipher cipher = ResolveCipher(push.Cipher);
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
                _keepalive?.OnDataSent(_clock());
                return new ValueTask(transport.SendAsync(wire));
            };

            int mtu = _tunMtu;
            TunnelConfig config = push.ToTunnelConfig();

            if (_device == OpenVpnDeviceType.Tap)
            {
                // tap-mode: the data channel carries Ethernet frames. Plug it in as an IEthernetChannel and bridge it down
                // to a bare L3 IPacketChannel through the userspace L2 fabric — the IP stack still binds the same facade.
                // The tunnel IP comes from the pushed ifconfig (a server-bridge managed pool); ARP is IPv4-only (L2.3),
                // so an IPv6 tunnel address needs NDISC (roadmap L2.4) and is refused here.
                if (push.IfconfigLocal.AddressFamily != AddressFamily.InterNetwork)
                    throw new VpnConnectionException(
                        "OpenVPN tap-mode bridges IPv4 only (ARP); an IPv6 tunnel address needs NDISC (roadmap L2.4).");

                var tap = new OpenVpnTapChannel(dataPlane, compression, sink, _tapMac.ToArray(), mtu);
                var arp = new ArpResolver(_tapMac, push.IfconfigLocal, tap);
                var host = new VirtualHost(_tapMac, tap, arp);
                host.InboundNonIpFrame += arp.HandleInboundFrame;   // ARP replies/requests arrive on the non-IP seam
                _dataLink = tap;                                    // OnTransportDatagram delivers P_DATA_V2 frames here
                _tapArp = arp;
                _tapHost = host;
                _dataActive = true;
                config.Mtu = host.Mtu;                              // link − 14: the bound stack clamps MSS for the Ethernet header
                _facade.SetInner(host);
            }
            else
            {
                // tun-mode: the data channel carries bare IP packets — bind it straight to the L3 facade.
                var tun = new OpenVpnTunChannel(dataPlane, compression, sink, mtu);
                _dataLink = tun;
                _dataActive = true;
                config.Mtu = mtu;
                _facade.SetInner(tun);
            }

            _config = config;
            _assignedAddress = config.AssignedAddress;
            _assignedDns = config.DnsServers.Count > 0 ? config.DnsServers[0] : null;
            StartKeepalive(push.Ping ?? 0, push.PingRestart ?? 0);
        }

        // The server didn't push a cipher ⇒ the default AES-256-GCM; pushed-and-supported ⇒ that; pushed-and-unsupported ⇒ fail.
        static OpenVpnDataCipher ResolveCipher(string? pushed)
        {
            if (string.IsNullOrEmpty(pushed)) return OpenVpnDataCipher.Aes256Gcm;
            if (OpenVpnDataCipher.TryResolve(pushed, out OpenVpnDataCipher cipher)) return cipher;
            throw new VpnConnectionException(
                $"OpenVPN server selected an unsupported data cipher '{pushed}' (NCP). Supported: {OpenVpnDataCipher.AdvertisedList}.");
        }

        // ---- opcode demux: route inbound P_DATA_V2 to the data plane (control packets are the channel's job) ----

        void OnTransportDatagram(ReadOnlyMemory<byte> datagram)
        {
            if (!_dataActive) return;
            ReadOnlySpan<byte> span = datagram.Span;
            if (span.Length < 1 || OpenVpnPacketCodec.ReadOpcode(span[0]) != OpenVpnOpcode.DataV2) return;

            _keepalive?.OnDataReceived(_clock()); // any inbound data packet (incl. the peer's ping) proves it is alive
            _dataLink?.Deliver(span);             // decrypt + decompress + (drop ping) + raise InboundIpPacket
        }

        // ---- keepalive: send the ping magic when idle; restart the tunnel when the peer goes silent ----

        void StartKeepalive(int pingSeconds, int pingRestartSeconds)
        {
            _keepalive = new OpenVpnKeepalive(pingSeconds, pingRestartSeconds, _clock());
            _keepaliveRunning = true;
            _logger.LogHandshakeCompleted(DriverName);
            SetState(OpenVpnConnectionState.Connected);
            if (pingSeconds > 0 || pingRestartSeconds > 0)
                _keepaliveTimer = new System.Threading.Timer(_ => _ = KeepaliveTickAsync(), null, KeepaliveTick, KeepaliveTick);
        }

        void StopKeepalive()
        {
            _keepaliveRunning = false;
            _keepaliveTimer?.Dispose();
            _keepaliveTimer = null;
        }

        async Task KeepaliveTickAsync()
        {
            if (!_keepaliveRunning) return;
            long now = _clock();
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
            _logger.LogKeepalive(DriverName, "sent OpenVPN keepalive ping");
        }

        // ---- rekey: the data-channel packet-id is nearing 2^32; re-establish before the GCM nonce could repeat ----
        // (Make-before-break soft-reset — a 2nd TLS handshake on a new key_id then OpenVpnDataPlane.Swap — is future work;
        // a full re-establish is the honest, correct fallback: fresh keys, packet-id restarts at 0, no nonce reuse.)
        void OnRekeyNeeded()
        {
            _logger.LogRekey(DriverName, "data-channel packet-id nearing exhaustion; re-establishing the session");
            OnLinkLost("data-channel rekey: packet-id approaching exhaustion; re-establishing the session.");
        }

        // ---- link-loss handling + auto-reconnect supervisor (mirrors the IKEv2 / L2TP driver) ----

        void OnLinkLost(string reason)
        {
            bool goDisconnected = false;
            bool startSupervisor = false;
            lock (_stateLock)
            {
                if (!_keepaliveRunning) return;
                _logger.LogLinkLost(DriverName, reason);
                StopKeepalive();
                _dataActive = false;

                if (_userTeardown || !_opts.Enabled)
                    goDisconnected = true;
                else if (!_supervisorActive)
                {
                    _supervisorActive = true;
                    startSupervisor = true;
                }
            }

            if (goDisconnected) { SetState(OpenVpnConnectionState.Disconnected); return; }
            if (startSupervisor)
            {
                SetState(OpenVpnConnectionState.Reconnecting);
                _supervisor = Task.Run(() => ReconnectLoopAsync(_lifetimeCts.Token));
            }
        }

        async Task ReconnectLoopAsync(CancellationToken cancellationToken)
        {
            TimeSpan delay = _opts.InitialBackoff;
            int failures = 0;
            while (!_userTeardown && !cancellationToken.IsCancellationRequested)
            {
                bool established = false;
                _logger.LogReconnectAttempt(DriverName, failures + 1);
                try { await EstablishAsync(cancellationToken).ConfigureAwait(false); established = true; }
                catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested) { break; }
                catch { /* attempt failed — back off and retry */ }

                if (established)
                {
                    bool healthy;
                    lock (_stateLock)
                    {
                        healthy = _keepaliveRunning;
                        if (healthy) _supervisorActive = false;
                    }
                    if (healthy) { _logger.LogReconnected(DriverName); RaiseReconnected(); return; }

                    SetState(OpenVpnConnectionState.Reconnecting);
                    delay = _opts.InitialBackoff;
                    failures = 0;
                    continue;
                }

                if (_opts.MaxAttempts != 0 && ++failures >= _opts.MaxAttempts) break;
                try { await Task.Delay(WithJitter(delay), cancellationToken).ConfigureAwait(false); }
                catch (OperationCanceledException) { break; }
                delay = _opts.NextBackoff(delay);
            }

            lock (_stateLock) { _supervisorActive = false; }
            if (!_userTeardown) SetState(OpenVpnConnectionState.Disconnected);
        }

        void RaiseReconnected()
        {
            IPAddress newAddress = _assignedAddress ?? IPAddress.Any;
            bool changed = _lastAssignedAddress != null && !newAddress.Equals(_lastAssignedAddress);
            _lastAssignedAddress = newAddress;
            Reconnected?.Invoke(new OpenVpnReconnectInfo(newAddress, changed));
        }

        // ---- teardown ----

        /// <summary>
        /// Tears the tunnel down permanently (no reconnect): cancels any reconnect in flight, then cancels the receive
        /// loop and disposes the transport. Best-effort and time-boxed; safe to call more than once.
        /// </summary>
        public async Task DisconnectAsync(CancellationToken cancellationToken = default)
        {
            _userTeardown = true;
            lock (_stateLock) StopKeepalive();

            _lifetimeCts.Cancel();
            Task? supervisor = _supervisor;
            if (supervisor != null) { try { await supervisor.ConfigureAwait(false); } catch { } }

            await CleanupAttemptResourcesAsync().ConfigureAwait(false);
            SetState(OpenVpnConnectionState.Disconnected);
        }

        async Task CleanupAttemptResourcesAsync()
        {
            StopKeepalive();
            _dataActive = false;

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

            // tap-mode fabric: disposing the host detaches + disposes the tap port; the resolver releases any pending ARP.
            VirtualHost? tapHost = _tapHost;
            _tapHost = null;
            if (tapHost != null) { try { await tapHost.DisposeAsync().ConfigureAwait(false); } catch { } }

            ArpResolver? tapArp = _tapArp;
            _tapArp = null;
            if (tapArp != null) { try { await tapArp.DisposeAsync().ConfigureAwait(false); } catch { } }

            _transport = null;
            _dataLink = null;
            _dataPlane = null;
            _compression = null;
            _keepalive = null;
        }

        // ---- helpers ----

        TimeSpan WithJitter(TimeSpan delay)
        {
            double fraction = _opts.JitterFraction;
            if (fraction <= 0) return delay;
            double r;
            lock (_random) r = _random.NextDouble();
            double jitter = delay.TotalMilliseconds * fraction * (r * 2 - 1);
            return TimeSpan.FromMilliseconds(Math.Max(0, delay.TotalMilliseconds + jitter));
        }

        void SetState(OpenVpnConnectionState state)
        {
            if (_state == state) return;
            _state = state;
            _logger.LogStateChanged(DriverName, state.ToString());
            StateChanged?.Invoke(state);
        }

#if NET5_0_OR_GREATER
        static long DefaultClock() => Environment.TickCount64;
#else
        static readonly System.Diagnostics.Stopwatch _stopwatch = System.Diagnostics.Stopwatch.StartNew();
        static long DefaultClock() => _stopwatch.ElapsedMilliseconds;
#endif

        /// <inheritdoc/>
        public async ValueTask DisposeAsync()
        {
            try { await DisconnectAsync().ConfigureAwait(false); } catch { }
            _lifetimeCts.Dispose();
            await _facade.DisposeAsync().ConfigureAwait(false);
        }

        /// <inheritdoc/>
        public void Dispose() => DisposeAsync().AsTask().GetAwaiter().GetResult();
    }
}
