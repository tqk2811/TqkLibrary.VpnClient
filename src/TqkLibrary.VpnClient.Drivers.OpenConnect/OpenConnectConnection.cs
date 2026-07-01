using System.Net;
using System.Text;
using Microsoft.Extensions.Logging;
using TqkLibrary.VpnClient.Abstractions.Channels;
using TqkLibrary.VpnClient.Abstractions.Channels.Interfaces;
using TqkLibrary.VpnClient.Abstractions.Diagnostics.Extensions;
using TqkLibrary.VpnClient.Abstractions.Drivers;
using TqkLibrary.VpnClient.Abstractions.Drivers.Models;
using TqkLibrary.VpnClient.Abstractions.Net;
using TqkLibrary.VpnClient.Abstractions.Transport.Interfaces;
using TqkLibrary.VpnClient.Drivers.Core;
using TqkLibrary.VpnClient.Drivers.OpenConnect.Models;
using TqkLibrary.VpnClient.Drivers.OpenConnect.Transport;
using TqkLibrary.VpnClient.OpenConnect;
using TqkLibrary.VpnClient.OpenConnect.Enums;
using TqkLibrary.VpnClient.OpenConnect.Models;
using TqkLibrary.VpnClient.Transport.Dtls;

namespace TqkLibrary.VpnClient.Drivers.OpenConnect
{
    /// <summary>
    /// A complete OpenConnect (Cisco AnyConnect / ocserv) client over a single TLS byte stream. It runs the HTTPS
    /// <c>config-auth</c> handshake (<see cref="OpenConnectAuthCodec"/>) to obtain the session cookie, promotes the same
    /// stream with an HTTP <c>CONNECT /CSCOSSLC/tunnel</c> (<see cref="OpenConnectConnectCodec"/>) whose
    /// <c>X-CSTP-*</c> headers carry the in-band tunnel config, then binds a <see cref="CstpChannel"/> (CSTP-over-TLS,
    /// bare IP — <b>no PPP</b>) behind a stable <see cref="SwappablePacketChannel"/>. A receive loop demuxes CSTP frames
    /// (DATA → IP stack, DPD-REQUEST → DPD-RESPONSE, DISCONNECT/TERMINATE → teardown) while a timer pumps
    /// <see cref="CstpDpdState"/> for the <c>X-CSTP-DPD</c> dead-peer-detection probe and the <c>X-CSTP-Keepalive</c>
    /// idle keep-alive (clock-injected, like the WireGuard/OpenVPN drivers). A dead session triggers the supervisor /
    /// auto-reconnect, mirroring those drivers.
    /// <para>
    /// <b>DTLS data path (V5.c):</b> when the CONNECT response advertises the <c>X-DTLS-*</c> headers and a datagram
    /// transport factory is supplied, the connection opens a UDP socket to the gateway's <c>X-DTLS-Port</c>, wraps it in
    /// a <see cref="DtlsDatagramTransport"/> (the <c>X-DTLS-Session-ID</c> is the correlating cookie), runs the DTLS 1.2
    /// handshake and swaps the data plane onto a <see cref="CstpDatagramChannel"/> (CSTP-over-DTLS, one datagram = one
    /// packet). The CSTP-over-TLS channel stays up as the control / fallback path; DPD and keep-alive run with parity on
    /// whichever channel is active. If DTLS is not offered, no factory is supplied, or the handshake fails, the data
    /// plane stays on CSTP-over-TLS (fallback). Not a server — the responder role lives only in tests.
    /// </para>
    /// <para>
    /// <b>Rekey (V.5):</b> when the gateway pushes <c>X-CSTP-Rekey-Method</c>/<c>X-CSTP-Rekey-Time</c>, the same 1 s
    /// timer arms a <see cref="CstpRekeyState"/>; at the rekey period the connection re-establishes a fresh tunnel
    /// (new auth + CONNECT + channel + optional DTLS) <b>make-before-break</b> behind the stable facade and swaps onto
    /// it, then tears the old one down — so the IP stack never rebinds and traffic is not dropped. Both
    /// <c>new-tunnel</c> and <c>ssl</c> use re-establish: <see cref="SslStream"/> exposes no client-initiated TLS
    /// renegotiation on net8/netstandard2.0, so the <c>ssl</c> method is handled as a re-establish (documented fallback).
    /// A rekey failure leaves the current tunnel in place and lets DPD/keep-alive + the supervisor catch a genuinely
    /// dead session.
    /// </para>
    /// </summary>
    public sealed partial class OpenConnectConnection : ReconnectingVpnConnection, IDisposable, IAsyncDisposable
    {
        static readonly TimeSpan TimerTick = TimeSpan.FromSeconds(1);
        const string DriverNameConst = "openconnect";

        readonly string _host;
        readonly int _port;
        readonly string? _username;
        readonly string? _password;
        readonly string _groupSelect;
        readonly IOpenConnectTransportFactory _transportFactory;
        readonly IOpenConnectDatagramTransportFactory? _datagramFactory;
        readonly DtlsServerCertificateValidationCallback? _dtlsCertificateValidation;
        readonly TimeSpan _dtlsHandshakeTimeout;
        readonly AddressFamilyPreference _addressFamilyPreference;
        readonly IHostResolver _hostResolver;
        readonly int _requestedMtu;

        IByteStreamTransport? _stream;
        CstpChannel? _channel;
        CstpDatagramChannel? _dtlsChannel;
        IDatagramTransport? _dtls;
        CstpDpdState? _dpd;
        CstpRekeyState? _rekey;
        CancellationTokenSource? _loopCts;   // attempt lifetime (cancelled on cleanup/teardown)
        CancellationTokenSource? _recvCts;   // the current receive loops' token — rotated on each rekey so the old loops can be cancelled
        Task? _receiveTask;
        Task? _dtlsReceiveTask;
        System.Threading.Timer? _timer;
        bool _dtlsActive; // true once the data plane is bound to the DTLS channel
        int _rekeyInProgress; // 0/1 guard: at most one rekey runs at a time (and never overlaps a reconnect)

        IPAddress? _assignedAddress;
        IPAddress? _lastAssignedAddress;
        TunnelConfig _config = new();

        /// <summary>
        /// Creates a connection. <paramref name="username"/>/<paramref name="password"/> answer the ocserv auth form
        /// (both null = no-credential / cookie-only gateway); <paramref name="groupSelect"/> picks an auth group when the
        /// gateway offers several; <paramref name="transportFactory"/> opens the TLS byte stream (an in-process factory
        /// drives it offline). <paramref name="datagramFactory"/> opens the plaintext UDP pipe for the DTLS data path —
        /// when supplied and the gateway advertises <c>X-DTLS-*</c>, the data plane runs over DTLS (falling back to TLS
        /// on failure); null = TLS-only. <paramref name="dtlsCertificateValidation"/> validates the gateway's DTLS
        /// certificate (null = accept any). <paramref name="dtlsHandshakeTimeout"/> bounds the DTLS handshake before the
        /// data plane falls back to TLS (default 10s). <paramref name="requestedMtu"/> is advertised in
        /// <c>X-CSTP-Base-MTU</c>; <paramref name="clock"/> supplies the DPD/keep-alive/rekey millisecond clock (default:
        /// the system tick clock) — tests inject a deterministic one. <paramref name="loggerFactory"/> receives diagnostic
        /// traces (auth/connect/DTLS/DPD/rekey/drop); null logs to a no-op logger.
        /// </summary>
        public OpenConnectConnection(string host, int port, IOpenConnectTransportFactory transportFactory,
            string? username = null, string? password = null, string groupSelect = "",
            OpenConnectReconnectOptions? reconnectOptions = null,
            AddressFamilyPreference addressFamilyPreference = AddressFamilyPreference.Auto,
            IHostResolver? hostResolver = null,
            int requestedMtu = 1400,
            Func<long>? clock = null,
            IOpenConnectDatagramTransportFactory? datagramFactory = null,
            DtlsServerCertificateValidationCallback? dtlsCertificateValidation = null,
            TimeSpan? dtlsHandshakeTimeout = null,
            ILoggerFactory? loggerFactory = null)
            : base(DriverNameConst, reconnectOptions ?? new OpenConnectReconnectOptions(), clock, loggerFactory)
        {
            _host = host ?? throw new ArgumentNullException(nameof(host));
            _port = port;
            _transportFactory = transportFactory ?? throw new ArgumentNullException(nameof(transportFactory));
            _datagramFactory = datagramFactory;
            _dtlsCertificateValidation = dtlsCertificateValidation;
            _dtlsHandshakeTimeout = dtlsHandshakeTimeout ?? TimeSpan.FromSeconds(10);
            _username = username;
            _password = password;
            _groupSelect = groupSelect ?? string.Empty;
            _addressFamilyPreference = addressFamilyPreference;
            _hostResolver = hostResolver ?? DnsHostResolver.Default;
            if (requestedMtu < 1) throw new ArgumentOutOfRangeException(nameof(requestedMtu));
            _requestedMtu = requestedMtu;
        }

        /// <summary>The tunnel configuration the gateway pushed in the X-CSTP-* CONNECT headers (address, DNS, routes, MTU).</summary>
        public TunnelConfig Config => _config;

        /// <summary>The tunnel IP address the gateway assigned (valid after connect).</summary>
        public IPAddress AssignedAddress => _assignedAddress ?? IPAddress.Any;

        /// <summary>True when the data plane is running over the DTLS datagram channel; false when it is on CSTP-over-TLS (the fallback).</summary>
        public bool IsDtlsDataPlane => _dtlsActive;

        /// <summary>The CSTP rekey method the gateway requested (<c>X-CSTP-Rekey-Method</c>); <see cref="OpenConnectRekeyMethod.None"/> when rekey is disabled.</summary>
        public OpenConnectRekeyMethod RekeyMethod => _rekey?.Method ?? OpenConnectRekeyMethod.None;

        /// <summary>How many times the CSTP session has been rekeyed (re-established) since the first connect (test/diagnostic hook).</summary>
        public int RekeyCount { get; private set; }

        /// <summary>Raised after a successful auto-reconnect, carrying the new address and whether it changed.</summary>
        public event Action<OpenConnectReconnectInfo>? Reconnected;

        /// <summary>Raised after a successful CSTP rekey (the data plane swapped onto a freshly re-established tunnel).</summary>
        public event Action? Rekeyed;

        /// <summary>Runs auth + CONNECT and returns once the CSTP tunnel is carrying traffic.</summary>
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

            IPAddress serverIp = await _hostResolver.ResolveAsync(_host, _addressFamilyPreference, cancellationToken).ConfigureAwait(false);
            _loopCts = CancellationTokenSource.CreateLinkedTokenSource(LifetimeToken, cancellationToken);
            _recvCts = CancellationTokenSource.CreateLinkedTokenSource(_loopCts.Token);
            CancellationToken connectToken = _loopCts.Token;
            CancellationToken recvToken = _recvCts.Token;

            // Build the CSTP-over-TLS channel + parse the in-band config (no live-field side effects until the bind).
            (IByteStreamTransport stream, CstpChannel channel, OpenConnectTunnelInfo tunnelInfo, TunnelConfig config, int mtu, byte[]? dtlsMasterSecret, ITlsKeyingMaterialExporter? dtlsExporter) =
                await BuildCstpChannelAsync(serverIp, cancellationToken).ConfigureAwait(false);

            _stream = stream;
            WireChannelEvents(channel);
            _channel = channel;

            _config = config;
            _assignedAddress = config.AssignedAddress;
            Facade.SetInner(channel);

            // Start the CSTP-over-TLS receive loop and the DPD/keep-alive + rekey timer (seeded from X-CSTP-DPD/Keepalive/Rekey-*).
            _dpd = new CstpDpdState(tunnelInfo.Dpd ?? 0, tunnelInfo.Keepalive ?? 0, Now());
            _rekey = new CstpRekeyState(tunnelInfo.ParsedRekeyMethod, tunnelInfo.RekeyTime ?? 0, Now());
            MarkRunning(); // a peer-close/fault from the receive loop below must now arm reconnect (before MarkConnected)
            _dtlsActive = false;
            _receiveTask = Task.Run(() => channel.RunReceiveLoopAsync(recvToken));

            Logger.LogHandshake(DriverName, $"CSTP CONNECT accepted; tunnel address {config.AssignedAddress} (CSTP-over-TLS bound)");

            // --- try to swap the data plane onto a parallel DTLS datagram channel (fallback to TLS on any failure) ---
            if (_datagramFactory != null && (tunnelInfo.HasDtlsPsk || tunnelInfo.HasDtls))
                await TryEstablishDtlsAsync(serverIp, tunnelInfo, mtu, dtlsMasterSecret, dtlsExporter, recvToken, connectToken).ConfigureAwait(false);

            _timer = new System.Threading.Timer(_ => _ = TimerTickAsync(), null, TimerTick, TimerTick);

            Logger.LogHandshakeCompleted(DriverName);
            MarkConnected();
        }

        // Connects a fresh TLS byte stream, runs auth + the HTTP CONNECT, and wraps the result in a CstpChannel —
        // without touching any live field. Returned to the caller, which decides whether to bind it (first connect /
        // reconnect) or swap it in make-before-break (rekey).
        async Task<(IByteStreamTransport stream, CstpChannel channel, OpenConnectTunnelInfo tunnelInfo, TunnelConfig config, int mtu, byte[]? dtlsMasterSecret, ITlsKeyingMaterialExporter? dtlsExporter)>
            BuildCstpChannelAsync(IPAddress serverIp, CancellationToken cancellationToken)
        {
            OpenConnectTransportHandle handle = await _transportFactory
                .ConnectAsync(_host, new IPEndPoint(serverIp, _port), cancellationToken).ConfigureAwait(false);
            IByteStreamTransport stream = handle.Stream;

            var http = new OpenConnectHttpTransactor(stream, _host);

            // --- HTTPS config-auth: init → (form → reply)* → success carrying the webvpn cookie ---
            Logger.LogHandshake(DriverName, "HTTPS config-auth (POST /)");
            string cookie = await AuthenticateAsync(http, cancellationToken).ConfigureAwait(false);
            Logger.LogHandshake(DriverName, "config-auth accepted; session cookie received");

            // --- HTTP CONNECT /CSCOSSLC/tunnel: the response X-CSTP-* headers are the in-band tunnel config ---
            // Advertise the DTLS data path only when a datagram factory is wired (otherwise stay TLS-only). When the TLS
            // stream can export RFC 5705 keying material (a BouncyCastleTlsByteStream), prefer the modern DTLS 1.2 PSK
            // path (PSK-NEGOTIATE) — the PSK is derived from the CSTP TLS session, never sent on the wire. Otherwise fall
            // back to legacy AnyConnect DTLS: the 48-byte master secret is transported in-band as X-DTLS-Master-Secret.
            bool requestDtls = _datagramFactory != null;
            ITlsKeyingMaterialExporter? dtlsExporter = stream as ITlsKeyingMaterialExporter;
            bool requestDtlsPsk = requestDtls && dtlsExporter is not null;
            byte[]? dtlsMasterSecret = requestDtls && !requestDtlsPsk ? GenerateDtlsMasterSecret() : null;
            string connectRequest = OpenConnectConnectCodec.BuildConnectRequest(_host, cookie, _requestedMtu,
                requestDtls: requestDtls,
                dtlsMasterSecretHex: dtlsMasterSecret is not null ? ToHex(dtlsMasterSecret) : null,
                requestDtlsPsk: requestDtlsPsk);
            OpenConnectHttpResponse connectResponse = await http.ConnectTunnelAsync(connectRequest, cancellationToken).ConfigureAwait(false);
            OpenConnectTunnelInfo tunnelInfo = OpenConnectConnectCodec.ParseConnectResponse(connectResponse.RawHeaderText + "\r\n\r\n");
            if (tunnelInfo.Address is null && tunnelInfo.AddressV6 is null)
                throw new VpnServerRejectedException("OpenConnect CONNECT response carried no tunnel address (no X-CSTP-Address).");

            TunnelConfig config = tunnelInfo.ToTunnelConfig();
            int mtu = tunnelInfo.Mtu ?? _requestedMtu;
            config.Mtu = mtu;

            var channel = new CstpChannel(stream, mtu);
            return (stream, channel, tunnelInfo, config, mtu, dtlsMasterSecret, dtlsExporter);
        }

        // Subscribes / unsubscribes the shared DPD/peer-close/liveness handlers on a TLS channel.
        void WireChannelEvents(CstpChannel channel)
        {
            channel.DpdRequestReceived += OnDpdRequest;
            channel.PeerClosed += OnPeerClosed;
            channel.PacketReceived += OnPacketReceived;
            channel.PacketSent += OnPacketSent;
        }

        void UnwireChannelEvents(CstpChannel channel)
        {
            channel.DpdRequestReceived -= OnDpdRequest;
            channel.PeerClosed -= OnPeerClosed;
            channel.PacketReceived -= OnPacketReceived;
            channel.PacketSent -= OnPacketSent;
        }

        void WireDatagramEvents(CstpDatagramChannel channel)
        {
            channel.DpdRequestReceived += OnDpdRequest;
            channel.PeerClosed += OnPeerClosed;
            channel.PacketReceived += OnPacketReceived;
            channel.PacketSent += OnPacketSent;
        }

        void UnwireDatagramEvents(CstpDatagramChannel channel)
        {
            channel.DpdRequestReceived -= OnDpdRequest;
            channel.PeerClosed -= OnPeerClosed;
            channel.PacketReceived -= OnPacketReceived;
            channel.PacketSent -= OnPacketSent;
        }

        // Opens UDP → DTLS → CstpDatagramChannel and swaps the data plane onto it. Any failure leaves the data plane on
        // CSTP-over-TLS (the fallback) — DTLS is an optimisation, never a hard requirement.
        async Task TryEstablishDtlsAsync(IPAddress serverIp, OpenConnectTunnelInfo tunnelInfo, int mtu,
            byte[]? dtlsMasterSecret, ITlsKeyingMaterialExporter? dtlsExporter, CancellationToken loopToken, CancellationToken cancellationToken)
        {
            IDatagramTransport? udp = null;
            DtlsDatagramTransport? dtls = null;
            int dtlsMtu = tunnelInfo.DtlsMtu ?? mtu;
            // Bound the handshake so a black-holed UDP path falls back to TLS promptly instead of stalling the connect.
            using var handshakeCts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
            handshakeCts.CancelAfter(_dtlsHandshakeTimeout);
            try
            {
                var dtlsEndpoint = new IPEndPoint(serverIp, tunnelInfo.DtlsPort!.Value);
                udp = await _datagramFactory!.ConnectAsync(_host, dtlsEndpoint, handshakeCts.Token).ConfigureAwait(false);

                // Prefer the modern DTLS 1.2 PSK full handshake (PSK-NEGOTIATE) when the gateway accepted it and the CSTP
                // TLS session can export the PSK; otherwise fall back to legacy AnyConnect DTLS resumption (in-band master
                // secret + X-DTLS-Session-ID). PSK avoids the GnuTLS↔BouncyCastle legacy-resumption interop failure.
                DtlsPskParameters? psk = BuildDtlsPsk(tunnelInfo, dtlsExporter);
                if (psk is not null)
                {
                    dtls = new DtlsDatagramTransport(udp, _dtlsCertificateValidation, ownsInner: true, psk: psk);
                    Logger.LogHandshake(DriverName, "DTLS 1.2 PSK (PSK-NEGOTIATE) handshake starting");
                }
                else
                {
                    DtlsResumptionParameters? resumption = BuildDtlsResumption(tunnelInfo, dtlsMasterSecret);
                    dtls = new DtlsDatagramTransport(udp, _dtlsCertificateValidation, ownsInner: true, resumption: resumption);
                }
                await dtls.ConnectAsync(handshakeCts.Token).ConfigureAwait(false);

                var dtlsChannel = new CstpDatagramChannel(dtls, dtlsMtu, ownsTransport: false);
                WireDatagramEvents(dtlsChannel);

                _dtls = dtls;
                _dtlsChannel = dtlsChannel;
                _dtlsActive = true;
                Facade.SetInner(dtlsChannel); // data now rides DTLS; TLS channel stays as the control/fallback path
                _dtlsReceiveTask = Task.Run(() => dtlsChannel.RunReceiveLoopAsync(loopToken));
                Logger.LogHandshake(DriverName, $"DTLS 1.2 data path established ({(psk is not null ? "PSK-NEGOTIATE" : "legacy")}; data plane swapped to DTLS)");
            }
            catch (Exception ex)
            {
                Logger.LogHandshake(DriverName, $"DTLS data path unavailable ({ex.GetType().Name}: {ex.Message}); staying on CSTP-over-TLS (fallback)");
                // DTLS handshake / socket failed (or hit the handshake timeout) — fall back to CSTP-over-TLS (already
                // bound). Clean up the half-open DTLS first.
                _dtlsActive = false;
                _dtlsChannel = null;
                _dtls = null;
                if (dtls != null) { try { await dtls.DisposeAsync().ConfigureAwait(false); } catch { } }
                else if (udp != null) { try { await udp.DisposeAsync().ConfigureAwait(false); } catch { } }

                // A genuine outer cancellation must abort the whole connect; only a DTLS-side failure/timeout falls back.
                cancellationToken.ThrowIfCancellationRequested();
            }
        }

        // A fresh 48-byte DTLS master secret (legacy AnyConnect X-DTLS-Master-Secret).
        byte[] GenerateDtlsMasterSecret()
        {
            byte[] secret = new byte[48];
            NextRandomBytes(secret);
            return secret;
        }

        // Builds the legacy AnyConnect DTLS resumption parameters from the gateway's X-DTLS-Session-ID/CipherSuite and our
        // in-band master secret; null when any piece is missing (the master secret, a hex session id, or a known cipher)
        // ⇒ the DTLS client falls back to a full handshake. ocserv dtls-legacy needs the resumption to accept the session.
        static DtlsResumptionParameters? BuildDtlsResumption(OpenConnectTunnelInfo tunnelInfo, byte[]? masterSecret)
        {
            if (masterSecret is null || masterSecret.Length == 0) return null;
            if (!TryParseHex(tunnelInfo.DtlsSessionId, out byte[] sessionId) || sessionId.Length == 0) return null;
            if (!DtlsCipherSuiteMap.TryResolve(tunnelInfo.DtlsCipherSuite, out int cipherSuite)) return null;
            return new DtlsResumptionParameters(masterSecret, sessionId, cipherSuite);
        }

        // The RFC 5705 exporter label + PSK identity for the modern OpenConnect DTLS 1.2 PSK path
        // (draft-mavrogiannopoulos-openconnect): the 32-byte PSK is exported from the CSTP TLS session with this label and
        // an empty context; the on-wire PSK identity is the ASCII string "psk".
        const string DtlsPskExporterLabel = "EXPORTER-openconnect-psk";
        const int DtlsPskKeyLength = 32;

        // Builds the modern DTLS 1.2 PSK parameters: the 32-byte PSK exported from the CSTP TLS session and the App-ID
        // (hex-decoded) for the ClientHello session_id. null when the gateway did not accept PSK-NEGOTIATE, no exporter is
        // available, or the App-ID is missing/odd-length ⇒ the caller falls back to legacy DTLS / CSTP-over-TLS.
        static DtlsPskParameters? BuildDtlsPsk(OpenConnectTunnelInfo tunnelInfo, ITlsKeyingMaterialExporter? exporter)
        {
            if (exporter is null || !tunnelInfo.HasDtlsPsk) return null;
            if (!TryParseHex(tunnelInfo.DtlsAppId, out byte[] sessionId) || sessionId.Length == 0) return null;
            byte[] pskKey = exporter.ExportKeyingMaterial(DtlsPskExporterLabel, ReadOnlySpan<byte>.Empty, DtlsPskKeyLength);
            byte[] identity = Encoding.ASCII.GetBytes("psk");
            return new DtlsPskParameters(identity, pskKey, sessionId);
        }

        static string ToHex(byte[] bytes)
        {
            var sb = new StringBuilder(bytes.Length * 2);
            foreach (byte b in bytes) sb.Append(b.ToString("x2"));
            return sb.ToString();
        }

        static bool TryParseHex(string? hex, out byte[] bytes)
        {
            bytes = Array.Empty<byte>();
            if (string.IsNullOrEmpty(hex) || (hex!.Length & 1) != 0) return false;
            var result = new byte[hex.Length / 2];
            for (int i = 0; i < result.Length; i++)
            {
                if (!byte.TryParse(hex.Substring(i * 2, 2), System.Globalization.NumberStyles.HexNumber,
                        System.Globalization.CultureInfo.InvariantCulture, out byte b))
                    return false;
                result[i] = b;
            }
            bytes = result;
            return true;
        }

        // Runs the ocserv config-auth handshake and returns the session cookie ("webvpn=..."), throwing on rejection.
        async Task<string> AuthenticateAsync(OpenConnectHttpTransactor http, CancellationToken cancellationToken)
        {
            string requestBody = OpenConnectAuthCodec.BuildInitRequest(_groupSelect);
            string? cookie = null;

            for (int step = 0; step < 8; step++) // bounded: init + a few form rounds (defends against a server loop)
            {
                OpenConnectHttpResponse response = await http.PostAsync("/", requestBody, cookie, cancellationToken).ConfigureAwait(false);
                if (response.StatusCode != 200)
                {
                    Logger.LogHandshakeFailed(DriverName, $"auth POST returned HTTP {response.StatusCode} {response.Reason}");
                    throw new VpnAuthenticationException($"OpenConnect auth POST failed: HTTP {response.StatusCode} {response.Reason}.");
                }

                // The cookie may be set at any step; capture it as it appears.
                foreach (string setCookie in response.GetHeaders("set-cookie"))
                {
                    string? extracted = OpenConnectAuthCodec.ExtractCookie("Set-Cookie: " + setCookie);
                    if (extracted != null) cookie = extracted;
                }

                if (OpenConnectAuthCodec.IsSuccess(response.Body))
                {
                    if (string.IsNullOrEmpty(cookie))
                        throw new VpnAuthenticationException("OpenConnect auth succeeded but the gateway returned no session cookie.");
                    return cookie!;
                }

                if (!OpenConnectAuthCodec.TryParseForm(response.Body, out OpenConnectAuthForm form))
                {
                    Logger.LogHandshakeFailed(DriverName, "auth rejected: non-form, non-success response (bad credentials)");
                    throw new VpnAuthenticationException("OpenConnect gateway returned a non-form, non-success auth response.");
                }

                FillForm(form);
                requestBody = OpenConnectAuthCodec.BuildReplyRequest(form);
            }
            Logger.LogHandshakeFailed(DriverName, "auth did not complete within the allowed number of steps");
            throw new VpnAuthenticationException("OpenConnect auth did not complete within the allowed number of steps.");
        }

        // Answers the form's username/password/select inputs from the supplied credentials.
        void FillForm(OpenConnectAuthForm form)
        {
            foreach (OpenConnectAuthField field in form.Fields)
            {
                if (IsUsernameField(field) && _username != null) field.Value = _username;
                else if (IsPasswordField(field) && _password != null) field.Value = _password;
                else if (IsGroupField(field) && !string.IsNullOrEmpty(_groupSelect)) field.Value = _groupSelect;
            }
        }

        static bool IsUsernameField(OpenConnectAuthField f) =>
            f.Name.IndexOf("user", StringComparison.OrdinalIgnoreCase) >= 0;
        static bool IsPasswordField(OpenConnectAuthField f) =>
            string.Equals(f.Type, "password", StringComparison.OrdinalIgnoreCase)
            || f.Name.IndexOf("pass", StringComparison.OrdinalIgnoreCase) >= 0;
        static bool IsGroupField(OpenConnectAuthField f) =>
            f.Name.IndexOf("group", StringComparison.OrdinalIgnoreCase) >= 0;

        // ---- CSTP event wiring: DPD reply, peer close, liveness (shared by the TLS and DTLS channels) ----

        // Control frames go over whichever channel is the active data plane (DTLS when up, else CSTP-over-TLS). Liveness
        // (PacketReceived) and the send timer (PacketSent) feed one shared CstpDpdState, so inbound traffic on either
        // path keeps the peer alive.
        Func<CancellationToken, ValueTask>? ActiveDpdRequest
        {
            get
            {
                CstpDatagramChannel? dtls = _dtlsChannel;
                if (_dtlsActive && dtls != null) return dtls.SendDpdRequestAsync;
                CstpChannel? tls = _channel;
                return tls != null ? tls.SendDpdRequestAsync : null;
            }
        }

        Func<CancellationToken, ValueTask>? ActiveDpdResponse
        {
            get
            {
                CstpDatagramChannel? dtls = _dtlsChannel;
                if (_dtlsActive && dtls != null) return dtls.SendDpdResponseAsync;
                CstpChannel? tls = _channel;
                return tls != null ? tls.SendDpdResponseAsync : null;
            }
        }

        Func<CancellationToken, ValueTask>? ActiveKeepalive
        {
            get
            {
                CstpDatagramChannel? dtls = _dtlsChannel;
                if (_dtlsActive && dtls != null) return dtls.SendKeepaliveAsync;
                CstpChannel? tls = _channel;
                return tls != null ? tls.SendKeepaliveAsync : null;
            }
        }

        void OnDpdRequest()
        {
            Func<CancellationToken, ValueTask>? reply = ActiveDpdResponse;
            if (reply != null) _ = SafeSendAsync(reply);
        }

        void OnPeerClosed() => OnLinkLost("OpenConnect gateway closed the CSTP session (DISCONNECT/TERMINATE or stream EOF).");

        void OnPacketReceived() => _dpd?.OnDataReceived(Now());

        void OnPacketSent() => _dpd?.OnDataSent(Now());

        // ---- timer loop: DPD probe + dead detection + idle keep-alive + session rekey (driven by CstpDpdState/CstpRekeyState) ----

        async Task TimerTickAsync()
        {
            if (!IsRunning) return;
            CstpDpdState? dpd = _dpd;
            Func<CancellationToken, ValueTask>? dpdRequest = ActiveDpdRequest;
            if (dpd is null || dpdRequest is null) return;

            long now = Now();
            if (dpd.IsPeerDead(now))
            {
                OnLinkLost("X-CSTP-DPD: no traffic from the OpenConnect gateway within the dead-peer-detection window.");
                return;
            }

            // Session rekey (X-CSTP-Rekey-*): refresh the tunnel make-before-break before the gateway times it out.
            CstpRekeyState? rekey = _rekey;
            if (rekey != null && rekey.ShouldRekey(now))
            {
                await MaybeRekeyAsync(rekey).ConfigureAwait(false);
                return; // a rekey already exchanges traffic; skip the DPD/keep-alive probe this tick
            }

            if (dpd.ShouldSendDpd(now))
            {
                dpd.OnDpdSent(now);
                Logger.LogKeepalive(DriverName, "X-CSTP-DPD probe sent");
                await SafeSendAsync(dpdRequest).ConfigureAwait(false);
            }
            else if (dpd.ShouldSendKeepalive(now))
            {
                Func<CancellationToken, ValueTask>? keepalive = ActiveKeepalive;
                if (keepalive != null)
                {
                    Logger.LogKeepalive(DriverName, "X-CSTP-Keepalive sent");
                    await SafeSendAsync(keepalive).ConfigureAwait(false);
                }
            }
        }

        static async Task SafeSendAsync(Func<CancellationToken, ValueTask> send)
        {
            try { await send(default).ConfigureAwait(false); }
            catch { /* a missed control frame trips DPD/keep-alive later; never crash the timer */ }
        }

        // ---- session rekey (V.5): re-establish a fresh tunnel make-before-break and swap onto it ----

        // Runs at most one rekey at a time; a rekey that fails leaves the current tunnel up (DPD/supervisor cover a real
        // dead session). Both new-tunnel and ssl re-establish (SslStream has no client TLS renegotiation on these TFMs).
        async Task MaybeRekeyAsync(CstpRekeyState rekey)
        {
            if (Interlocked.CompareExchange(ref _rekeyInProgress, 1, 0) != 0) return; // a rekey is already running
            try
            {
                if (!IsRunning) return; // dropped between the timer check and here
                await RekeyAsync(rekey).ConfigureAwait(false);
            }
            catch
            {
                Logger.LogHandshakeFailed(DriverName, "CSTP rekey failed; keeping the current tunnel (DPD/supervisor will catch a dead session)");
                // Keep the live tunnel; re-arm so the next period retries. DPD/keep-alive + the supervisor remain the
                // safety net for a genuinely dead session.
                rekey.OnRekeyDone(Now());
            }
            finally
            {
                Interlocked.Exchange(ref _rekeyInProgress, 0);
            }
        }

        async Task RekeyAsync(CstpRekeyState rekey)
        {
            Logger.LogHandshake(DriverName, $"CSTP rekey ({rekey.Method}) due; re-establishing the tunnel make-before-break");
            CancellationToken connectToken = _loopCts?.Token ?? LifetimeToken;
            IPAddress serverIp = await _hostResolver.ResolveAsync(_host, _addressFamilyPreference, connectToken).ConfigureAwait(false);

            // 1) Build a fresh tunnel into locals (the current tunnel keeps carrying traffic throughout).
            (IByteStreamTransport newStream, CstpChannel newChannel, OpenConnectTunnelInfo newInfo, TunnelConfig newConfig, int newMtu, byte[]? newDtlsMasterSecret, ITlsKeyingMaterialExporter? newDtlsExporter) =
                await BuildCstpChannelAsync(serverIp, connectToken).ConfigureAwait(false);

            // 2) Capture the old resources + the old receive-loop token so we can cancel the old loops after the swap.
            CstpChannel? oldChannel = _channel;
            CstpDatagramChannel? oldDtlsChannel = _dtlsChannel;
            IDatagramTransport? oldDtls = _dtls;
            IByteStreamTransport? oldStream = _stream;
            Task? oldReceive = _receiveTask;
            Task? oldDtlsReceive = _dtlsReceiveTask;
            CancellationTokenSource? oldRecvCts = _recvCts;

            // 3) Swap onto the new CSTP-over-TLS channel behind the stable facade (the IP stack never rebinds). The new
            //    loops run under a fresh receive-loop token so the old ones can be cancelled independently.
            var newRecvCts = CancellationTokenSource.CreateLinkedTokenSource(connectToken);
            CancellationToken newRecvToken = newRecvCts.Token;
            WireChannelEvents(newChannel);
            _stream = newStream;
            _channel = newChannel;
            _dtlsChannel = null;
            _dtls = null;
            _dtlsActive = false;
            _config = newConfig;
            _assignedAddress = newConfig.AssignedAddress;
            _dpd = new CstpDpdState(newInfo.Dpd ?? 0, newInfo.Keepalive ?? 0, Now());
            _recvCts = newRecvCts;
            _receiveTask = Task.Run(() => newChannel.RunReceiveLoopAsync(newRecvToken));
            _dtlsReceiveTask = null;
            Facade.SetInner(newChannel);

            // Re-open the DTLS data path on the new tunnel when the gateway still offers it (fallback to TLS otherwise).
            if (_datagramFactory != null && (newInfo.HasDtlsPsk || newInfo.HasDtls))
                await TryEstablishDtlsAsync(serverIp, newInfo, newMtu, newDtlsMasterSecret, newDtlsExporter, newRecvToken, connectToken).ConfigureAwait(false);

            // 4) Tear the old tunnel down: detach its events (so its EOF cannot call OnLinkLost), send a best-effort
            //    DISCONNECT, cancel + await its loops, then dispose it. Done after the swap = make-before-break.
            if (oldDtlsChannel != null) UnwireDatagramEvents(oldDtlsChannel);
            if (oldChannel != null) UnwireChannelEvents(oldChannel);
            if (oldDtlsChannel != null) { try { await oldDtlsChannel.SendDisconnectAsync(connectToken).ConfigureAwait(false); } catch { } }
            if (oldChannel != null) { try { await oldChannel.SendDisconnectAsync(connectToken).ConfigureAwait(false); } catch { } }
            try { oldRecvCts?.Cancel(); } catch { }
            if (oldReceive != null) { try { await oldReceive.ConfigureAwait(false); } catch { } }
            if (oldDtlsReceive != null) { try { await oldDtlsReceive.ConfigureAwait(false); } catch { } }
            oldRecvCts?.Dispose();
            if (oldDtlsChannel != null) { try { await oldDtlsChannel.DisposeAsync().ConfigureAwait(false); } catch { } }
            if (oldDtls != null) { try { await oldDtls.DisposeAsync().ConfigureAwait(false); } catch { } }
            if (oldChannel != null) { try { await oldChannel.DisposeAsync().ConfigureAwait(false); } catch { } }
            if (oldStream != null) { try { await oldStream.DisposeAsync().ConfigureAwait(false); } catch { } }

            RekeyCount++;
            rekey.OnRekeyDone(Now());
            Logger.LogHandshake(DriverName, $"CSTP rekey complete (#{RekeyCount}); tunnel address {newConfig.AssignedAddress}");
            Rekeyed?.Invoke();
        }

        // ---- link-loss handling + auto-reconnect supervisor live in ReconnectingVpnConnection (roadmap F.6). ----
        // OnPeerClosed / the DPD-dead path call the inherited OnLinkLost, which arms the shared ReconnectLoopAsync.

        /// <inheritdoc/>
        protected override void OnReconnected()
        {
            IPAddress newAddress = _assignedAddress ?? IPAddress.Any;
            bool changed = _lastAssignedAddress != null && !newAddress.Equals(_lastAssignedAddress);
            _lastAssignedAddress = newAddress;
            Reconnected?.Invoke(new OpenConnectReconnectInfo(newAddress, changed));
        }

        // ---- teardown ----

        /// <summary>
        /// Tears the tunnel down permanently (no reconnect): sends a best-effort CSTP DISCONNECT on both data paths, then
        /// runs the shared teardown (cancel any reconnect in flight, cancel the receive loop, dispose the stream).
        /// Best-effort and time-boxed; safe to call more than once.
        /// </summary>
        public override async Task DisconnectAsync(CancellationToken cancellationToken = default)
        {
            CstpChannel? channel = _channel;
            CstpDatagramChannel? dtlsChannel = _dtlsChannel;
            // Best-effort DISCONNECT on both paths (the active data plane and the TLS control/fallback channel).
            if (dtlsChannel != null) { try { await dtlsChannel.SendDisconnectAsync(cancellationToken).ConfigureAwait(false); } catch { } }
            if (channel != null) { try { await channel.SendDisconnectAsync(cancellationToken).ConfigureAwait(false); } catch { } }

            await DisconnectCoreAsync().ConfigureAwait(false);
        }

        /// <inheritdoc/>
        protected override async Task CleanupAttemptResourcesAsync()
        {
            StopAttemptLoop();
            _dtlsActive = false;
            _rekey = null;

            CstpChannel? channel = _channel;
            _channel = null;
            if (channel != null) UnwireChannelEvents(channel);

            CstpDatagramChannel? dtlsChannel = _dtlsChannel;
            _dtlsChannel = null;
            if (dtlsChannel != null) UnwireDatagramEvents(dtlsChannel);

            CancellationTokenSource? recv = _recvCts;
            _recvCts = null;
            try { recv?.Cancel(); } catch { } // cancels the current receive loops (linked to _loopCts)

            CancellationTokenSource? loop = _loopCts;
            _loopCts = null;
            try { loop?.Cancel(); } catch { }

            Task? receive = _receiveTask;
            _receiveTask = null;
            if (receive != null) { try { await receive.ConfigureAwait(false); } catch { } }

            Task? dtlsReceive = _dtlsReceiveTask;
            _dtlsReceiveTask = null;
            if (dtlsReceive != null) { try { await dtlsReceive.ConfigureAwait(false); } catch { } }
            recv?.Dispose();
            loop?.Dispose();

            if (dtlsChannel != null) { try { await dtlsChannel.DisposeAsync().ConfigureAwait(false); } catch { } }

            // The DTLS channel does not own the DTLS transport (ownsTransport:false) so dispose it here (close_notify + UDP).
            IDatagramTransport? dtls = _dtls;
            _dtls = null;
            if (dtls != null) { try { await dtls.DisposeAsync().ConfigureAwait(false); } catch { } }

            if (channel != null) { try { await channel.DisposeAsync().ConfigureAwait(false); } catch { } }

            IByteStreamTransport? stream = _stream;
            _stream = null;
            if (stream != null) { try { await stream.DisposeAsync().ConfigureAwait(false); } catch { } }

            _dpd = null;
        }

        /// <inheritdoc/>
        protected override void StopAttemptLoop()
        {
            _timer?.Dispose();
            _timer = null;
        }

        // ---- teardown / dispose ----

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
