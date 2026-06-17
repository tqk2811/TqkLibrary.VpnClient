using System.Net;
using System.Text;
using TqkLibrary.VpnClient.Abstractions.Channels;
using TqkLibrary.VpnClient.Abstractions.Channels.Interfaces;
using TqkLibrary.VpnClient.Abstractions.Drivers;
using TqkLibrary.VpnClient.Abstractions.Drivers.Models;
using TqkLibrary.VpnClient.Abstractions.Net;
using TqkLibrary.VpnClient.Abstractions.Transport.Interfaces;
using TqkLibrary.VpnClient.Drivers.OpenConnect.Enums;
using TqkLibrary.VpnClient.Drivers.OpenConnect.Models;
using TqkLibrary.VpnClient.Drivers.OpenConnect.Transport;
using TqkLibrary.VpnClient.OpenConnect;
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
    /// </summary>
    public sealed class OpenConnectConnection : IDisposable, IAsyncDisposable
    {
        static readonly TimeSpan TimerTick = TimeSpan.FromSeconds(1);

        readonly string _host;
        readonly int _port;
        readonly string? _username;
        readonly string? _password;
        readonly string _groupSelect;
        readonly IOpenConnectTransportFactory _transportFactory;
        readonly IOpenConnectDatagramTransportFactory? _datagramFactory;
        readonly DtlsServerCertificateValidationCallback? _dtlsCertificateValidation;
        readonly TimeSpan _dtlsHandshakeTimeout;
        readonly OpenConnectReconnectOptions _opts;
        readonly AddressFamilyPreference _addressFamilyPreference;
        readonly IHostResolver _hostResolver;
        readonly int _requestedMtu;
        readonly Func<long> _clock;

        readonly SwappablePacketChannel _facade = new();
        readonly CancellationTokenSource _lifetimeCts = new();
        readonly Random _random = new();
        readonly object _stateLock = new();

        IByteStreamTransport? _stream;
        CstpChannel? _channel;
        CstpDatagramChannel? _dtlsChannel;
        IDatagramTransport? _dtls;
        CstpDpdState? _dpd;
        CancellationTokenSource? _loopCts;
        Task? _receiveTask;
        Task? _dtlsReceiveTask;
        System.Threading.Timer? _timer;
        bool _dtlsActive; // true once the data plane is bound to the DTLS channel

        IPAddress? _assignedAddress;
        IPAddress? _lastAssignedAddress;
        TunnelConfig _config = new();

        volatile bool _running;
        volatile bool _userTeardown;
        bool _supervisorActive;   // guarded by _stateLock
        Task? _supervisor;
        OpenConnectConnectionState _state = OpenConnectConnectionState.Disconnected;

        /// <summary>
        /// Creates a connection. <paramref name="username"/>/<paramref name="password"/> answer the ocserv auth form
        /// (both null = no-credential / cookie-only gateway); <paramref name="groupSelect"/> picks an auth group when the
        /// gateway offers several; <paramref name="transportFactory"/> opens the TLS byte stream (an in-process factory
        /// drives it offline). <paramref name="datagramFactory"/> opens the plaintext UDP pipe for the DTLS data path —
        /// when supplied and the gateway advertises <c>X-DTLS-*</c>, the data plane runs over DTLS (falling back to TLS
        /// on failure); null = TLS-only. <paramref name="dtlsCertificateValidation"/> validates the gateway's DTLS
        /// certificate (null = accept any). <paramref name="dtlsHandshakeTimeout"/> bounds the DTLS handshake before the
        /// data plane falls back to TLS (default 10s). <paramref name="requestedMtu"/> is advertised in
        /// <c>X-CSTP-Base-MTU</c>; <paramref name="clock"/> supplies the DPD/keep-alive millisecond clock (default: the
        /// system tick clock) — tests inject a deterministic one.
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
            TimeSpan? dtlsHandshakeTimeout = null)
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
            _opts = reconnectOptions ?? new OpenConnectReconnectOptions();
            _addressFamilyPreference = addressFamilyPreference;
            _hostResolver = hostResolver ?? DnsHostResolver.Default;
            if (requestedMtu < 1) throw new ArgumentOutOfRangeException(nameof(requestedMtu));
            _requestedMtu = requestedMtu;
            _clock = clock ?? DefaultClock;
        }

        /// <summary>The stable L3 packet channel (valid after a successful connect; survives reconnect).</summary>
        public IPacketChannel PacketChannel => _facade;

        /// <summary>The tunnel configuration the gateway pushed in the X-CSTP-* CONNECT headers (address, DNS, routes, MTU).</summary>
        public TunnelConfig Config => _config;

        /// <summary>The tunnel IP address the gateway assigned (valid after connect).</summary>
        public IPAddress AssignedAddress => _assignedAddress ?? IPAddress.Any;

        /// <summary>True when the data plane is running over the DTLS datagram channel; false when it is on CSTP-over-TLS (the fallback).</summary>
        public bool IsDtlsDataPlane => _dtlsActive;

        /// <summary>Raised whenever the connection state changes (auth/connect progress, drop, reconnect).</summary>
        public event Action<OpenConnectConnectionState>? StateChanged;

        /// <summary>Raised after a successful auto-reconnect, carrying the new address and whether it changed.</summary>
        public event Action<OpenConnectReconnectInfo>? Reconnected;

        /// <summary>The current lifecycle state.</summary>
        public OpenConnectConnectionState State => _state;

        /// <summary>Runs auth + CONNECT and returns once the CSTP tunnel is carrying traffic.</summary>
        public async Task ConnectAsync(CancellationToken cancellationToken = default)
        {
            SetState(OpenConnectConnectionState.Connecting);
            await EstablishAsync(cancellationToken).ConfigureAwait(false);
            _lastAssignedAddress = _assignedAddress;
        }

        // ---- one full tunnel attempt (reused by the first connect and every reconnect) ----

        async Task EstablishAsync(CancellationToken cancellationToken)
        {
            await CleanupAttemptResourcesAsync().ConfigureAwait(false);

            IPAddress serverIp = await _hostResolver.ResolveAsync(_host, _addressFamilyPreference, cancellationToken).ConfigureAwait(false);
            _loopCts = CancellationTokenSource.CreateLinkedTokenSource(_lifetimeCts.Token, cancellationToken);
            CancellationToken loopToken = _loopCts.Token;

            OpenConnectTransportHandle handle = await _transportFactory
                .ConnectAsync(_host, new IPEndPoint(serverIp, _port), cancellationToken).ConfigureAwait(false);
            IByteStreamTransport stream = handle.Stream;
            _stream = stream;

            var http = new OpenConnectHttpTransactor(stream, _host);

            // --- HTTPS config-auth: init → (form → reply)* → success carrying the webvpn cookie ---
            string cookie = await AuthenticateAsync(http, cancellationToken).ConfigureAwait(false);

            // --- HTTP CONNECT /CSCOSSLC/tunnel: the response X-CSTP-* headers are the in-band tunnel config ---
            // Advertise the DTLS data path only when a datagram factory is wired (otherwise stay TLS-only).
            bool requestDtls = _datagramFactory != null;
            string connectRequest = OpenConnectConnectCodec.BuildConnectRequest(_host, cookie, _requestedMtu,
                requestDtls: requestDtls,
                dtlsMasterSecretHex: requestDtls ? GenerateDtlsMasterSecretHex() : null);
            OpenConnectHttpResponse connectResponse = await http.ConnectTunnelAsync(connectRequest, cancellationToken).ConfigureAwait(false);
            OpenConnectTunnelInfo tunnelInfo = OpenConnectConnectCodec.ParseConnectResponse(connectResponse.RawHeaderText + "\r\n\r\n");
            if (tunnelInfo.Address is null && tunnelInfo.AddressV6 is null)
                throw new VpnServerRejectedException("OpenConnect CONNECT response carried no tunnel address (no X-CSTP-Address).");

            // --- bind the CSTP-over-TLS data plane behind the stable facade (control + fallback path) ---
            TunnelConfig config = tunnelInfo.ToTunnelConfig();
            int mtu = tunnelInfo.Mtu ?? _requestedMtu;
            config.Mtu = mtu;

            var channel = new CstpChannel(stream, mtu);
            channel.DpdRequestReceived += OnDpdRequest;
            channel.PeerClosed += OnPeerClosed;
            channel.PacketReceived += OnPacketReceived;
            channel.PacketSent += OnPacketSent;
            _channel = channel;

            _config = config;
            _assignedAddress = config.AssignedAddress;
            _facade.SetInner(channel);

            // Start the CSTP-over-TLS receive loop and the DPD/keep-alive timer (seeded from X-CSTP-DPD/Keepalive).
            _dpd = new CstpDpdState(tunnelInfo.Dpd ?? 0, tunnelInfo.Keepalive ?? 0, _clock());
            _running = true;
            _dtlsActive = false;
            _receiveTask = Task.Run(() => channel.RunReceiveLoopAsync(loopToken));

            // --- try to swap the data plane onto a parallel DTLS datagram channel (fallback to TLS on any failure) ---
            if (requestDtls && tunnelInfo.HasDtls)
                await TryEstablishDtlsAsync(serverIp, tunnelInfo, mtu, loopToken, cancellationToken).ConfigureAwait(false);

            _timer = new System.Threading.Timer(_ => _ = TimerTickAsync(), null, TimerTick, TimerTick);

            SetState(OpenConnectConnectionState.Connected);
        }

        // Opens UDP → DTLS → CstpDatagramChannel and swaps the data plane onto it. Any failure leaves the data plane on
        // CSTP-over-TLS (the fallback) — DTLS is an optimisation, never a hard requirement.
        async Task TryEstablishDtlsAsync(IPAddress serverIp, OpenConnectTunnelInfo tunnelInfo, int mtu,
            CancellationToken loopToken, CancellationToken cancellationToken)
        {
            IDatagramTransport? udp = null;
            DtlsDatagramTransport? dtls = null;
            // Bound the handshake so a black-holed UDP path falls back to TLS promptly instead of stalling the connect.
            using var handshakeCts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
            handshakeCts.CancelAfter(_dtlsHandshakeTimeout);
            try
            {
                var dtlsEndpoint = new IPEndPoint(serverIp, tunnelInfo.DtlsPort!.Value);
                udp = await _datagramFactory!.ConnectAsync(_host, dtlsEndpoint, handshakeCts.Token).ConfigureAwait(false);
                // The X-DTLS-Session-ID correlates the UDP/DTLS session to this CSTP session (it is carried as the DTLS
                // ClientHello session_id by AnyConnect/ocserv; the offline loopback link already pairs the two ends).
                dtls = new DtlsDatagramTransport(udp, _dtlsCertificateValidation, ownsInner: true);
                await dtls.ConnectAsync(handshakeCts.Token).ConfigureAwait(false);

                var dtlsChannel = new CstpDatagramChannel(dtls, mtu, ownsTransport: false);
                dtlsChannel.DpdRequestReceived += OnDpdRequest;
                dtlsChannel.PeerClosed += OnPeerClosed;
                dtlsChannel.PacketReceived += OnPacketReceived;
                dtlsChannel.PacketSent += OnPacketSent;

                _dtls = dtls;
                _dtlsChannel = dtlsChannel;
                _dtlsActive = true;
                _facade.SetInner(dtlsChannel); // data now rides DTLS; TLS channel stays as the control/fallback path
                _dtlsReceiveTask = Task.Run(() => dtlsChannel.RunReceiveLoopAsync(loopToken));
            }
            catch
            {
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

        // A fresh 48-byte DTLS master secret (legacy AnyConnect X-DTLS-Master-Secret), hex-encoded.
        string GenerateDtlsMasterSecretHex()
        {
            byte[] secret = new byte[48];
            lock (_random) _random.NextBytes(secret);
            var sb = new StringBuilder(secret.Length * 2);
            foreach (byte b in secret) sb.Append(b.ToString("x2"));
            return sb.ToString();
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
                    throw new VpnAuthenticationException($"OpenConnect auth POST failed: HTTP {response.StatusCode} {response.Reason}.");

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
                    throw new VpnAuthenticationException("OpenConnect gateway returned a non-form, non-success auth response.");

                FillForm(form);
                requestBody = OpenConnectAuthCodec.BuildReplyRequest(form);
            }
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

        void OnPacketReceived() => _dpd?.OnDataReceived(_clock());

        void OnPacketSent() => _dpd?.OnDataSent(_clock());

        // ---- timer loop: DPD probe + dead detection + idle keep-alive (driven by CstpDpdState) ----

        async Task TimerTickAsync()
        {
            if (!_running) return;
            CstpDpdState? dpd = _dpd;
            Func<CancellationToken, ValueTask>? dpdRequest = ActiveDpdRequest;
            if (dpd is null || dpdRequest is null) return;

            long now = _clock();
            if (dpd.IsPeerDead(now))
            {
                OnLinkLost("X-CSTP-DPD: no traffic from the OpenConnect gateway within the dead-peer-detection window.");
                return;
            }
            if (dpd.ShouldSendDpd(now))
            {
                dpd.OnDpdSent(now);
                await SafeSendAsync(dpdRequest).ConfigureAwait(false);
            }
            else if (dpd.ShouldSendKeepalive(now))
            {
                Func<CancellationToken, ValueTask>? keepalive = ActiveKeepalive;
                if (keepalive != null) await SafeSendAsync(keepalive).ConfigureAwait(false);
            }
        }

        static async Task SafeSendAsync(Func<CancellationToken, ValueTask> send)
        {
            try { await send(default).ConfigureAwait(false); }
            catch { /* a missed control frame trips DPD/keep-alive later; never crash the timer */ }
        }

        // ---- link-loss handling + auto-reconnect supervisor (mirrors the WireGuard / OpenVPN driver) ----

        void OnLinkLost(string reason)
        {
            bool goDisconnected = false;
            bool startSupervisor = false;
            lock (_stateLock)
            {
                if (!_running) return;
                StopTimer();
                _running = false;

                if (_userTeardown || !_opts.Enabled)
                    goDisconnected = true;
                else if (!_supervisorActive)
                {
                    _supervisorActive = true;
                    startSupervisor = true;
                }
            }

            if (goDisconnected) { SetState(OpenConnectConnectionState.Disconnected); return; }
            if (startSupervisor)
            {
                SetState(OpenConnectConnectionState.Reconnecting);
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
                try { await EstablishAsync(cancellationToken).ConfigureAwait(false); established = true; }
                catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested) { break; }
                catch { /* attempt failed — back off and retry */ }

                if (established)
                {
                    bool healthy;
                    lock (_stateLock)
                    {
                        healthy = _running;
                        if (healthy) _supervisorActive = false;
                    }
                    if (healthy) { RaiseReconnected(); return; }

                    SetState(OpenConnectConnectionState.Reconnecting);
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
            if (!_userTeardown) SetState(OpenConnectConnectionState.Disconnected);
        }

        void RaiseReconnected()
        {
            IPAddress newAddress = _assignedAddress ?? IPAddress.Any;
            bool changed = _lastAssignedAddress != null && !newAddress.Equals(_lastAssignedAddress);
            _lastAssignedAddress = newAddress;
            Reconnected?.Invoke(new OpenConnectReconnectInfo(newAddress, changed));
        }

        // ---- teardown ----

        /// <summary>
        /// Tears the tunnel down permanently (no reconnect): sends a best-effort CSTP DISCONNECT, cancels any reconnect
        /// in flight, then cancels the receive loop and disposes the stream. Best-effort and time-boxed; safe to call
        /// more than once.
        /// </summary>
        public async Task DisconnectAsync(CancellationToken cancellationToken = default)
        {
            _userTeardown = true;
            CstpChannel? channel = _channel;
            CstpDatagramChannel? dtlsChannel = _dtlsChannel;
            lock (_stateLock) { StopTimer(); _running = false; }
            // Best-effort DISCONNECT on both paths (the active data plane and the TLS control/fallback channel).
            if (dtlsChannel != null) { try { await dtlsChannel.SendDisconnectAsync(cancellationToken).ConfigureAwait(false); } catch { } }
            if (channel != null) { try { await channel.SendDisconnectAsync(cancellationToken).ConfigureAwait(false); } catch { } }

            _lifetimeCts.Cancel();
            Task? supervisor = _supervisor;
            if (supervisor != null) { try { await supervisor.ConfigureAwait(false); } catch { } }

            await CleanupAttemptResourcesAsync().ConfigureAwait(false);
            SetState(OpenConnectConnectionState.Disconnected);
        }

        async Task CleanupAttemptResourcesAsync()
        {
            StopTimer();
            _running = false;
            _dtlsActive = false;

            CstpChannel? channel = _channel;
            _channel = null;
            if (channel != null)
            {
                channel.DpdRequestReceived -= OnDpdRequest;
                channel.PeerClosed -= OnPeerClosed;
                channel.PacketReceived -= OnPacketReceived;
                channel.PacketSent -= OnPacketSent;
            }

            CstpDatagramChannel? dtlsChannel = _dtlsChannel;
            _dtlsChannel = null;
            if (dtlsChannel != null)
            {
                dtlsChannel.DpdRequestReceived -= OnDpdRequest;
                dtlsChannel.PeerClosed -= OnPeerClosed;
                dtlsChannel.PacketReceived -= OnPacketReceived;
                dtlsChannel.PacketSent -= OnPacketSent;
            }

            CancellationTokenSource? loop = _loopCts;
            _loopCts = null;
            try { loop?.Cancel(); } catch { }

            Task? receive = _receiveTask;
            _receiveTask = null;
            if (receive != null) { try { await receive.ConfigureAwait(false); } catch { } }

            Task? dtlsReceive = _dtlsReceiveTask;
            _dtlsReceiveTask = null;
            if (dtlsReceive != null) { try { await dtlsReceive.ConfigureAwait(false); } catch { } }
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

        void StopTimer()
        {
            _timer?.Dispose();
            _timer = null;
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

        void SetState(OpenConnectConnectionState state)
        {
            if (_state == state) return;
            _state = state;
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
