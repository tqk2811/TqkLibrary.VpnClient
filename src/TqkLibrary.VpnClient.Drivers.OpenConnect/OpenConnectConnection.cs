using System.Net;
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
    /// auto-reconnect, mirroring those drivers. <b>TLS-only</b> — the DTLS data path is roadmap V5.c (F.3). Not a
    /// server — the responder role lives only in tests.
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
        CstpDpdState? _dpd;
        CancellationTokenSource? _loopCts;
        Task? _receiveTask;
        System.Threading.Timer? _timer;

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
        /// drives it offline). <paramref name="requestedMtu"/> is advertised in <c>X-CSTP-Base-MTU</c>;
        /// <paramref name="clock"/> supplies the DPD/keep-alive millisecond clock (default: the system tick clock) —
        /// tests inject a deterministic one.
        /// </summary>
        public OpenConnectConnection(string host, int port, IOpenConnectTransportFactory transportFactory,
            string? username = null, string? password = null, string groupSelect = "",
            OpenConnectReconnectOptions? reconnectOptions = null,
            AddressFamilyPreference addressFamilyPreference = AddressFamilyPreference.Auto,
            IHostResolver? hostResolver = null,
            int requestedMtu = 1400,
            Func<long>? clock = null)
        {
            _host = host ?? throw new ArgumentNullException(nameof(host));
            _port = port;
            _transportFactory = transportFactory ?? throw new ArgumentNullException(nameof(transportFactory));
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
            string connectRequest = OpenConnectConnectCodec.BuildConnectRequest(_host, cookie, _requestedMtu);
            OpenConnectHttpResponse connectResponse = await http.ConnectTunnelAsync(connectRequest, cancellationToken).ConfigureAwait(false);
            OpenConnectTunnelInfo tunnelInfo = OpenConnectConnectCodec.ParseConnectResponse(connectResponse.RawHeaderText + "\r\n\r\n");
            if (tunnelInfo.Address is null && tunnelInfo.AddressV6 is null)
                throw new VpnServerRejectedException("OpenConnect CONNECT response carried no tunnel address (no X-CSTP-Address).");

            // --- bind the CSTP data plane behind the stable facade ---
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

            // Start the CSTP receive loop and the DPD/keep-alive timer.
            _dpd = new CstpDpdState(tunnelInfo.Dpd ?? 0, tunnelInfo.Keepalive ?? 0, _clock());
            _running = true;
            _receiveTask = Task.Run(() => channel.RunReceiveLoopAsync(loopToken));
            _timer = new System.Threading.Timer(_ => _ = TimerTickAsync(), null, TimerTick, TimerTick);

            SetState(OpenConnectConnectionState.Connected);
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

        // ---- CSTP event wiring: DPD reply, peer close, liveness ----

        void OnDpdRequest()
        {
            CstpChannel? channel = _channel;
            if (channel != null) _ = SafeSendAsync(channel.SendDpdResponseAsync);
        }

        void OnPeerClosed() => OnLinkLost("OpenConnect gateway closed the CSTP session (DISCONNECT/TERMINATE or stream EOF).");

        void OnPacketReceived() => _dpd?.OnDataReceived(_clock());

        void OnPacketSent() => _dpd?.OnDataSent(_clock());

        // ---- timer loop: DPD probe + dead detection + idle keep-alive (driven by CstpDpdState) ----

        async Task TimerTickAsync()
        {
            if (!_running) return;
            CstpDpdState? dpd = _dpd;
            CstpChannel? channel = _channel;
            if (dpd is null || channel is null) return;

            long now = _clock();
            if (dpd.IsPeerDead(now))
            {
                OnLinkLost("X-CSTP-DPD: no traffic from the OpenConnect gateway within the dead-peer-detection window.");
                return;
            }
            if (dpd.ShouldSendDpd(now))
            {
                dpd.OnDpdSent(now);
                await SafeSendAsync(channel.SendDpdRequestAsync).ConfigureAwait(false);
            }
            else if (dpd.ShouldSendKeepalive(now))
            {
                await SafeSendAsync(channel.SendKeepaliveAsync).ConfigureAwait(false);
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
            lock (_stateLock) { StopTimer(); _running = false; }
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

            CstpChannel? channel = _channel;
            _channel = null;
            if (channel != null)
            {
                channel.DpdRequestReceived -= OnDpdRequest;
                channel.PeerClosed -= OnPeerClosed;
                channel.PacketReceived -= OnPacketReceived;
                channel.PacketSent -= OnPacketSent;
            }

            CancellationTokenSource? loop = _loopCts;
            _loopCts = null;
            try { loop?.Cancel(); } catch { }

            Task? receive = _receiveTask;
            _receiveTask = null;
            if (receive != null) { try { await receive.ConfigureAwait(false); } catch { } }
            loop?.Dispose();

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
