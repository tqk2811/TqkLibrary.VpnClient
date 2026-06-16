using System.Net;
using System.Security.Cryptography;
using TqkLibrary.VpnClient.Abstractions.Channels;
using TqkLibrary.VpnClient.Abstractions.Channels.Interfaces;
using TqkLibrary.VpnClient.Abstractions.Drivers;
using TqkLibrary.VpnClient.Abstractions.Drivers.Models;
using TqkLibrary.VpnClient.Abstractions.Net;
using TqkLibrary.VpnClient.Abstractions.Transport.Interfaces;
using TqkLibrary.VpnClient.Drivers.WireGuard.Enums;
using TqkLibrary.VpnClient.Drivers.WireGuard.Models;
using TqkLibrary.VpnClient.Drivers.WireGuard.Transport;
using TqkLibrary.VpnClient.WireGuard;
using TqkLibrary.VpnClient.WireGuard.Config;
using TqkLibrary.VpnClient.WireGuard.DataChannel;
using TqkLibrary.VpnClient.WireGuard.Enums;
using TqkLibrary.VpnClient.WireGuard.Handshake;
using TqkLibrary.VpnClient.WireGuard.Handshake.Models;
using TqkLibrary.VpnClient.WireGuard.Transport;

namespace TqkLibrary.VpnClient.Drivers.WireGuard
{
    /// <summary>
    /// A complete WireGuard client over a single UDP transport. It runs the <c>Noise_IKpsk2</c> handshake as the
    /// <b>initiator</b> (type-1 initiation + mac1 → type-2 response → transport keys), binds the resulting
    /// <see cref="WireGuardTransport"/> to a <see cref="WireGuardChannel"/> exposed through a stable
    /// <see cref="SwappablePacketChannel"/>, and then pumps a <see cref="WireGuardPeerState"/> timer loop for
    /// keepalives and a make-before-break rekey (a fresh handshake on a new session index, the channel swapped once it
    /// completes). Inbound datagrams are demuxed by message type: type-2 completes a pending handshake, type-3 feeds
    /// the cookie machinery, type-4 transport data goes to the matching session's channel. A dead session (a handshake
    /// that could not complete within <c>REKEY_ATTEMPT_TIME</c>, or a transport fault) triggers the supervisor /
    /// auto-reconnect, mirroring the OpenVPN / IKEv2 drivers. Not a server — the responder role lives only in tests.
    /// </summary>
    public sealed class WireGuardConnection : IDisposable, IAsyncDisposable
    {
        static readonly TimeSpan TimerTick = TimeSpan.FromMilliseconds(250);

        readonly string _host;
        readonly int _port;
        readonly WireGuardConfig _config;
        readonly IWireGuardTransportFactory _transportFactory;
        readonly WireGuardReconnectOptions _opts;
        readonly AddressFamilyPreference _addressFamilyPreference;
        readonly IHostResolver _hostResolver;
        readonly WireGuardTimers _timers;
        readonly Func<long> _clock;

        readonly SwappablePacketChannel _facade = new();
        readonly CancellationTokenSource _lifetimeCts = new();
        readonly Random _random = new();
        readonly object _stateLock = new();
        readonly TunnelConfig _tunnelConfig;

        IDatagramTransport? _transport;
        CancellationTokenSource? _loopCts;
        Task? _receiveTask;
        System.Threading.Timer? _timer;

        WireGuardPeerState? _peerState;
        Session? _active;        // the live session feeding the facade
        Session? _pending;       // a make-before-break rekey handshake in flight (no transport yet)

        volatile bool _running;
        volatile bool _userTeardown;
        bool _supervisorActive;  // guarded by _stateLock
        Task? _supervisor;
        WireGuardConnectionState _state = WireGuardConnectionState.Disconnected;

        /// <summary>
        /// Creates a connection. <paramref name="config"/> is the static point-to-point profile; <paramref name="transportFactory"/>
        /// opens the UDP socket (an in-process factory drives it offline). <paramref name="timers"/> overrides the
        /// whitepaper timer thresholds (mainly for tests); <paramref name="clock"/> supplies the millisecond clock
        /// (default: the system tick clock) — tests inject a deterministic one.
        /// </summary>
        public WireGuardConnection(string host, int port, WireGuardConfig config, IWireGuardTransportFactory transportFactory,
            WireGuardReconnectOptions? reconnectOptions = null,
            AddressFamilyPreference addressFamilyPreference = AddressFamilyPreference.Auto,
            IHostResolver? hostResolver = null,
            WireGuardTimers? timers = null,
            Func<long>? clock = null)
        {
            _host = host ?? throw new ArgumentNullException(nameof(host));
            _port = port;
            _config = config ?? throw new ArgumentNullException(nameof(config));
            _transportFactory = transportFactory ?? throw new ArgumentNullException(nameof(transportFactory));
            _opts = reconnectOptions ?? new WireGuardReconnectOptions();
            _addressFamilyPreference = addressFamilyPreference;
            _hostResolver = hostResolver ?? DnsHostResolver.Default;
            _timers = timers ?? new WireGuardTimers(config.PersistentKeepaliveSeconds);
            _clock = clock ?? DefaultClock;
            _tunnelConfig = config.ToTunnelConfig();
        }

        /// <summary>The stable L3 packet channel (valid after a successful connect; survives rekey/reconnect).</summary>
        public IPacketChannel PacketChannel => _facade;

        /// <summary>The static tunnel configuration from the config (address, DNS, allowed-ips as routes, MTU).</summary>
        public TunnelConfig Config => _tunnelConfig;

        /// <summary>The local tunnel IPv4 address, if configured.</summary>
        public IPAddress? AssignedAddress => _config.Address;

        /// <summary>Raised whenever the connection state changes (handshake progress, drop, reconnect).</summary>
        public event Action<WireGuardConnectionState>? StateChanged;

        /// <summary>Raised after a successful auto-reconnect.</summary>
        public event Action<WireGuardReconnectInfo>? Reconnected;

        /// <summary>The current lifecycle state.</summary>
        public WireGuardConnectionState State => _state;

        /// <summary>Runs the initial handshake and returns once the tunnel is carrying traffic.</summary>
        public async Task ConnectAsync(CancellationToken cancellationToken = default)
        {
            SetState(WireGuardConnectionState.Connecting);
            await EstablishAsync(cancellationToken).ConfigureAwait(false);
        }

        // ---- one full tunnel attempt (reused by the first connect and every reconnect) ----

        async Task EstablishAsync(CancellationToken cancellationToken)
        {
            await CleanupAttemptResourcesAsync().ConfigureAwait(false);

            IPAddress serverIp = await _hostResolver.ResolveAsync(_host, _addressFamilyPreference, cancellationToken).ConfigureAwait(false);
            _loopCts = CancellationTokenSource.CreateLinkedTokenSource(_lifetimeCts.Token, cancellationToken);
            CancellationToken loopToken = _loopCts.Token;

            WireGuardTransportHandle handle = await _transportFactory
                .ConnectAsync(new IPEndPoint(serverIp, _port), cancellationToken).ConfigureAwait(false);
            _transport = handle.Datagram;
            handle.SetReceiver(OnInboundDatagram);

            // Start the receive pump (real UDP socket) once the handler is wired; loopback transports self-pump.
            if (handle.ReceivePump != null)
                _receiveTask = Task.Run(() => handle.ReceivePump(loopToken));

            var peerState = new WireGuardPeerState(_timers);
            _peerState = peerState;

            // --- run the initiator handshake and wait for the response (type-2) ---
            Session session = StartHandshake();
            _active = session;
            peerState.OnHandshakeInitiated(_clock());

            // Start the timer loop *before* awaiting completion so an unanswered initiation (e.g. one the responder
            // met with a cookie-reply) is resent with a valid mac2 by the ResendHandshake path while we wait.
            StartTimerLoop();

            bool completed = await session.WaitForHandshakeAsync(_timers.RekeyAttemptTimeMs, cancellationToken).ConfigureAwait(false);
            if (!completed)
            {
                StopTimerLoop();
                throw new VpnConnectionException("WireGuard handshake timed out: no type-2 response from the peer.");
            }

            BindSession(session, peerState);
            SetState(WireGuardConnectionState.Connected);
        }

        // ---- handshake start: allocate a local index, send the initiation with mac1 ----

        Session StartHandshake()
        {
            var handshake = new WireGuardHandshake(
                BuildLocalStatic(), _config.PeerPublicKey, _config.PresharedKey);
            uint localIndex = NextIndex();
            var session = new Session(handshake, localIndex);

            WireGuardInitiationMessage init = handshake.CreateInitiation(localIndex);
            byte[] wire = new WireGuardMessageCodec().EncodeInitiation(init);
            handshake.StampOutgoingMacs(wire);
            _ = SendAsync(wire); // fire-and-forget; a missed initiation is resent by the timer loop
            return session;
        }

        WireGuardKeyPair BuildLocalStatic()
        {
            byte[] priv = _config.PrivateKey ?? throw new VpnConnectionException("WireGuard config has no PrivateKey.");
            var dh = new TqkLibrary.VpnClient.Crypto.Noise.Curve25519DhGroup();
            return new WireGuardKeyPair { PrivateKey = (byte[])priv.Clone(), PublicKey = dh.DerivePublicValue(priv) };
        }

        // Bind a completed handshake's transport to a fresh channel and install it behind the facade.
        void BindSession(Session session, WireGuardPeerState peerState)
        {
            WireGuardTransportKeys keys = session.Handshake.DeriveTransportKeys();
            var transport = new WireGuardTransport(keys, session.PeerIndex, session.LocalIndex);
            long now = _clock();
            var channel = new WireGuardChannel(transport, SendChannelAsync, _config.Mtu,
                onPacketSealed: () => peerState.OnDataSent(_clock()),
                onPacketReceived: () => peerState.OnDataReceived(_clock()));
            session.Channel = channel;
            peerState.OnHandshakeCompleted(now);
            _facade.SetInner(channel);
        }

        ValueTask SendChannelAsync(ReadOnlyMemory<byte> wire, CancellationToken cancellationToken)
        {
            IDatagramTransport? transport = _transport;
            return transport?.SendAsync(wire, cancellationToken) ?? default;
        }

        Task SendAsync(ReadOnlyMemory<byte> wire)
        {
            IDatagramTransport? transport = _transport;
            return transport is null ? Task.CompletedTask : transport.SendAsync(wire).AsTask();
        }

        // ---- inbound demux: route by message type (response / cookie-reply / transport-data) ----

        void OnInboundDatagram(ReadOnlyMemory<byte> datagram)
        {
            ReadOnlySpan<byte> span = datagram.Span;
            if (span.Length < 1) return;
            byte type = span[0];

            if (type == WireGuardConstants.MessageTypeResponse) { OnResponse(span); return; }
            if (type == WireGuardConstants.MessageTypeCookieReply) { OnCookieReply(span); return; }
            if (type == WireGuardConstants.MessageTypeTransportData) { OnTransportData(span); return; }
            // type-1 initiation is the server's job (we are the initiator); drop anything else.
        }

        void OnResponse(ReadOnlySpan<byte> span)
        {
            var codec = new WireGuardMessageCodec();
            if (!codec.TryDecodeResponse(span, out WireGuardResponseMessage response)) return;

            // The response addresses the session whose local (sender) index it echoes in ReceiverIndex.
            Session? target = MatchPendingHandshake(response.ReceiverIndex);
            if (target is null || target.HandshakeDone) return;
            if (!target.Handshake.VerifyIncomingMac1(span)) return; // forged/foreign — drop before the DH work
            if (!target.Handshake.ConsumeResponse(response)) return; // bad tag / PSK mismatch

            target.PeerIndex = response.SenderIndex;
            target.CompleteHandshake();

            // A rekey handshake (pending while the old session keeps running): swap the channel make-before-break.
            WireGuardPeerState? peerState = _peerState;
            if (_pending == target && peerState != null)
            {
                _active = target;
                _pending = null;
                BindSession(target, peerState);
            }
        }

        Session? MatchPendingHandshake(uint localIndex)
        {
            if (_pending is { } p && p.LocalIndex == localIndex && !p.HandshakeDone) return p;
            if (_active is { } a && a.LocalIndex == localIndex && !a.HandshakeDone) return a;
            return null;
        }

        void OnCookieReply(ReadOnlySpan<byte> span)
        {
            var codec = new WireGuardMessageCodec();
            if (!codec.TryDecodeCookieReply(span, out WireGuardCookieReplyMessage reply)) return;
            Session? target = MatchPendingHandshake(reply.ReceiverIndex);
            target?.Handshake.ConsumeCookieReply(reply); // caches the cookie → mac2 on the next (resent) initiation
        }

        void OnTransportData(ReadOnlySpan<byte> span)
        {
            // Deliver to whichever live session owns the receiver index in the header.
            Session? active = _active;
            if (active?.Channel != null && active.HandshakeDone && active.Channel.Deliver(span)) return;
            // A late packet for a just-replaced previous session can be ignored (no previous kept here).
        }

        // ---- timer loop: keepalive + make-before-break rekey, driven by WireGuardPeerState ----

        void StartTimerLoop()
        {
            _running = true;
            _timer = new System.Threading.Timer(_ => _ = TimerTickAsync(), null, TimerTick, TimerTick);
        }

        async Task TimerTickAsync()
        {
            if (!_running) return;
            WireGuardPeerState? peerState = _peerState;
            Session? active = _active;
            if (peerState is null || active is null) return;

            long now = _clock();
            WireGuardSessionAction action = peerState.Evaluate(now);
            switch (action)
            {
                case WireGuardSessionAction.SendKeepalive:
                    try { if (active.Channel != null) await active.Channel.SendKeepaliveAsync().ConfigureAwait(false); }
                    catch { /* a missed keepalive is harmless; the peer's own timer covers liveness */ }
                    break;

                case WireGuardSessionAction.InitiateHandshake:
                    StartRekey(peerState, now);
                    break;

                case WireGuardSessionAction.ResendHandshake:
                    ResendHandshake(peerState, now);
                    break;

                case WireGuardSessionAction.AbandonHandshake:
                case WireGuardSessionAction.SessionDead:
                    OnLinkLost("WireGuard session dead: handshake could not be (re)established within REKEY_ATTEMPT_TIME.");
                    break;
            }
        }

        // Begin a make-before-break rekey: a new handshake on a new index runs while the old session keeps carrying data.
        void StartRekey(WireGuardPeerState peerState, long now)
        {
            if (_pending != null) return; // already rekeying
            Session rekey = StartHandshake();
            _pending = rekey;
            peerState.OnHandshakeInitiated(now);
        }

        void ResendHandshake(WireGuardPeerState peerState, long now)
        {
            Session? handshaking = _pending ?? (_active is { HandshakeDone: false } a ? a : null);
            if (handshaking is null) return;
            WireGuardInitiationMessage init = handshaking.Handshake.CreateInitiation(handshaking.LocalIndex);
            byte[] wire = new WireGuardMessageCodec().EncodeInitiation(init);
            handshaking.Handshake.StampOutgoingMacs(wire); // includes mac2 if a cookie-reply was consumed
            _ = SendAsync(wire);
            peerState.OnHandshakeInitiated(now);
        }

        // ---- link-loss handling + auto-reconnect supervisor (mirrors the OpenVPN / IKEv2 driver) ----

        void OnLinkLost(string reason)
        {
            bool goDisconnected = false;
            bool startSupervisor = false;
            lock (_stateLock)
            {
                if (!_running) return;
                StopTimerLoop();

                if (_userTeardown || !_opts.Enabled)
                    goDisconnected = true;
                else if (!_supervisorActive)
                {
                    _supervisorActive = true;
                    startSupervisor = true;
                }
            }

            if (goDisconnected) { SetState(WireGuardConnectionState.Disconnected); return; }
            if (startSupervisor)
            {
                SetState(WireGuardConnectionState.Reconnecting);
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
                    if (healthy) { Reconnected?.Invoke(new WireGuardReconnectInfo()); return; }

                    SetState(WireGuardConnectionState.Reconnecting);
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
            if (!_userTeardown) SetState(WireGuardConnectionState.Disconnected);
        }

        // ---- teardown ----

        /// <summary>
        /// Tears the tunnel down permanently (no reconnect): cancels any reconnect in flight, then cancels the receive
        /// loop and disposes the transport. Best-effort and time-boxed; safe to call more than once.
        /// </summary>
        public async Task DisconnectAsync(CancellationToken cancellationToken = default)
        {
            _userTeardown = true;
            lock (_stateLock) StopTimerLoop();

            _lifetimeCts.Cancel();
            Task? supervisor = _supervisor;
            if (supervisor != null) { try { await supervisor.ConfigureAwait(false); } catch { } }

            await CleanupAttemptResourcesAsync().ConfigureAwait(false);
            SetState(WireGuardConnectionState.Disconnected);
        }

        async Task CleanupAttemptResourcesAsync()
        {
            StopTimerLoop();

            CancellationTokenSource? loop = _loopCts;
            _loopCts = null;
            try { loop?.Cancel(); } catch { }

            Task? receive = _receiveTask;
            _receiveTask = null;
            if (receive != null) { try { await receive.ConfigureAwait(false); } catch { } }
            loop?.Dispose();

            IDatagramTransport? transport = _transport;
            _transport = null;
            if (transport != null) { try { await transport.DisposeAsync().ConfigureAwait(false); } catch { } }

            _active = null;
            _pending = null;
            _peerState = null;
        }

        void StopTimerLoop()
        {
            _running = false;
            _timer?.Dispose();
            _timer = null;
        }

        // ---- helpers ----

        static uint NextIndex()
        {
            byte[] b = new byte[4];
#if NET6_0_OR_GREATER
            RandomNumberGenerator.Fill(b);
#else
            using (var rng = RandomNumberGenerator.Create()) rng.GetBytes(b);
#endif
            return BitConverter.ToUInt32(b, 0);
        }

        TimeSpan WithJitter(TimeSpan delay)
        {
            double fraction = _opts.JitterFraction;
            if (fraction <= 0) return delay;
            double r;
            lock (_random) r = _random.NextDouble();
            double jitter = delay.TotalMilliseconds * fraction * (r * 2 - 1);
            return TimeSpan.FromMilliseconds(Math.Max(0, delay.TotalMilliseconds + jitter));
        }

        void SetState(WireGuardConnectionState state)
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

        /// <summary>One handshake/transport generation: the Noise state machine, the two session indices, and (once the
        /// handshake completes) the live data channel. A rekey produces a second instance that replaces the first.</summary>
        sealed class Session
        {
            readonly TaskCompletionSource<bool> _handshakeDone = new(TaskCreationOptions.RunContinuationsAsynchronously);

            public Session(WireGuardHandshake handshake, uint localIndex)
            {
                Handshake = handshake;
                LocalIndex = localIndex;
            }

            public WireGuardHandshake Handshake { get; }
            public uint LocalIndex { get; }
            public uint PeerIndex { get; set; }
            public WireGuardChannel? Channel { get; set; }
            public bool HandshakeDone { get; private set; }

            public void CompleteHandshake()
            {
                HandshakeDone = true;
                _handshakeDone.TrySetResult(true);
            }

            public async Task<bool> WaitForHandshakeAsync(long timeoutMs, CancellationToken cancellationToken)
            {
                using var timeout = new CancellationTokenSource(timeoutMs > 0 ? (int)Math.Min(timeoutMs, int.MaxValue) : -1);
                using var linked = CancellationTokenSource.CreateLinkedTokenSource(timeout.Token, cancellationToken);
                using (linked.Token.Register(() => _handshakeDone.TrySetResult(false)))
                    return await _handshakeDone.Task.ConfigureAwait(false);
            }
        }
    }
}
