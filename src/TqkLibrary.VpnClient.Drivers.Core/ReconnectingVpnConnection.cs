using System;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;
using TqkLibrary.VpnClient.Abstractions.Channels;
using TqkLibrary.VpnClient.Abstractions.Channels.Interfaces;
using TqkLibrary.VpnClient.Abstractions.Diagnostics.Extensions;
using TqkLibrary.VpnClient.Drivers.Core.Enums;
using TqkLibrary.VpnClient.Drivers.Core.Models;

namespace TqkLibrary.VpnClient.Drivers.Core
{
    /// <summary>
    /// The shared auto-reconnect supervisor every protocol driver was duplicating (roadmap F.6): it owns the stable
    /// <see cref="SwappablePacketChannel"/> facade, the lifetime cancellation, the <c>_running</c> / teardown guards,
    /// the link-loss → supervisor → reconnect-loop machinery (with capped exponential backoff and ±jitter), the
    /// <c>StateChanged</c> event with structured logging, and the monotonic millisecond clock. A driver subclass keeps
    /// only its protocol logic: <see cref="EstablishAsync"/> (one full tunnel attempt — handshake, bind the data plane
    /// behind <see cref="Facade"/>, start timers/receive loops) and <see cref="CleanupAttemptResourcesAsync"/> (undo it).
    /// The lifecycle state is the shared <see cref="VpnConnectionState"/> enum. The base never invents behaviour the
    /// originals did not have — it is the same loop, factored once.
    /// </summary>
    public abstract class ReconnectingVpnConnection
    {
        readonly SwappablePacketChannel _facade = new();
        readonly CancellationTokenSource _lifetimeCts = new();
        readonly Random _random = new();
        readonly object _stateLock = new();

        volatile bool _running;
        volatile bool _userTeardown;
        bool _supervisorActive;   // guarded by _stateLock
        Task? _supervisor;
        VpnConnectionState _state;

        readonly ILogger _logger;
        readonly string _driverName;
        readonly VpnReconnectOptions _options;
        readonly Func<long> _clock;

        /// <summary>
        /// Initialises the shared state. <paramref name="driverName"/> tags every structured log line;
        /// <paramref name="options"/> is the reconnect/backoff policy (a driver's named subclass of
        /// <see cref="VpnReconnectOptions"/>); <paramref name="clock"/> supplies the millisecond clock (default: the
        /// monotonic system tick clock) — tests inject a deterministic one; <paramref name="loggerFactory"/> receives the
        /// cross-cutting traces (null logs to <see cref="NullLogger"/>, a no-op). The initial state is
        /// <see cref="VpnConnectionState.Disconnected"/>.
        /// </summary>
        protected ReconnectingVpnConnection(string driverName, VpnReconnectOptions options,
            Func<long>? clock = null, ILoggerFactory? loggerFactory = null)
        {
            _driverName = driverName ?? throw new ArgumentNullException(nameof(driverName));
            _options = options ?? throw new ArgumentNullException(nameof(options));
            _clock = clock ?? DefaultClock;
            _logger = (loggerFactory ?? NullLoggerFactory.Instance).CreateLogger("TqkLibrary.VpnClient.Drivers." + driverName);
            _state = VpnConnectionState.Disconnected;
        }

        // ---- shared state exposed to the subclass ----

        /// <summary>The stable L3 packet channel (valid after a successful connect; survives rekey/reconnect).</summary>
        public IPacketChannel PacketChannel => _facade;

        /// <summary>The current lifecycle state.</summary>
        public VpnConnectionState State => _state;

        /// <summary>Raised whenever the connection state changes (handshake progress, drop, reconnect).</summary>
        public event Action<VpnConnectionState>? StateChanged;

        /// <summary>The stable facade the subclass binds its live channel behind (make-before-break safe).</summary>
        protected SwappablePacketChannel Facade => _facade;

        /// <summary>The structured logger (driver-tagged); see <see cref="VpnLogExtensions"/> for the helpers.</summary>
        protected ILogger Logger => _logger;

        /// <summary>The driver name tag used in the structured log lines.</summary>
        protected string DriverName => _driverName;

        /// <summary>The reconnect/backoff policy (the driver's <see cref="VpnReconnectOptions"/> subclass).</summary>
        protected VpnReconnectOptions Options => _options;

        /// <summary>Cancelled when the connection is torn down for good; link the per-attempt loop token to this.</summary>
        protected CancellationToken LifetimeToken => _lifetimeCts.Token;

        /// <summary>True between a successful attempt and the next link-loss/teardown (the "tunnel is up" flag).</summary>
        protected bool IsRunning => _running;

        /// <summary>True once <see cref="DisconnectCoreAsync"/> has begun (no more reconnects will be attempted).</summary>
        protected bool IsUserTeardown => _userTeardown;

        /// <summary>The monotonic millisecond clock (system tick by default, or the injected one).</summary>
        protected long Now() => _clock();

        // ---- protocol-specific hooks the subclass implements ----

        /// <summary>
        /// Runs one full tunnel attempt: resolve/connect the transport, run the handshake, bind the live channel behind
        /// <see cref="Facade"/> via <see cref="SwappablePacketChannel.SetInner"/>, start the timer/receive loops, then
        /// call <see cref="MarkConnected"/>. Reused by the first connect and by every reconnect. Throws on failure (the
        /// supervisor backs off and retries). Should begin by calling <see cref="CleanupAttemptResourcesAsync"/> to drop
        /// any half-open prior attempt (matching the original drivers).
        /// </summary>
        protected abstract Task EstablishAsync(CancellationToken cancellationToken);

        /// <summary>Undoes everything <see cref="EstablishAsync"/> set up (timers, receive loops, transport, channels).
        /// Best-effort and idempotent; called before each attempt and on teardown.</summary>
        protected abstract Task CleanupAttemptResourcesAsync();

        /// <summary>Stops the per-attempt timer/receive loop (disposed under the state lock on link-loss/teardown). The
        /// base sets <see cref="IsRunning"/> false around this; the subclass just disposes its timer.</summary>
        protected abstract void StopAttemptLoop();

        /// <summary>Called (off the state lock) after a successful auto-reconnect so the subclass can raise its own
        /// <c>Reconnected</c> event. The default does nothing.</summary>
        protected virtual void OnReconnected() { }

        // ---- lifecycle the subclass calls ----

        /// <summary>
        /// Marks the attempt "running" without changing the public state. Set this once the data plane is bound and the
        /// receive loop is about to start, so a drop detected during the rest of the establish (peer close, fault) is
        /// honoured by <see cref="OnLinkLost"/>. <see cref="MarkConnected"/> finishes the transition to
        /// <see cref="VpnConnectionState.Connected"/>. (A driver whose establish has no such window can just call MarkConnected.)
        /// </summary>
        protected void MarkRunning() => _running = true;

        /// <summary>Marks the tunnel up: ensures <see cref="IsRunning"/> is true and moves the state to
        /// <see cref="VpnConnectionState.Connected"/>. Call at the end of a successful <see cref="EstablishAsync"/>.</summary>
        protected void MarkConnected()
        {
            _running = true;
            SetState(VpnConnectionState.Connected);
        }

        /// <summary>Runs the initial connect: moves to <see cref="VpnConnectionState.Connecting"/> then the first
        /// <see cref="EstablishAsync"/>. Throws if the first attempt fails (reconnect only arms after a success).</summary>
        protected async Task ConnectCoreAsync(CancellationToken cancellationToken)
        {
            SetState(VpnConnectionState.Connecting);
            await EstablishAsync(cancellationToken).ConfigureAwait(false);
        }

        /// <summary>
        /// Declares the link dead. Under the state lock: a no-op if not running; otherwise it stops the attempt loop and
        /// either goes <see cref="VpnConnectionState.Disconnected"/> (user teardown or reconnect disabled) or arms the reconnect
        /// supervisor exactly once. Safe to call from a receive loop, a timer, or a channel fault.
        /// </summary>
        protected void OnLinkLost(string reason)
        {
            bool goDisconnected = false;
            bool startSupervisor = false;
            lock (_stateLock)
            {
                if (!_running) return;
                _logger.LogLinkLost(_driverName, reason);
                StopAttemptLoop();
                _running = false;

                if (_userTeardown || !_options.Enabled)
                    goDisconnected = true;
                else if (!_supervisorActive)
                {
                    _supervisorActive = true;
                    startSupervisor = true;
                }
            }

            if (goDisconnected) { SetState(VpnConnectionState.Disconnected); return; }
            if (startSupervisor)
            {
                SetState(VpnConnectionState.Reconnecting);
                _supervisor = Task.Run(() => ReconnectLoopAsync(_lifetimeCts.Token));
            }
        }

        async Task ReconnectLoopAsync(CancellationToken cancellationToken)
        {
            TimeSpan delay = _options.InitialBackoff;
            int failures = 0;
            while (!_userTeardown && !cancellationToken.IsCancellationRequested)
            {
                bool established = false;
                _logger.LogReconnectAttempt(_driverName, failures + 1);
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
                    if (healthy) { _logger.LogReconnected(_driverName); OnReconnected(); return; }

                    SetState(VpnConnectionState.Reconnecting);
                    delay = _options.InitialBackoff;
                    failures = 0;
                    continue;
                }

                if (_options.MaxAttempts != 0 && ++failures >= _options.MaxAttempts) break;
                try { await Task.Delay(WithJitter(delay), cancellationToken).ConfigureAwait(false); }
                catch (OperationCanceledException) { break; }
                delay = _options.NextBackoff(delay);
            }

            lock (_stateLock) { _supervisorActive = false; }
            if (!_userTeardown) SetState(VpnConnectionState.Disconnected);
        }

        // ---- teardown ----

        /// <summary>
        /// Tears the tunnel down permanently (no reconnect): flips <see cref="IsUserTeardown"/>, stops the attempt loop,
        /// cancels any reconnect in flight, awaits the supervisor, then runs the subclass cleanup and goes
        /// <see cref="VpnConnectionState.Disconnected"/>. The subclass overrides <see cref="DisconnectAsync"/> to send a best-effort
        /// protocol close first, then calls this. Best-effort and time-boxed; safe to call more than once.
        /// </summary>
        protected async Task DisconnectCoreAsync()
        {
            _userTeardown = true;
            lock (_stateLock) { StopAttemptLoop(); _running = false; }

            _lifetimeCts.Cancel();
            Task? supervisor = _supervisor;
            if (supervisor != null) { try { await supervisor.ConfigureAwait(false); } catch { } }

            await CleanupAttemptResourcesAsync().ConfigureAwait(false);
            SetState(VpnConnectionState.Disconnected);
        }

        /// <summary>Disposes the lifetime cancellation and the facade. Call from the subclass's DisposeAsync after
        /// <see cref="DisconnectAsync"/>.</summary>
        protected async ValueTask DisposeCoreAsync()
        {
            _lifetimeCts.Dispose();
            await _facade.DisposeAsync().ConfigureAwait(false);
        }

        /// <summary>Tears the tunnel down permanently. The default just calls <see cref="DisconnectCoreAsync"/>; a
        /// subclass overrides it to send a best-effort protocol close first.</summary>
        public virtual Task DisconnectAsync(CancellationToken cancellationToken = default) => DisconnectCoreAsync();

        // ---- helpers ----

        /// <summary>Applies ±<see cref="VpnReconnectOptions.JitterFraction"/> jitter to a backoff delay (thread-safe RNG).</summary>
        protected TimeSpan WithJitter(TimeSpan delay)
        {
            double fraction = _options.JitterFraction;
            if (fraction <= 0) return delay;
            double r;
            lock (_random) r = _random.NextDouble();
            double jitter = delay.TotalMilliseconds * fraction * (r * 2 - 1);
            return TimeSpan.FromMilliseconds(Math.Max(0, delay.TotalMilliseconds + jitter));
        }

        /// <summary>Fills a buffer with cryptographically-strong random bytes (used for nonces/secrets) under the shared RNG.</summary>
        protected void NextRandomBytes(byte[] buffer)
        {
            lock (_random) _random.NextBytes(buffer);
        }

        /// <summary>Transitions state, logging the change and raising <see cref="StateChanged"/> (no-op if unchanged).</summary>
        protected void SetState(VpnConnectionState state)
        {
            if (_state.Equals(state)) return;
            _state = state;
            _logger.LogStateChanged(_driverName, state.ToString()!);
            StateChanged?.Invoke(state);
        }

#if NET5_0_OR_GREATER
        static long DefaultClock() => Environment.TickCount64;
#else
        static readonly System.Diagnostics.Stopwatch _stopwatch = System.Diagnostics.Stopwatch.StartNew();
        static long DefaultClock() => _stopwatch.ElapsedMilliseconds;
#endif
    }
}
