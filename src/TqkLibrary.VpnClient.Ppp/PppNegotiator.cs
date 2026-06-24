using System.Threading;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;
using TqkLibrary.VpnClient.Abstractions.Diagnostics.Extensions;
using TqkLibrary.VpnClient.Ppp.Enums;
using TqkLibrary.VpnClient.Ppp.Models;

namespace TqkLibrary.VpnClient.Ppp
{
    /// <summary>
    /// Generic PPP option-negotiation state machine shared by LCP and IPCP (RFC 1661 §4, simplified for a
    /// voluntary client). Reaches <see cref="PppNegotiationState.Opened"/> once our request is acked AND we
    /// have acked the peer's request.
    /// <para>
    /// A <b>Restart timer</b> (RFC 1661 §4.6) retransmits the current Configure-Request until the peer answers it:
    /// a single Configure-Request that is lost — or one the peer drops because its own layer is not yet up (e.g.
    /// accel-ppp/SSTP discards an IPCP Configure-Request that arrives before <c>NPMODE_PASS</c>, then sends an LCP
    /// Protocol-Reject) — would otherwise stall the whole link until the outer connect timeout. Retransmission makes
    /// the negotiation self-healing: the peer answers a later copy once it is ready. The timer stops the moment our
    /// request is acknowledged (or the layer opens); the peer drives its own side with its own Restart timer.
    /// </para>
    /// </summary>
    public abstract class PppNegotiator : IDisposable
    {
        /// <summary>Default delay between Configure-Request retransmissions (RFC 1661 default Restart timer).</summary>
        public static readonly TimeSpan DefaultRestartInterval = TimeSpan.FromSeconds(3);

        /// <summary>Default number of Configure-Request transmissions before giving up (RFC 1661 Max-Configure).</summary>
        public const int DefaultMaxRequests = 10;

        readonly Action<byte[]> _send;
        readonly object _lock = new();
        readonly TimeSpan _restartInterval;
        readonly int _maxRequests;

        /// <summary>The protocol-trace layer name this negotiator stamps on its <see cref="VpnLogExtensions"/> entries
        /// (e.g. <c>ppp.lcp</c>, <c>ppp.ipcp</c>, <c>ppp.ipv6cp</c>).</summary>
        protected string Layer { get; }

        /// <summary>The logger this negotiator traces to (a no-op <see cref="NullLogger"/> when none was supplied).</summary>
        protected ILogger Logger { get; }

        Timer? _restartTimer;
        byte _nextId = 1;
        byte _lastRequestId;
        byte[]? _lastRequest;     // exact bytes of the in-flight Configure-Request (retransmitted verbatim, §4.6)
        int _requestAttempts;     // how many times the current Configure-Request has been transmitted
        bool _localAcked;
        bool _peerAcked;
        bool _disposed;

        /// <summary>
        /// Creates a negotiator that emits control packets through <paramref name="send"/>. The Restart timer resends
        /// the current Configure-Request every <paramref name="restartInterval"/> (default <see cref="DefaultRestartInterval"/>)
        /// until it is acknowledged, at most <paramref name="maxRequests"/> total transmissions
        /// (default <see cref="DefaultMaxRequests"/>; ≤0 ⇒ unbounded).
        /// </summary>
        protected PppNegotiator(Action<byte[]> send, TimeSpan? restartInterval = null, int maxRequests = DefaultMaxRequests,
            string layer = "ppp", ILogger? logger = null)
        {
            _send = send;
            _restartInterval = restartInterval ?? DefaultRestartInterval;
            _maxRequests = maxRequests <= 0 ? int.MaxValue : maxRequests;
            Layer = layer;
            Logger = logger ?? NullLogger.Instance;
        }

        /// <summary>Current negotiation state.</summary>
        public PppNegotiationState State { get; private set; } = PppNegotiationState.Closed;

        /// <summary>Raised once when the negotiator reaches <see cref="PppNegotiationState.Opened"/>.</summary>
        public event Action? Opened;

        /// <summary>Sends the first Configure-Request to begin negotiation and arms the Restart timer.</summary>
        public void Start()
        {
            byte[]? wire;
            lock (_lock)
            {
                if (_disposed) return;
                State = PppNegotiationState.RequestSent;
                wire = BuildRequestLocked();
                ArmRestartTimerLocked();
            }
            Logger.LogProtocolStep(Layer, "Configure-Request sent (negotiation started)");
            if (wire != null) _send(wire);
        }

        /// <summary>Feeds one received control packet (Code/Id/Length + options) into the state machine.</summary>
        public void HandlePacket(ReadOnlySpan<byte> packet)
        {
            PppControlPacket parsed = PppControlCodec.Parse(packet);
            List<PppOption> options = PppControlCodec.ParseOptions(parsed.Data);

            byte[]? toSend = null;
            bool raiseOpened = false;
            lock (_lock)
            {
                if (_disposed) return;
                switch ((PppCode)parsed.Code)
                {
                    case PppCode.ConfigureRequest:
                        toSend = EvaluatePeerRequestLocked(parsed.Identifier, options, out raiseOpened);
                        break;
                    case PppCode.ConfigureAck:
                        if (parsed.Identifier == _lastRequestId)
                        {
                            _localAcked = true;
                            StopRestartTimerLocked();   // our request is acknowledged; stop retransmitting it
                            raiseOpened = CheckOpenedLocked();
                        }
                        break;
                    case PppCode.ConfigureNak:
                        OnNak(options);
                        Logger.LogProtocolStep(Layer, "Configure-Nak received; re-requesting with adjusted options");
                        toSend = BuildRequestLocked();  // resend with adjusted options + restart the timer/counter
                        ArmRestartTimerLocked();
                        break;
                    case PppCode.ConfigureReject:
                        OnReject(options);
                        Logger.LogProtocolStep(Layer, "Configure-Reject received; dropping rejected options and re-requesting");
                        toSend = BuildRequestLocked();
                        ArmRestartTimerLocked();
                        break;
                    default:
                        // Codes outside the Configure-* set (e.g. LCP Echo-Request) — the subclass may answer.
                        toSend = HandleOtherCode(parsed.Code, parsed.Identifier, parsed.Data);
                        break;
                }
            }
            // Emit outside the lock: _send may run inline and the Opened handler may re-enter the engine.
            if (toSend != null) _send(toSend);
            if (raiseOpened) Opened?.Invoke();
        }

        // Builds a fresh Configure-Request, stores it for verbatim retransmission, and resets the attempt counter.
        byte[] BuildRequestLocked()
        {
            _lastRequestId = _nextId++;
            _lastRequest = PppControlCodec.BuildConfigure((byte)PppCode.ConfigureRequest, _lastRequestId, BuildLocalOptions());
            _requestAttempts = 1;
            return _lastRequest;
        }

        // Evaluates the peer's Configure-Request, returns the response wire, and reports whether the link just opened.
        byte[] EvaluatePeerRequestLocked(byte identifier, List<PppOption> peerOptions, out bool raiseOpened)
        {
            raiseOpened = false;
            (byte code, IReadOnlyList<PppOption> responseOptions) = EvaluatePeerRequest(peerOptions);
            byte[] wire = PppControlCodec.BuildConfigure(code, identifier, responseOptions);
            if (code == (byte)PppCode.ConfigureAck)
            {
                _peerAcked = true;
                raiseOpened = CheckOpenedLocked();
            }
            return wire;
        }

        bool CheckOpenedLocked()
        {
            if (_localAcked && _peerAcked && State != PppNegotiationState.Opened)
            {
                State = PppNegotiationState.Opened;
                StopRestartTimerLocked();
                Logger.LogProtocolStep(Layer, "Opened (both sides acked)");
                return true;
            }
            return false;
        }

        void ArmRestartTimerLocked()
        {
            if (_disposed) return;
            if (_restartTimer == null)
                _restartTimer = new Timer(_ => OnRestartTick(), null, _restartInterval, Timeout.InfiniteTimeSpan);
            else
                TryChangeTimer(_restartInterval);
        }

        void StopRestartTimerLocked() => TryChangeTimer(Timeout.InfiniteTimeSpan);

        void TryChangeTimer(TimeSpan due)
        {
            try { _restartTimer?.Change(due, Timeout.InfiniteTimeSpan); }
            catch (ObjectDisposedException) { }
        }

        // Restart timer (RFC 1661 §4.6): resend the in-flight Configure-Request verbatim until it is acked.
        void OnRestartTick()
        {
            byte[]? wire = null;
            lock (_lock)
            {
                if (_disposed || _localAcked || State == PppNegotiationState.Opened || _lastRequest == null) return;
                if (_requestAttempts >= _maxRequests) return; // give up; the outer connect timeout surfaces the failure
                _requestAttempts++;
                wire = _lastRequest;
                TryChangeTimer(_restartInterval);
            }
            // The timer fires on a pool thread; a send against a torn-down channel must not crash the callback.
            try { _send(wire); } catch { }
        }

        /// <summary>The options to request for ourselves (rebuilt on each Configure-Request, after any Nak/Reject).</summary>
        protected abstract IReadOnlyList<PppOption> BuildLocalOptions();

        /// <summary>Decides our response to the peer's Configure-Request: Ack (echo), Nak (suggest), or Reject.</summary>
        protected abstract (byte code, IReadOnlyList<PppOption> options) EvaluatePeerRequest(List<PppOption> peerOptions);

        /// <summary>Applies the peer's Nak hints to our local options before resending.</summary>
        protected virtual void OnNak(List<PppOption> nakOptions) { }

        /// <summary>Drops options the peer rejected before resending.</summary>
        protected virtual void OnReject(List<PppOption> rejectedOptions) { }

        /// <summary>Responds to a received control code outside the Configure-* set (e.g. LCP Echo-Request, RFC 1661 §5.8).
        /// Returns a reply packet to transmit, or null to ignore. Invoked under the negotiator lock.</summary>
        protected virtual byte[]? HandleOtherCode(byte code, byte identifier, byte[] data) => null;

        /// <summary>Stops and releases the Restart timer; safe to call more than once.</summary>
        public void Dispose()
        {
            Timer? timer;
            lock (_lock)
            {
                if (_disposed) return;
                _disposed = true;
                timer = _restartTimer;
                _restartTimer = null;
            }
            timer?.Dispose();
        }
    }
}
