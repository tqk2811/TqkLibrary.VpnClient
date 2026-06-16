using TqkLibrary.VpnClient.WireGuard.Enums;

namespace TqkLibrary.VpnClient.WireGuard
{
    /// <summary>
    /// The per-peer timer state machine from the WireGuard whitepaper (§6.2 "Reinitiation" / reference
    /// <c>timers.c</c>). It records session lifecycle events (handshake started/completed, data sent/received, message
    /// counters) and turns the injected clock plus those facts into one <see cref="WireGuardSessionAction"/> via
    /// <see cref="Evaluate"/> — a deterministic pure function of <c>(now, last_handshake, counters, last_send,
    /// last_recv)</c>, so the driver pumps it from a timer while tests stay offline and reproducible.
    /// <para>
    /// The clock is injected (<c>nowMs</c>, monotonic milliseconds) exactly like <c>OpenVpnKeepalive</c>. Thresholds
    /// come from <see cref="WireGuardTimers"/>. Handshake resend jitter (<c>REKEY_TIMEOUT</c> + random ⅓ s in the
    /// reference) is provided by an injected delegate so it can be made deterministic in tests; the default adds 0.
    /// </para>
    /// <para>
    /// This type holds <b>no</b> keys and does no crypto — it only decides <i>when</i> the driver should hand a fresh
    /// handshake to <see cref="Handshake.WireGuardHandshake"/> or a keepalive to
    /// <see cref="DataChannel.WireGuardTransport"/>. It is not thread-safe; the driver calls it from its single timer/IO loop.
    /// </para>
    /// </summary>
    public sealed class WireGuardPeerState
    {
        readonly WireGuardTimers _timers;
        readonly Func<long> _jitterMs;

        // ---- handshake (re)initiation tracking ----
        bool _handshakeInFlight;     // an initiation has been sent and no response consumed yet
        long _handshakeStartedMs;    // when the *first* initiation of the current attempt was sent (for REKEY_ATTEMPT_TIME)
        long _lastInitiationMs;      // when the most recent initiation was sent (for REKEY_TIMEOUT resends)
        long _nextResendMs;          // earliest time the next resend is allowed (REKEY_TIMEOUT + jitter from _lastInitiationMs)

        // ---- established session tracking ----
        bool _hasSession;            // a handshake has completed and produced live transport keys
        long _sessionEstablishedMs;  // when the current session's handshake completed (for REKEY/REJECT_AFTER_TIME)
        long _lastSentMs;            // last time we sent any transport packet (for persistent keepalive)
        long _lastReceivedMs;        // last time we received any transport packet
        bool _keepalivePending;      // data was received and we have not sent anything since → passive keepalive owed
        long _keepaliveDueMs;        // when that passive keepalive should fire (recv + KEEPALIVE_TIMEOUT)

        // ---- message counters on the current send key ----
        ulong _sentMessages;

        /// <summary>
        /// Creates the state machine. <paramref name="jitterMs"/> supplies the per-resend jitter added to
        /// <c>REKEY_TIMEOUT</c> (the reference adds up to ⅓ s of randomness); pass <c>null</c> for no jitter
        /// (deterministic — used by tests).
        /// </summary>
        public WireGuardPeerState(WireGuardTimers? timers = null, Func<long>? jitterMs = null)
        {
            _timers = timers ?? WireGuardTimers.Default;
            _jitterMs = jitterMs ?? (static () => 0L);
        }

        /// <summary>The timer thresholds in effect.</summary>
        public WireGuardTimers Timers => _timers;

        /// <summary>True once a handshake has completed and a live session exists (cleared by <see cref="Reset"/>).</summary>
        public bool HasSession => _hasSession;

        /// <summary>True while a handshake initiation is outstanding (awaiting a response).</summary>
        public bool HandshakeInFlight => _handshakeInFlight;

        /// <summary>Number of transport messages sent on the current key (drives the message-count re-key/reject).</summary>
        public ulong SentMessages => _sentMessages;

        // ---- event recording ----

        /// <summary>
        /// Records that a handshake initiation was just sent. The first call of an attempt also starts the
        /// <c>REKEY_ATTEMPT_TIME</c> give-up clock; subsequent calls (resends) only refresh the <c>REKEY_TIMEOUT</c>
        /// resend clock.
        /// </summary>
        public void OnHandshakeInitiated(long nowMs)
        {
            if (!_handshakeInFlight)
            {
                _handshakeInFlight = true;
                _handshakeStartedMs = nowMs;
            }
            _lastInitiationMs = nowMs;
            _nextResendMs = nowMs + _timers.RekeyTimeoutMs + Math.Max(0, _jitterMs());
        }

        /// <summary>
        /// Records that a handshake just completed (response consumed, transport keys derived): a fresh session starts
        /// now, the in-flight handshake clears, and the send-message counter resets for the new key.
        /// </summary>
        public void OnHandshakeCompleted(long nowMs)
        {
            _handshakeInFlight = false;
            _hasSession = true;
            _sessionEstablishedMs = nowMs;
            _lastSentMs = nowMs;
            _lastReceivedMs = nowMs;
            _sentMessages = 0;
            _keepalivePending = false;
        }

        /// <summary>Records that a transport packet (data or keepalive) was sent, advancing the send counter and clearing any owed passive keepalive.</summary>
        public void OnDataSent(long nowMs)
        {
            _lastSentMs = nowMs;
            _keepalivePending = false;
            _sentMessages = unchecked(_sentMessages + 1UL);
        }

        /// <summary>
        /// Records that a transport packet was received. Per the whitepaper, if nothing is sent back within
        /// <c>KEEPALIVE_TIMEOUT</c> a passive keepalive becomes due; call this for every inbound transport packet.
        /// </summary>
        public void OnDataReceived(long nowMs)
        {
            _lastReceivedMs = nowMs;
            if (!_keepalivePending)
            {
                _keepalivePending = true;
                _keepaliveDueMs = nowMs + _timers.KeepaliveTimeoutMs;
            }
        }

        /// <summary>Clears all session/handshake state (after a tear-down or give-up) so the peer starts cold again.</summary>
        public void Reset()
        {
            _handshakeInFlight = false;
            _hasSession = false;
            _keepalivePending = false;
            _sentMessages = 0;
        }

        // ---- pure decisions (each a function of now + recorded facts) ----

        /// <summary>Age of the current session in ms (or 0 when there is none).</summary>
        public long SessionAge(long nowMs) => _hasSession ? nowMs - _sessionEstablishedMs : 0L;

        /// <summary>True when the current session has passed <c>REKEY_AFTER_TIME</c> or <c>REKEY_AFTER_MESSAGES</c> and should be replaced (still usable until reject).</summary>
        public bool NeedsRekey(long nowMs) =>
            _hasSession &&
            (nowMs - _sessionEstablishedMs >= _timers.RekeyAfterTimeMs || _sentMessages >= _timers.RekeyAfterMessages);

        /// <summary>True when the current session may no longer be used at all (past <c>REJECT_AFTER_TIME</c> or <c>REJECT_AFTER_MESSAGES</c>).</summary>
        public bool IsSessionDead(long nowMs) =>
            _hasSession &&
            (nowMs - _sessionEstablishedMs >= _timers.RejectAfterTimeMs || _sentMessages >= _timers.RejectAfterMessages);

        /// <summary>True when a fresh handshake should be started: no live session and none in flight, or the live one needs a re-key and none is in flight yet.</summary>
        public bool NeedsHandshake(long nowMs) =>
            !_handshakeInFlight && (!_hasSession || NeedsRekey(nowMs) || IsSessionDead(nowMs));

        /// <summary>True when the in-flight handshake should be resent: it is outstanding and <c>REKEY_TIMEOUT</c> (+jitter) has elapsed since the last initiation, but it has not yet been retrying for <c>REKEY_ATTEMPT_TIME</c>.</summary>
        public bool ShouldResendHandshake(long nowMs) =>
            _handshakeInFlight && nowMs >= _nextResendMs && !ShouldAbandonHandshake(nowMs);

        /// <summary>True when the in-flight handshake has been retrying for <c>REKEY_ATTEMPT_TIME</c> with no response and must be abandoned (tear the peer down).</summary>
        public bool ShouldAbandonHandshake(long nowMs) =>
            _handshakeInFlight && nowMs - _handshakeStartedMs >= _timers.RekeyAttemptTimeMs;

        /// <summary>
        /// True when a keepalive is due: a persistent-keepalive interval of silence has elapsed (when enabled), or a
        /// passive keepalive owed after a received packet has reached <c>KEEPALIVE_TIMEOUT</c>. Requires a live session.
        /// </summary>
        public bool ShouldSendKeepalive(long nowMs)
        {
            if (!_hasSession) return false;
            if (_keepalivePending && nowMs >= _keepaliveDueMs) return true;
            if (_timers.PersistentKeepaliveMs > 0 && nowMs - _lastSentMs >= _timers.PersistentKeepaliveMs) return true;
            return false;
        }

        /// <summary>
        /// The single most-urgent action for the driver this instant (whitepaper §6.2 priority): abandon a stalled
        /// handshake first, then resend a pending one, then start one (cold or for a re-key/dead session), then report a
        /// dead session, then a due keepalive, else <see cref="WireGuardSessionAction.None"/>.
        /// </summary>
        public WireGuardSessionAction Evaluate(long nowMs)
        {
            if (_handshakeInFlight)
            {
                if (ShouldAbandonHandshake(nowMs)) return WireGuardSessionAction.AbandonHandshake;
                if (ShouldResendHandshake(nowMs)) return WireGuardSessionAction.ResendHandshake;
                // a handshake is in flight and still within its window — nothing else to start
                return WireGuardSessionAction.None;
            }

            if (NeedsHandshake(nowMs)) return WireGuardSessionAction.InitiateHandshake;
            if (IsSessionDead(nowMs)) return WireGuardSessionAction.SessionDead;
            if (ShouldSendKeepalive(nowMs)) return WireGuardSessionAction.SendKeepalive;
            return WireGuardSessionAction.None;
        }
    }
}
