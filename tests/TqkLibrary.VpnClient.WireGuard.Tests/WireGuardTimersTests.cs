using TqkLibrary.VpnClient.WireGuard;
using TqkLibrary.VpnClient.WireGuard.Enums;
using Xunit;

namespace TqkLibrary.VpnClient.WireGuard.Tests
{
    /// <summary>
    /// Offline tests for the WireGuard timer state machine (V3.e): with the clock injected as <c>nowMs</c> the
    /// <see cref="WireGuardPeerState"/> reports re-key at 120 s, a dead session past 180 s, persistent/passive
    /// keepalives on the right cadence, handshake resends every <c>REKEY_TIMEOUT</c>, and give-up after
    /// <c>REKEY_ATTEMPT_TIME</c> (90 s). Pure decision logic — no sockets, no real time.
    /// </summary>
    public class WireGuardTimersTests
    {
        const long Sec = 1000L;

        // ---- timer constants match the whitepaper ----

        [Fact]
        public void Default_Timers_Match_Whitepaper()
        {
            var t = WireGuardTimers.Default;
            Assert.Equal(120 * Sec, t.RekeyAfterTimeMs);
            Assert.Equal(180 * Sec, t.RejectAfterTimeMs);
            Assert.Equal(90 * Sec, t.RekeyAttemptTimeMs);
            Assert.Equal(5 * Sec, t.RekeyTimeoutMs);
            Assert.Equal(10 * Sec, t.KeepaliveTimeoutMs);
            Assert.Equal(0L, t.PersistentKeepaliveMs); // off by default
            Assert.Equal(1UL << 60, t.RekeyAfterMessages);
            Assert.Equal(ulong.MaxValue - (1UL << 13) - 1UL, t.RejectAfterMessages);
        }

        // ---- a cold peer asks for a handshake; an in-flight one suppresses it ----

        [Fact]
        public void Cold_Peer_Needs_Handshake_Then_Goes_Quiet_While_In_Flight()
        {
            var s = new WireGuardPeerState();
            Assert.True(s.NeedsHandshake(0));
            Assert.Equal(WireGuardSessionAction.InitiateHandshake, s.Evaluate(0));

            s.OnHandshakeInitiated(0);
            Assert.True(s.HandshakeInFlight);
            Assert.False(s.NeedsHandshake(1 * Sec));               // suppressed while one is outstanding
            Assert.Equal(WireGuardSessionAction.None, s.Evaluate(1 * Sec));
        }

        // ---- re-key at exactly 120 s of session age ----

        [Fact]
        public void Reports_Rekey_At_120s()
        {
            var s = new WireGuardPeerState();
            s.OnHandshakeInitiated(0);
            s.OnHandshakeCompleted(0);

            Assert.False(s.NeedsRekey(119 * Sec));
            Assert.Equal(WireGuardSessionAction.None, s.Evaluate(119 * Sec));

            Assert.True(s.NeedsRekey(120 * Sec));                  // REKEY_AFTER_TIME reached
            Assert.True(s.NeedsHandshake(120 * Sec));
            Assert.Equal(WireGuardSessionAction.InitiateHandshake, s.Evaluate(120 * Sec));
            Assert.False(s.IsSessionDead(120 * Sec));              // still usable until reject
        }

        // ---- dead session past 180 s ----

        [Fact]
        public void Reports_Session_Dead_Past_180s()
        {
            var s = new WireGuardPeerState();
            s.OnHandshakeInitiated(0);
            s.OnHandshakeCompleted(0);

            Assert.False(s.IsSessionDead(179 * Sec));
            Assert.True(s.IsSessionDead(180 * Sec));               // REJECT_AFTER_TIME reached
            Assert.True(s.IsSessionDead(181 * Sec));

            // With no handshake in flight, a dead session first drives a new handshake (preferred over reporting dead).
            Assert.Equal(WireGuardSessionAction.InitiateHandshake, s.Evaluate(180 * Sec));

            // If a handshake is already outstanding (cannot start another), the dead session is what is reported.
            s.OnHandshakeInitiated(180 * Sec);
            Assert.Equal(WireGuardSessionAction.None, s.Evaluate(181 * Sec)); // in-flight, still within attempt window
        }

        // ---- message-count re-key / reject ----

        [Fact]
        public void Rekey_And_Reject_On_Message_Count()
        {
            // Tiny limits so the test can actually cross them.
            var timers = new WireGuardTimers(rekeyAfterMessages: 3, rejectAfterMessages: 5);
            var s = new WireGuardPeerState(timers);
            s.OnHandshakeInitiated(0);
            s.OnHandshakeCompleted(0);

            s.OnDataSent(Sec); s.OnDataSent(Sec); // 2 messages
            Assert.False(s.NeedsRekey(Sec));
            s.OnDataSent(Sec);                     // 3rd → at the watermark
            Assert.True(s.NeedsRekey(Sec));
            Assert.False(s.IsSessionDead(Sec));

            s.OnDataSent(Sec); s.OnDataSent(Sec);  // 5 messages → reject
            Assert.True(s.IsSessionDead(Sec));
            Assert.Equal(5UL, s.SentMessages);
        }

        // ---- handshake resend every REKEY_TIMEOUT (5 s), with injected jitter ----

        [Fact]
        public void Handshake_Resends_Every_RekeyTimeout()
        {
            var s = new WireGuardPeerState();      // no jitter
            s.OnHandshakeInitiated(0);

            Assert.False(s.ShouldResendHandshake(4 * Sec));
            Assert.True(s.ShouldResendHandshake(5 * Sec));         // REKEY_TIMEOUT elapsed
            Assert.Equal(WireGuardSessionAction.ResendHandshake, s.Evaluate(5 * Sec));

            s.OnHandshakeInitiated(5 * Sec);                       // resend done; clock restarts from here
            Assert.False(s.ShouldResendHandshake(9 * Sec));
            Assert.True(s.ShouldResendHandshake(10 * Sec));
        }

        [Fact]
        public void Resend_Honours_Injected_Jitter()
        {
            var s = new WireGuardPeerState(jitterMs: static () => 300L); // +0.3 s jitter
            s.OnHandshakeInitiated(0);
            Assert.False(s.ShouldResendHandshake(5 * Sec));               // 5.0 s < 5.3 s
            Assert.True(s.ShouldResendHandshake(5 * Sec + 300));          // 5.3 s reached
        }

        // ---- give up after REKEY_ATTEMPT_TIME (90 s) ----

        [Fact]
        public void Handshake_Abandoned_After_90s()
        {
            var s = new WireGuardPeerState();
            s.OnHandshakeInitiated(0);

            // Resends keep happening up to the attempt deadline.
            for (long t = 5 * Sec; t < 90 * Sec; t += 5 * Sec)
            {
                Assert.True(s.ShouldResendHandshake(t));
                s.OnHandshakeInitiated(t);
            }

            Assert.False(s.ShouldAbandonHandshake(89 * Sec));
            Assert.True(s.ShouldAbandonHandshake(90 * Sec));             // REKEY_ATTEMPT_TIME reached
            Assert.Equal(WireGuardSessionAction.AbandonHandshake, s.Evaluate(90 * Sec));
            Assert.False(s.ShouldResendHandshake(90 * Sec));            // resend yields to abandon

            s.Reset();
            Assert.False(s.HandshakeInFlight);
            Assert.True(s.NeedsHandshake(90 * Sec));                    // cold again → start over
        }

        // ---- persistent keepalive fires on its interval; off by default ----

        [Fact]
        public void Persistent_Keepalive_Off_By_Default()
        {
            var s = new WireGuardPeerState();
            s.OnHandshakeInitiated(0);
            s.OnHandshakeCompleted(0);
            // Long silence but no persistent-keepalive configured and nothing received → no keepalive owed.
            Assert.False(s.ShouldSendKeepalive(60 * Sec));
        }

        [Fact]
        public void Persistent_Keepalive_Fires_On_Cadence()
        {
            var timers = new WireGuardTimers(persistentKeepaliveSeconds: 25);
            var s = new WireGuardPeerState(timers);
            s.OnHandshakeInitiated(0);
            s.OnHandshakeCompleted(0);

            Assert.False(s.ShouldSendKeepalive(24 * Sec));
            Assert.True(s.ShouldSendKeepalive(25 * Sec));                // 25 s of send-silence
            Assert.Equal(WireGuardSessionAction.SendKeepalive, s.Evaluate(25 * Sec));

            s.OnDataSent(25 * Sec);                                      // sending resets the cadence
            Assert.False(s.ShouldSendKeepalive(49 * Sec));
            Assert.True(s.ShouldSendKeepalive(50 * Sec));               // next interval
        }

        // ---- passive keepalive 10 s after receiving data with no reply ----

        [Fact]
        public void Passive_Keepalive_After_Received_Data()
        {
            var s = new WireGuardPeerState();                            // persistent off
            s.OnHandshakeInitiated(0);
            s.OnHandshakeCompleted(0);

            s.OnDataReceived(10 * Sec);                                  // got a packet at t=10
            Assert.False(s.ShouldSendKeepalive(19 * Sec));
            Assert.True(s.ShouldSendKeepalive(20 * Sec));               // KEEPALIVE_TIMEOUT (10 s) after the receive
            Assert.Equal(WireGuardSessionAction.SendKeepalive, s.Evaluate(20 * Sec));
        }

        [Fact]
        public void Sending_Data_Cancels_The_Owed_Passive_Keepalive()
        {
            var s = new WireGuardPeerState();
            s.OnHandshakeInitiated(0);
            s.OnHandshakeCompleted(0);

            s.OnDataReceived(10 * Sec);                                  // keepalive owed at t=20
            s.OnDataSent(12 * Sec);                                      // but we sent a real packet in response
            Assert.False(s.ShouldSendKeepalive(20 * Sec));             // so no passive keepalive is needed
        }

        // ---- a completed handshake supersedes the previous in-flight state ----

        [Fact]
        public void Completing_Handshake_Clears_In_Flight_And_Starts_Fresh_Session()
        {
            var s = new WireGuardPeerState();
            s.OnHandshakeInitiated(0);
            Assert.True(s.HandshakeInFlight);

            s.OnHandshakeCompleted(2 * Sec);
            Assert.False(s.HandshakeInFlight);
            Assert.True(s.HasSession);
            Assert.Equal(0UL, s.SentMessages);                          // counter reset for the new key
            Assert.Equal(WireGuardSessionAction.None, s.Evaluate(3 * Sec));
            Assert.Equal(0L, s.SessionAge(2 * Sec));     // age is measured from completion at t=2 s
            Assert.Equal(3 * Sec, s.SessionAge(5 * Sec)); // 3 s later
        }

        // ---- Evaluate priority: abandon beats resend ----

        [Fact]
        public void Evaluate_Prefers_Abandon_Over_Resend_At_The_Deadline()
        {
            var s = new WireGuardPeerState();
            s.OnHandshakeInitiated(0);
            // At t=90 both "resend due" (>5 s since last) and "attempt expired" hold; abandon must win.
            Assert.Equal(WireGuardSessionAction.AbandonHandshake, s.Evaluate(90 * Sec));
        }
    }
}
