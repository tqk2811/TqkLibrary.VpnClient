namespace TqkLibrary.VpnClient.WireGuard
{
    /// <summary>
    /// The fixed timer thresholds from the WireGuard whitepaper ("WireGuard: Next Generation Kernel Network Tunnel",
    /// §6.2 "Reinitiation" and the reference <c>timers.c</c>). These are the constants the
    /// <see cref="WireGuardPeerState"/> state machine compares the clock and counters against. All durations are kept
    /// in <b>milliseconds</b> (the same unit <see cref="WireGuardPeerState"/> is clocked in, mirroring how
    /// <c>OpenVpnKeepalive</c>/<c>OpenVpnPing</c> take <c>nowMs</c>) so tests can inject a deterministic clock.
    /// <para>
    /// The defaults are the spec values; <see cref="PersistentKeepaliveMs"/> is the only per-peer knob (0 = off, the
    /// WireGuard default — passive keepalives still fire regardless). Everything is immutable once constructed.
    /// </para>
    /// </summary>
    public sealed class WireGuardTimers
    {
        /// <summary>Re-key once a session has carried traffic for this long — 120 s (whitepaper <c>REKEY_AFTER_TIME</c>).</summary>
        public const int DefaultRekeyAfterTimeSeconds = 120;

        /// <summary>A session may never be used past this age — 180 s (whitepaper <c>REJECT_AFTER_TIME</c>).</summary>
        public const int DefaultRejectAfterTimeSeconds = 180;

        /// <summary>Give up a stalled handshake after this long, tearing the session down — 90 s (whitepaper <c>REKEY_ATTEMPT_TIME</c>).</summary>
        public const int DefaultRekeyAttemptTimeSeconds = 90;

        /// <summary>Resend an unanswered handshake initiation after this long — 5 s (whitepaper <c>REKEY_TIMEOUT</c>), plus jitter.</summary>
        public const int DefaultRekeyTimeoutSeconds = 5;

        /// <summary>Send a passive keepalive this long after receiving a data packet that needed no reply — 10 s (whitepaper <c>KEEPALIVE_TIMEOUT</c>).</summary>
        public const int DefaultKeepaliveTimeoutSeconds = 10;

        /// <summary>Re-key after this many messages on a key — <c>2^60</c> (whitepaper <c>REKEY_AFTER_MESSAGES</c>).</summary>
        public const ulong DefaultRekeyAfterMessages = 1UL << 60;

        /// <summary>Refuse to encrypt past this many messages on a key — <c>2^64 − 2^13 − 1</c> (whitepaper <c>REJECT_AFTER_MESSAGES</c>).</summary>
        public const ulong DefaultRejectAfterMessages = ulong.MaxValue - (1UL << 13) - 1UL;

        /// <summary>Re-key once a session has been alive this many ms (whitepaper <c>REKEY_AFTER_TIME</c>, default 120 s).</summary>
        public long RekeyAfterTimeMs { get; }

        /// <summary>Hard upper bound on session age in ms; past it the session is dead (whitepaper <c>REJECT_AFTER_TIME</c>, default 180 s).</summary>
        public long RejectAfterTimeMs { get; }

        /// <summary>How long to keep retrying a handshake before giving up in ms (whitepaper <c>REKEY_ATTEMPT_TIME</c>, default 90 s).</summary>
        public long RekeyAttemptTimeMs { get; }

        /// <summary>Base interval between handshake initiation resends in ms (whitepaper <c>REKEY_TIMEOUT</c>, default 5 s); jitter is added on top.</summary>
        public long RekeyTimeoutMs { get; }

        /// <summary>Passive-keepalive delay in ms after a received data packet (whitepaper <c>KEEPALIVE_TIMEOUT</c>, default 10 s).</summary>
        public long KeepaliveTimeoutMs { get; }

        /// <summary>Persistent-keepalive interval in ms; 0 disables it (the WireGuard default). When set, a keepalive is sent every interval of silence.</summary>
        public long PersistentKeepaliveMs { get; }

        /// <summary>Message count after which a re-key should be started (whitepaper <c>REKEY_AFTER_MESSAGES</c>, default <c>2^60</c>).</summary>
        public ulong RekeyAfterMessages { get; }

        /// <summary>Message count after which a key must not be used at all (whitepaper <c>REJECT_AFTER_MESSAGES</c>).</summary>
        public ulong RejectAfterMessages { get; }

        /// <summary>
        /// Creates the timer thresholds. <paramref name="persistentKeepaliveSeconds"/> is the only per-peer knob
        /// (0 = off, the default); the rest default to the whitepaper values but can be overridden (mainly for tests).
        /// </summary>
        public WireGuardTimers(
            int persistentKeepaliveSeconds = 0,
            int rekeyAfterTimeSeconds = DefaultRekeyAfterTimeSeconds,
            int rejectAfterTimeSeconds = DefaultRejectAfterTimeSeconds,
            int rekeyAttemptTimeSeconds = DefaultRekeyAttemptTimeSeconds,
            int rekeyTimeoutSeconds = DefaultRekeyTimeoutSeconds,
            int keepaliveTimeoutSeconds = DefaultKeepaliveTimeoutSeconds,
            ulong rekeyAfterMessages = DefaultRekeyAfterMessages,
            ulong rejectAfterMessages = DefaultRejectAfterMessages)
        {
            RekeyAfterTimeMs = Math.Max(0, rekeyAfterTimeSeconds) * 1000L;
            RejectAfterTimeMs = Math.Max(0, rejectAfterTimeSeconds) * 1000L;
            RekeyAttemptTimeMs = Math.Max(0, rekeyAttemptTimeSeconds) * 1000L;
            RekeyTimeoutMs = Math.Max(0, rekeyTimeoutSeconds) * 1000L;
            KeepaliveTimeoutMs = Math.Max(0, keepaliveTimeoutSeconds) * 1000L;
            PersistentKeepaliveMs = Math.Max(0, persistentKeepaliveSeconds) * 1000L;
            RekeyAfterMessages = rekeyAfterMessages;
            RejectAfterMessages = rejectAfterMessages;
        }

        /// <summary>The whitepaper defaults with persistent-keepalive off.</summary>
        public static WireGuardTimers Default { get; } = new WireGuardTimers();
    }
}
