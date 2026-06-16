namespace TqkLibrary.VpnClient.Drivers.WireGuard
{
    /// <summary>
    /// Auto-reconnect policy for a <see cref="WireGuardConnection"/>. Reconnect kicks in only after an initial
    /// successful connect, when the tunnel is declared dead (a handshake that could not be re-established within the
    /// whitepaper's <c>REKEY_ATTEMPT_TIME</c>, or a transport fault). Enabled by default; set <see cref="Enabled"/> to
    /// false to keep single-shot behaviour. Mirrors the OpenVPN/IKEv2/L2TP driver policies so the shared supervisor
    /// (roadmap F.6) can later subsume all of them.
    /// </summary>
    public sealed class WireGuardReconnectOptions
    {
        /// <summary>Whether a dead tunnel is re-established automatically.</summary>
        public bool Enabled { get; set; } = true;

        /// <summary>Maximum reconnect attempts before giving up; 0 = retry indefinitely until DisconnectAsync.</summary>
        public int MaxAttempts { get; set; } = 0;

        /// <summary>Delay before the second attempt (the first retry runs immediately after the drop).</summary>
        public TimeSpan InitialBackoff { get; set; } = TimeSpan.FromSeconds(1);

        /// <summary>Upper bound the exponential backoff is capped at.</summary>
        public TimeSpan MaxBackoff { get; set; } = TimeSpan.FromSeconds(30);

        /// <summary>Factor the backoff grows by after each failed attempt.</summary>
        public double BackoffMultiplier { get; set; } = 2.0;

        /// <summary>Random jitter applied to each delay as ±(fraction × delay); 0 disables jitter.</summary>
        public double JitterFraction { get; set; } = 0.2;

        /// <summary>The next backoff in the geometric sequence, capped at <see cref="MaxBackoff"/> (jitter applied separately).</summary>
        public TimeSpan NextBackoff(TimeSpan current)
            => TimeSpan.FromMilliseconds(Math.Min(MaxBackoff.TotalMilliseconds, current.TotalMilliseconds * BackoffMultiplier));
    }
}
