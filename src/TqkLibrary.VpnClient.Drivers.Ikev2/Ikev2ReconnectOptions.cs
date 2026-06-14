namespace TqkLibrary.VpnClient.Drivers.Ikev2
{
    /// <summary>
    /// Auto-reconnect policy for an <see cref="Ikev2Connection"/>. Reconnect kicks in only after an initial
    /// successful connect, when the tunnel drops (DPD timeout or a server DELETE). Enabled by default; set
    /// <see cref="Enabled"/> to false to keep the old single-shot behaviour. Mirrors the L2TP/IPsec driver's policy.
    /// </summary>
    public sealed class Ikev2ReconnectOptions
    {
        /// <summary>Whether a dropped tunnel is re-established automatically.</summary>
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
