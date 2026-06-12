namespace TqkLibrary.Vpn.L2tp
{
    /// <summary>
    /// Retransmit policy for the reliable L2TP control channel (RFC 2661 §5.8): the base interval, how that interval
    /// grows after each unacknowledged resend (exponential backoff with jitter), the cap the grown interval is clamped
    /// to, and how many times a head message is resent before the channel declares the peer dead. The defaults
    /// reproduce the original fixed-interval behaviour (<see cref="BackoffMultiplier"/> 1.0, no jitter), so a caller that
    /// passes nothing keeps the previous 1s/no-backoff timing.
    /// </summary>
    public sealed class L2tpRetransmitOptions
    {
        /// <summary>Delay before the first retransmit of an unacked control message (default 1s).</summary>
        public TimeSpan Interval { get; set; } = TimeSpan.FromSeconds(1);

        /// <summary>How many times a head message is resent before the channel declares the peer dead; 0 = unbounded.</summary>
        public int MaxRetransmits { get; set; }

        /// <summary>Factor the interval grows by after each resend (1.0 = fixed interval, no backoff).</summary>
        public double BackoffMultiplier { get; set; } = 1.0;

        /// <summary>Upper bound the backed-off interval is clamped to (default 8s).</summary>
        public TimeSpan MaxInterval { get; set; } = TimeSpan.FromSeconds(8);

        /// <summary>Random jitter applied to each interval as ±(fraction × interval); 0 disables jitter.</summary>
        public double JitterFraction { get; set; }

        /// <summary>
        /// The delay before the resend that follows <paramref name="resends"/> already-completed resends of the same head:
        /// <c>Interval × BackoffMultiplier^resends</c>, clamped at <see cref="MaxInterval"/> (jitter applied separately).
        /// <paramref name="resends"/> 0 ⇒ the base <see cref="Interval"/>.
        /// </summary>
        public TimeSpan IntervalFor(int resends)
            => TimeSpan.FromMilliseconds(Math.Min(
                MaxInterval.TotalMilliseconds,
                Interval.TotalMilliseconds * Math.Pow(BackoffMultiplier, Math.Max(0, resends))));
    }
}
