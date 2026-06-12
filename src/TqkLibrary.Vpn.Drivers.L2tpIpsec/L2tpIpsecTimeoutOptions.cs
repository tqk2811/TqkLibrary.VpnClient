namespace TqkLibrary.Vpn.Drivers.L2tpIpsec
{
    /// <summary>
    /// Tunable handshake/keepalive timeouts for an <see cref="L2tpIpsecConnection"/>: how persistently the IKE
    /// exchanges and the L2TP control channel retry before declaring the gateway unresponsive. Both retransmits use
    /// exponential backoff with jitter — the wait doubles after each unanswered try (capped), so a congested or
    /// briefly-stalled link is not hammered at a fixed rate. The defaults match the values that used to be hard-coded;
    /// tighten them to fail fast, or loosen them for high-latency links.
    /// </summary>
    public sealed class L2tpIpsecTimeoutOptions
    {
        /// <summary>The wait for a reply to the first send of each IKE message before resending it (Main/Quick Mode + rekey).</summary>
        public TimeSpan IkeRetransmitInterval { get; set; } = TimeSpan.FromSeconds(2.5);

        /// <summary>Factor the IKE retransmit wait grows by after each unanswered try (1.0 = fixed interval, no backoff).</summary>
        public double IkeBackoffMultiplier { get; set; } = 2.0;

        /// <summary>Upper bound the backed-off IKE retransmit wait is clamped to.</summary>
        public TimeSpan IkeMaxRetransmitInterval { get; set; } = TimeSpan.FromSeconds(20);

        /// <summary>How many times an IKE message is sent before giving up with a <see cref="TqkLibrary.Vpn.Abstractions.Drivers.VpnNetworkTimeoutException"/>.</summary>
        public int IkeMaxAttempts { get; set; } = 5;

        /// <summary>The wait before the L2TP reliable control channel first resends the head unacked message.</summary>
        public TimeSpan L2tpRetransmitInterval { get; set; } = TimeSpan.FromSeconds(1);

        /// <summary>Factor the L2TP control retransmit wait grows by after each resend (1.0 = fixed interval, no backoff).</summary>
        public double L2tpBackoffMultiplier { get; set; } = 2.0;

        /// <summary>Upper bound the backed-off L2TP control retransmit wait is clamped to.</summary>
        public TimeSpan L2tpMaxRetransmitInterval { get; set; } = TimeSpan.FromSeconds(8);

        /// <summary>How many times an L2TP control message is retransmitted before the link is declared dead; 0 = unbounded.</summary>
        public int L2tpMaxRetransmits { get; set; } = 8;

        /// <summary>Random jitter applied to each IKE / L2TP retransmit wait as ±(fraction × wait); 0 disables jitter.</summary>
        public double RetransmitJitterFraction { get; set; } = 0.2;

        /// <summary>
        /// The wait before the IKE send that follows <paramref name="attempt"/> unanswered tries:
        /// <c>IkeRetransmitInterval × IkeBackoffMultiplier^attempt</c>, clamped at <see cref="IkeMaxRetransmitInterval"/>
        /// (jitter applied separately). <paramref name="attempt"/> 0 ⇒ the base <see cref="IkeRetransmitInterval"/>.
        /// </summary>
        public TimeSpan IkeIntervalFor(int attempt)
            => TimeSpan.FromMilliseconds(Math.Min(
                IkeMaxRetransmitInterval.TotalMilliseconds,
                IkeRetransmitInterval.TotalMilliseconds * Math.Pow(IkeBackoffMultiplier, Math.Max(0, attempt))));

        /// <summary>Builds the reliable control-channel policy passed to <see cref="TqkLibrary.Vpn.L2tp.L2tpClient"/>.</summary>
        public TqkLibrary.Vpn.L2tp.L2tpRetransmitOptions BuildL2tpRetransmitOptions()
            => new()
            {
                Interval = L2tpRetransmitInterval,
                MaxRetransmits = L2tpMaxRetransmits,
                BackoffMultiplier = L2tpBackoffMultiplier,
                MaxInterval = L2tpMaxRetransmitInterval,
                JitterFraction = RetransmitJitterFraction,
            };
    }
}
