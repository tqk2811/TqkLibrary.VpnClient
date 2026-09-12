namespace TqkLibrary.VpnClient.Tunnels
{
    /// <summary>
    /// How often a tunnel that says it is up is made to prove it, and how much silence in a row
    /// counts as dead.
    /// </summary>
    /// <remarks>
    /// The defaults spot a silently dropped session in roughly a minute. Shorter than that starts
    /// calling a tunnel dead over one lost datagram — the probe travels the same lossy path as
    /// everything else — and re-dialling costs several seconds and every connection that was open.
    /// Much longer and the user meets the dead tunnel before the monitor does, which is the whole
    /// problem this exists to fix.
    /// </remarks>
    public sealed class VpnHealthProbeOptions
    {
        /// <summary>Whether a live tunnel is probed at all. On by default.</summary>
        public bool Enabled { get; set; } = true;

        /// <summary>
        /// Gap between probes. <see cref="TimeSpan.Zero"/> disables them as surely as
        /// <see cref="Enabled"/>.
        /// </summary>
        public TimeSpan Interval { get; set; } = TimeSpan.FromSeconds(20);

        /// <summary>How long one probe waits for an answer before counting as silence.</summary>
        public TimeSpan Timeout { get; set; } = TimeSpan.FromSeconds(3);

        /// <summary>Consecutive silent probes before the link is declared dead. Must be at least 1.</summary>
        public int FailuresBeforeDead { get; set; } = 3;

        /// <summary>True when these settings actually ask for probing.</summary>
        internal bool IsActive => Enabled && Interval > TimeSpan.Zero && FailuresBeforeDead >= 1;
    }
}
