namespace TqkLibrary.VpnClient.OpenConnect
{
    /// <summary>
    /// CSTP dead-peer-detection / keep-alive timing (the <c>X-CSTP-DPD</c> and <c>X-CSTP-Keepalive</c> seconds the
    /// gateway pushes on the CONNECT response). The clock is injected (every method takes <c>nowMs</c>) so the driver
    /// pumps it from a timer while tests stay deterministic — the same clock-inject shape as
    /// <c>WireGuardPeerState</c> / <c>OpenVpnKeepalive</c>.
    /// <para>
    /// DPD has two thresholds off the last <i>received</i> traffic: at <c>X-CSTP-DPD</c> seconds of silence the client
    /// probes the peer with a DPD-REQUEST (<see cref="ShouldSendDpd"/>); if nothing is received for the dead window
    /// (a configurable multiple of the DPD interval, default 2×) the peer is presumed dead (<see cref="IsPeerDead"/>).
    /// A separate keep-alive (<see cref="ShouldSendKeepalive"/>) sends a CSTP keep-alive after <c>X-CSTP-Keepalive</c>
    /// seconds of nothing <i>sent</i>, so the TLS connection (and any NAT mapping) does not idle out. Each side is
    /// disabled when its pushed interval is 0.
    /// </para>
    /// </summary>
    public sealed class CstpDpdState
    {
        readonly long _dpdIntervalMs;
        readonly long _deadAfterMs;
        readonly long _keepaliveIntervalMs;
        long _lastSentMs;
        long _lastReceivedMs;
        long _lastDpdSentMs;

        /// <summary>
        /// Creates the timer from the pushed seconds (0 disables that side), seeded at <paramref name="nowMs"/>.
        /// <paramref name="dpdSeconds"/> is <c>X-CSTP-DPD</c>; <paramref name="keepaliveSeconds"/> is
        /// <c>X-CSTP-Keepalive</c>; <paramref name="deadMultiplier"/> sets the dead window as that many DPD intervals
        /// of silence (default 2 — matching OpenConnect's "miss two DPDs" liveness rule).
        /// </summary>
        public CstpDpdState(int dpdSeconds, int keepaliveSeconds, long nowMs, int deadMultiplier = 2)
        {
            if (deadMultiplier < 1) deadMultiplier = 1;
            _dpdIntervalMs = Math.Max(0, dpdSeconds) * 1000L;
            _deadAfterMs = _dpdIntervalMs * deadMultiplier;
            _keepaliveIntervalMs = Math.Max(0, keepaliveSeconds) * 1000L;
            _lastSentMs = nowMs;
            _lastReceivedMs = nowMs;
            _lastDpdSentMs = nowMs;
        }

        /// <summary>Records that a packet (any CSTP frame) was sent — resets the keep-alive send timer.</summary>
        public void OnDataSent(long nowMs) => Interlocked.Exchange(ref _lastSentMs, nowMs);

        /// <summary>Records that a packet (any CSTP frame, data or control) was received — proves the peer is alive.</summary>
        public void OnDataReceived(long nowMs) => Interlocked.Exchange(ref _lastReceivedMs, nowMs);

        /// <summary>
        /// True when a DPD probe is due: nothing has been received for the DPD interval and no probe has been sent in
        /// the last interval either (so probes are not spammed). Disabled when DPD = 0. The caller marks the probe with
        /// <see cref="OnDpdSent"/>.
        /// </summary>
        public bool ShouldSendDpd(long nowMs) =>
            _dpdIntervalMs > 0
            && nowMs - Interlocked.Read(ref _lastReceivedMs) >= _dpdIntervalMs
            && nowMs - Interlocked.Read(ref _lastDpdSentMs) >= _dpdIntervalMs;

        /// <summary>Records that a DPD-REQUEST was just sent (rate-limits the next probe).</summary>
        public void OnDpdSent(long nowMs) => Interlocked.Exchange(ref _lastDpdSentMs, nowMs);

        /// <summary>True when a keep-alive is due (nothing sent for the keep-alive interval). Disabled when keep-alive = 0.</summary>
        public bool ShouldSendKeepalive(long nowMs) =>
            _keepaliveIntervalMs > 0 && nowMs - Interlocked.Read(ref _lastSentMs) >= _keepaliveIntervalMs;

        /// <summary>True when the peer is presumed dead (nothing received for the dead window). Disabled when DPD = 0.</summary>
        public bool IsPeerDead(long nowMs) =>
            _deadAfterMs > 0 && nowMs - Interlocked.Read(ref _lastReceivedMs) >= _deadAfterMs;
    }
}
