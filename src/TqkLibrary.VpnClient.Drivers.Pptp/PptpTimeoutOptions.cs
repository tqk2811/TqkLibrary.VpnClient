namespace TqkLibrary.VpnClient.Drivers.Pptp
{
    /// <summary>
    /// Tunable handshake/keepalive timeouts for a <see cref="PptpConnection"/>: how long each handshake phase
    /// (PPP authentication, CCP/MPPE, IPCP link-up) may take before the attempt is abandoned, and how often the
    /// control connection sends an Echo-Request keep-alive. The defaults are conservative; tighten them to fail fast,
    /// or loosen them for high-latency links.
    /// </summary>
    public sealed class PptpTimeoutOptions
    {
        /// <summary>How long to wait for the full PPP handshake (MS-CHAPv2 auth, CCP/MPPE, IPCP link-up) before failing the attempt.</summary>
        public TimeSpan HandshakeTimeout { get; set; } = TimeSpan.FromSeconds(30);

        /// <summary>The interval between control-connection Echo-Request keep-alives once the tunnel is up.</summary>
        public TimeSpan EchoInterval { get; set; } = TimeSpan.FromSeconds(60);
    }
}
