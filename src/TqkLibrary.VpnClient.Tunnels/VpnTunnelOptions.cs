using Microsoft.Extensions.Logging;

namespace TqkLibrary.VpnClient.Tunnels
{
    /// <summary>
    /// What every dial has in common, kept apart from the arguments a single protocol needs.
    /// </summary>
    public sealed class VpnTunnelOptions
    {
        /// <summary>
        /// The budget for ONE handshake. Exceeding it throws rather than hanging: a VPN server that
        /// is unreachable usually swallows the packets in silence instead of refusing them.
        /// </summary>
        public TimeSpan ConnectTimeout { get; set; } = TimeSpan.FromSeconds(90);

        /// <summary>
        /// Ask for a global IPv6 over the PPP link as well (IPV6CP, then SLAAC/DHCPv6) — SSTP and
        /// L2TP/IPsec. Best-effort: a server that offers none still yields a working IPv4 tunnel.
        /// </summary>
        public bool EnableIpv6 { get; set; }

        /// <summary>
        /// Prefer IPv6 for the OUTER transport (resolve AAAA, run TLS/IKE over it). A host with no
        /// AAAA record falls back to IPv4 on its own.
        /// </summary>
        public bool PreferOuterIpv6 { get; set; }

        /// <summary>
        /// The genuine SoftEther watermark blob. Left unset the driver sends a placeholder and a
        /// real SoftEther server answers HTTP 403 — the blob is GPL data and cannot live in this
        /// repository.
        /// </summary>
        public string? SoftEtherWatermarkPath { get; set; }

        /// <summary>Where the drivers' handshake/rekey/link-loss traces go. Null means no logging.</summary>
        public ILoggerFactory? LoggerFactory { get; set; }

        internal static VpnTunnelOptions OrDefault(VpnTunnelOptions? options) => options ?? new VpnTunnelOptions();
    }
}
