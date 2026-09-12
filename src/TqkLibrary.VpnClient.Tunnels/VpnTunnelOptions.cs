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

        /// <summary>
        /// Keepalive interval, in seconds, given to a WireGuard peer whose <c>.conf</c> sets no
        /// <c>PersistentKeepalive</c>. 0 leaves the file alone.
        /// </summary>
        /// <remarks>
        /// WireGuard's own default is off, and that default assumes something else keeps the path
        /// open. Nothing here does: this tunnel exists only while this process holds it, the peer
        /// is almost always behind NAT, and a mapping the far side drops after a minute of silence
        /// takes the tunnel with it — silently, since WireGuard has no link-loss to report. Most
        /// providers' files leave the key out, so 25 seconds is the interval a tunnel gets unless
        /// its file asks for another; it is also what wg-quick users are told to write, and what
        /// wireproxy uses.
        /// </remarks>
        public int WireGuardKeepaliveSeconds { get; set; } = 25;

        /// <summary>
        /// How a tunnel that is up is checked for a session the server dropped in silence. On by
        /// default; set <see cref="VpnHealthProbeOptions.Enabled"/> to false to leave a tunnel
        /// entirely to its driver's own drop detection.
        /// </summary>
        public VpnHealthProbeOptions HealthProbe { get; set; } = new VpnHealthProbeOptions();

        /// <summary>Where the drivers' handshake/rekey/link-loss traces go. Null means no logging.</summary>
        public ILoggerFactory? LoggerFactory { get; set; }

        internal static VpnTunnelOptions OrDefault(VpnTunnelOptions? options) => options ?? new VpnTunnelOptions();
    }
}
