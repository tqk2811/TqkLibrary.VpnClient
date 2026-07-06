using TqkLibrary.VpnClient.Abstractions.Net;
using TqkLibrary.VpnClient.Drivers.Fou.Enums;
using TqkLibrary.VpnClient.IpEncap.Gre;

namespace TqkLibrary.VpnClient.Drivers.Fou
{
    /// <summary>
    /// Static configuration for a <see cref="FouConnection"/>: which X-over-UDP framing (<see cref="Mode"/>), which inner
    /// IP protocol the tunnel carries (<see cref="InnerProtocol"/>), the UDP destination port, the inner MTU, and the
    /// (optional) RFC 2890 GRE options used when the inner protocol is GRE. FOU/GUE have no negotiation — every parameter
    /// is fixed up front by the caller (the remote gateway is the <c>VpnEndpoint.Host</c> passed to the driver).
    /// </summary>
    public sealed record FouOptions
    {
        /// <summary>The X-over-UDP framing: bare <see cref="FouEncapMode.Fou"/> (no header) or <see cref="FouEncapMode.Gue"/> (4-byte GUE variant-0 header). Default FOU.</summary>
        public FouEncapMode Mode { get; init; } = FouEncapMode.Fou;

        /// <summary>
        /// The IANA IP protocol number the tunnel carries. Supported: <see cref="IpProtocol.IpInIp"/> (4, IPv4-in-UDP) and
        /// <see cref="IpProtocol.Ipv6"/> (41, IPv6-in-UDP) — a header-less passthrough of the inner IP packet; and
        /// <see cref="IpProtocol.Gre"/> (47) — the payload is a GRE packet decoded by the reused IpEncap GRE codec. Default GRE.
        /// <para>In FOU mode this fixes both directions (there is no header to say otherwise); in GUE mode it is written to
        /// (and expected in) the GUE Proto field.</para>
        /// </summary>
        public byte InnerProtocol { get; init; } = IpProtocol.Gre;

        /// <summary>The UDP destination port. Default 6080 (the IANA-assigned "GUE" port; also usable for FOU — Linux <c>ip fou</c> requires an explicit port).</summary>
        public int Port { get; init; } = 6080;

        /// <summary>Inner-packet MTU advertised to the IP stack (outer-IP + UDP + GUE/GRE overhead already deducted). Default 1400.</summary>
        public int Mtu { get; init; } = 1400;

        /// <summary>
        /// Outbound GRE options (RFC 2890 Key / Sequence / Checksum), used only when <see cref="InnerProtocol"/> is GRE.
        /// When null a minimal RFC 2784 GRE header is emitted; the channel's MTU is always taken from <see cref="Mtu"/>
        /// regardless of any value set on this object.
        /// </summary>
        public GreTunnelOptions? Gre { get; init; }
    }
}
