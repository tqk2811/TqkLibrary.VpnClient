using TqkLibrary.VpnClient.Drivers.IpEncap.Enums;
using TqkLibrary.VpnClient.IpEncap.Gre;

namespace TqkLibrary.VpnClient.Drivers.IpEncap
{
    /// <summary>
    /// Static configuration for an <see cref="IpEncapConnection"/>: which encapsulation to carry and its MTU. Plain
    /// IP-in-IP / GRE has no negotiation — every parameter is fixed up front by the caller (the remote gateway is the
    /// <c>VpnEndpoint.Host</c> passed to the driver).
    /// </summary>
    public sealed class IpEncapOptions
    {
        /// <summary>The encapsulation kind (GRE proto-47 / IPIP proto-4 / SIT proto-41). Default <see cref="IpEncapKind.Gre"/>.</summary>
        public IpEncapKind Kind { get; init; } = IpEncapKind.Gre;

        /// <summary>Inner-packet MTU advertised to the IP stack (outer-IP + encap overhead already deducted). Default 1400.</summary>
        public int Mtu { get; init; } = 1400;

        /// <summary>
        /// Outbound GRE options (RFC 2890 Key / Sequence / Checksum) when <see cref="Kind"/> is <see cref="IpEncapKind.Gre"/>.
        /// Ignored for IPIP/SIT (header-less). When null a minimal RFC 2784 GRE header is emitted; the channel's MTU is
        /// always taken from <see cref="Mtu"/> regardless of any value set on this object.
        /// </summary>
        public GreTunnelOptions? Gre { get; init; }
    }
}
