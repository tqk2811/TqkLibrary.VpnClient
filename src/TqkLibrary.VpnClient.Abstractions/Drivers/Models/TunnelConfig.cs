using System.Net;

namespace TqkLibrary.VpnClient.Abstractions.Drivers.Models
{
    /// <summary>
    /// The network configuration a session obtained, regardless of how (IPCP / config-push / DHCP).
    /// The userspace stack uses these internally; nothing is written to the OS routing table.
    /// </summary>
    public sealed class TunnelConfig
    {
        /// <summary>The tunnel IP assigned to this session.</summary>
        public IPAddress? AssignedAddress { get; set; }

        /// <summary>Prefix length of the assigned address (e.g. 32 for a point-to-point /32).</summary>
        public int PrefixLength { get; set; } = 32;

        /// <summary>The IPv6 tunnel address assigned to this session, or null if IPv6 was not negotiated.</summary>
        public IPAddress? AssignedAddressV6 { get; set; }

        /// <summary>Prefix length of the assigned IPv6 address (e.g. 64 for a link-local /64).</summary>
        public int PrefixLengthV6 { get; set; } = 64;

        /// <summary>
        /// The IPv4 default gateway (DHCP option 3 / an ifconfig push), or null when the session has none. On an L2
        /// link this is the address a host must ARP for anything outside <see cref="PrefixLength"/> — ARPing the
        /// destination itself goes unanswered, and the packet is dropped with nothing to show for it.
        /// </summary>
        /// <remarks>
        /// The same gateway also appears in <see cref="Routes"/> as <c>"0.0.0.0/0 &lt;gateway&gt;"</c>; this is the typed
        /// form, so a caller that only needs the next hop does not have to parse route text back apart.
        /// </remarks>
        public IPAddress? Gateway { get; set; }

        /// <summary>The IPv6 default gateway (the advertising router of a Router Advertisement), or null if none.</summary>
        public IPAddress? GatewayV6 { get; set; }

        /// <summary>DNS servers pushed by the server.</summary>
        public IList<IPAddress> DnsServers { get; } = new List<IPAddress>();

        /// <summary>Routes (CIDR text) the server asked to send through the tunnel.</summary>
        public IList<string> Routes { get; } = new List<string>();

        /// <summary>Negotiated MTU for this session's IP stack.</summary>
        public int Mtu { get; set; } = 1400;
    }
}
