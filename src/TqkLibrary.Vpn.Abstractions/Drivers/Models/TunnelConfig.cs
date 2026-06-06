using System.Net;

namespace TqkLibrary.Vpn.Abstractions.Drivers.Models
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

        /// <summary>DNS servers pushed by the server.</summary>
        public IList<IPAddress> DnsServers { get; } = new List<IPAddress>();

        /// <summary>Routes (CIDR text) the server asked to send through the tunnel.</summary>
        public IList<string> Routes { get; } = new List<string>();

        /// <summary>Negotiated MTU for this session's IP stack.</summary>
        public int Mtu { get; set; } = 1400;
    }
}
