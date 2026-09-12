using System.Net;

namespace TqkLibrary.VpnClient.Tunnels.Models
{
    /// <summary>
    /// What a VPN session was given: the addresses to send from and the resolver to ask. Read again
    /// after a driver re-establishes its link, because none of it is guaranteed to be the same.
    /// </summary>
    public readonly struct TunnelAddressing
    {
        public TunnelAddressing(IPAddress address, IPAddress? addressV6 = null, IPAddress? dns = null)
        {
            Address = address;
            AddressV6 = addressV6;
            Dns = dns;
        }

        /// <summary>The IPv4 assigned to this side of the tunnel.</summary>
        public IPAddress Address { get; }

        /// <summary>The global IPv6 assigned, or null when the session is IPv4-only.</summary>
        public IPAddress? AddressV6 { get; }

        /// <summary>The DNS server the session handed out, if any.</summary>
        public IPAddress? Dns { get; }

        /// <summary>True when this is the same addressing as <paramref name="other"/>.</summary>
        public bool Matches(TunnelAddressing other)
            => Equals(Address, other.Address) && Equals(AddressV6, other.AddressV6) && Equals(Dns, other.Dns);
    }
}
