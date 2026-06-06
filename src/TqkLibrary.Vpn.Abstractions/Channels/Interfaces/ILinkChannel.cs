using TqkLibrary.Vpn.Abstractions.Channels.Enums;

namespace TqkLibrary.Vpn.Abstractions.Channels.Interfaces
{
    /// <summary>
    /// Common base for a duplex link the userspace stack rides on. Either L3 (<see cref="IPacketChannel"/>)
    /// or L2 (<see cref="IEthernetChannel"/>); the <see cref="Medium"/> property gates ARP/neighbor-discovery.
    /// </summary>
    public interface ILinkChannel : IAsyncDisposable
    {
        /// <summary>L3 (Ip) or L2 (Ethernet).</summary>
        LinkMedium Medium { get; }

        /// <summary>Maximum transmission unit (payload bytes) for this link.</summary>
        int Mtu { get; }

        /// <summary>Bytes the link prepends to a payload (0 for an IP-only channel, 14 for Ethernet).</summary>
        int MaxHeaderLength { get; }

        /// <summary>True when the next hop's link address must be resolved (ARP/NDISC) before egress — L2 only.</summary>
        bool RequiresLinkAddressResolution { get; }
    }
}
