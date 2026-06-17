using System;
using TqkLibrary.VpnClient.Abstractions.Channels.Interfaces;

namespace TqkLibrary.VpnClient.Ethernet.Models
{
    /// <summary>
    /// The components that make one virtual host on an <see cref="EthernetAdapter"/>: the
    /// <see cref="INeighborResolver"/> (ARP/NDISC) the host resolves next-hops through, an optional
    /// <see cref="IAddressConfigurator"/> (DHCPv4 / SLAAC+DHCPv6) for its lease, and the inbound-frame seam hooks the
    /// resolver/configurator listen on.
    /// <para>
    /// Built by the <c>build</c> callback of <see cref="EthernetAdapter.AddHost"/>, which hands in the host's freshly
    /// connected switch port so the resolver/configurator can share it (they send ARP/DHCP out the same port the
    /// <see cref="VirtualHost"/> uses). The seam hooks wire the same manual composition the SoftEther / OpenVPN-tap
    /// drivers do today:
    /// <list type="bullet">
    /// <item><see cref="NonIpFrameHandler"/> → <c>arpResolver.HandleInboundFrame</c> (ARP rides a separate EtherType, so
    /// the <see cref="VirtualHost.InboundNonIpFrame"/> seam carries it);</item>
    /// <item><see cref="IpPacketHandler"/> → <c>ndiscResolver.HandleInboundFrame</c> and/or
    /// <c>configurator.HandleInboundFrame</c> (NDISC, DHCPv4 and DHCPv6 ride inside ordinary IP, so the
    /// <see cref="VirtualHost.InboundIpPacket"/> seam carries them — otherwise the bound stack would swallow them).</item>
    /// </list>
    /// These are plain delegates so the adapter never depends on the concrete resolver/configurator types (their
    /// <c>HandleInboundFrame</c> is not part of <see cref="INeighborResolver"/>/<see cref="IAddressConfigurator"/>).
    /// </para>
    /// </summary>
    public sealed class EthernetHostSpec
    {
        /// <summary>Creates the components for a host resolving next-hops through <paramref name="resolver"/>.</summary>
        public EthernetHostSpec(INeighborResolver resolver)
        {
            Resolver = resolver ?? throw new ArgumentNullException(nameof(resolver));
        }

        /// <summary>The neighbor resolver (ARP for IPv4, NDISC for IPv6) the host's egress resolves next-hops through.</summary>
        public INeighborResolver Resolver { get; }

        /// <summary>The optional address configurator (DHCPv4 / SLAAC+DHCPv6) run by <see cref="EthernetAdapter.EthernetHostHandle.ConfigureAsync"/>.</summary>
        public IAddressConfigurator? Configurator { get; init; }

        /// <summary>
        /// Subscribed to <see cref="VirtualHost.InboundNonIpFrame"/> (e.g. <c>arpResolver.HandleInboundFrame</c>):
        /// inbound non-IP frames (ARP) the neighbor layer must see.
        /// </summary>
        public Action<ReadOnlyMemory<byte>>? NonIpFrameHandler { get; init; }

        /// <summary>
        /// Subscribed to <see cref="VirtualHost.InboundIpPacket"/> (e.g. <c>ndisc.HandleInboundFrame</c> +
        /// <c>configurator.HandleInboundFrame</c>): inbound IP packets NDISC/DHCP must intercept before the stack.
        /// </summary>
        public Action<ReadOnlyMemory<byte>>? IpPacketHandler { get; init; }

        /// <summary>
        /// When <c>true</c> (default), the adapter disposes <see cref="Resolver"/> and <see cref="Configurator"/> (if
        /// they implement <see cref="IAsyncDisposable"/>) when the host handle is disposed. Set <c>false</c> if the
        /// caller owns their lifetime.
        /// </summary>
        public bool OwnsResolverAndConfigurator { get; init; } = true;
    }
}
