namespace TqkLibrary.Vpn.Abstractions.Channels.Interfaces
{
    /// <summary>
    /// L2 channel carrying full Ethernet frames. Consumed by an EthernetAdapter (ARP + DHCP + switch) that
    /// bridges it down to one or more <see cref="IPacketChannel"/> — the stack never binds to this directly.
    /// </summary>
    public interface IEthernetChannel : ILinkChannel
    {
        /// <summary>This endpoint's MAC address (6 bytes).</summary>
        ReadOnlyMemory<byte> LinkAddress { get; }

        /// <summary>Sends one complete Ethernet frame toward the tunnel peer.</summary>
        ValueTask WriteFrameAsync(ReadOnlyMemory<byte> ethernetFrame, CancellationToken cancellationToken = default);

        /// <summary>Raised for each inbound Ethernet frame. Buffer valid only during the handler.</summary>
        event Action<ReadOnlyMemory<byte>>? InboundFrame;
    }
}
