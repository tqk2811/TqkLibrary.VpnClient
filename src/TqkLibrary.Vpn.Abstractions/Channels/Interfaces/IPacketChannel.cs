namespace TqkLibrary.Vpn.Abstractions.Channels.Interfaces
{
    /// <summary>
    /// L3 channel carrying bare IPv4/IPv6 packets. The userspace TCP/IP stack binds to THIS only and never sees Ethernet.
    /// </summary>
    public interface IPacketChannel : ILinkChannel
    {
        /// <summary>Sends one complete IP packet toward the tunnel peer.</summary>
        ValueTask WriteIpPacketAsync(ReadOnlyMemory<byte> ipPacket, CancellationToken cancellationToken = default);

        /// <summary>
        /// Raised for each inbound IP packet. The buffer is only valid for the duration of the handler —
        /// copy if it must outlive the callback.
        /// </summary>
        event Action<ReadOnlyMemory<byte>>? InboundIpPacket;
    }
}
