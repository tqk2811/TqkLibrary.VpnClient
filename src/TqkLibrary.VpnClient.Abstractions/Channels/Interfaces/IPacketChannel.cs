namespace TqkLibrary.VpnClient.Abstractions.Channels.Interfaces
{
    /// <summary>
    /// L3 channel carrying bare IPv4/IPv6 packets. The userspace TCP/IP stack binds to THIS only and never sees Ethernet.
    /// </summary>
    public interface IPacketChannel : ILinkChannel
    {
        /// <summary>Sends one complete IP packet toward the tunnel peer.</summary>
        /// <remarks>
        /// The stack may call this inline while holding a TCP connection's lock. An implementation must therefore not
        /// raise <see cref="InboundIpPacket"/> synchronously from inside this call (deliver it from its own receive
        /// loop or a queue instead), or the reply re-enters the stack mid-update or deadlocks two connections.
        /// </remarks>
        ValueTask WriteIpPacketAsync(ReadOnlyMemory<byte> ipPacket, CancellationToken cancellationToken = default);

        /// <summary>
        /// Raised for each inbound IP packet. The buffer is only valid for the duration of the handler —
        /// copy if it must outlive the callback.
        /// </summary>
        event Action<ReadOnlyMemory<byte>>? InboundIpPacket;
    }
}
