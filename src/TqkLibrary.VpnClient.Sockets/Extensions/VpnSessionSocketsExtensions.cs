using TqkLibrary.VpnClient.Abstractions.Drivers.Interfaces;
using TqkLibrary.VpnClient.IpStack;

namespace TqkLibrary.VpnClient.Sockets.Extensions
{
    /// <summary>Convenience helpers that build the userspace socket layer over a VPN session.</summary>
    public static class VpnSessionSocketsExtensions
    {
        /// <summary>
        /// Creates a userspace TCP/IP stack bound to the session's packet channel and assigned address(es). When the
        /// session also negotiated an IPv6 address (<see cref="TunnelConfig.AssignedAddressV6"/>) the stack is built
        /// dual-stack, so both families flow through the one channel.
        /// </summary>
        /// <remarks>
        /// The caller owns the returned stack and must <see cref="TcpIpStack.Dispose"/> it — before disposing the
        /// session — so its egress stops (a write in flight is cancelled) and it detaches from the packet channel.
        /// </remarks>
        public static TcpIpStack CreateTcpStack(this IVpnSession session)
        {
            if (session.Config.AssignedAddress == null && session.Config.AssignedAddressV6 == null)
                throw new InvalidOperationException("The session has no assigned address.");
            return new TcpIpStack(session.PacketChannel, session.Config.AssignedAddress, session.Config.AssignedAddressV6);
        }
    }
}
