using TqkLibrary.Vpn.Abstractions.Channels.Interfaces;
using TqkLibrary.Vpn.Abstractions.Drivers.Models;

namespace TqkLibrary.Vpn.Abstractions.Drivers.Interfaces
{
    /// <summary>
    /// One logical IP endpoint inside a connection: one assigned IP, one <see cref="IPacketChannel"/>, one IP stack.
    /// SSTP yields exactly one; L2TP may yield several; an L2 EthernetAdapter yields one per virtual host.
    /// </summary>
    public interface IVpnSession : IAsyncDisposable
    {
        /// <summary>The address/DNS/routes/MTU this session obtained.</summary>
        TunnelConfig Config { get; }

        /// <summary>The L3 channel feeding this session's userspace TCP/IP stack.</summary>
        IPacketChannel PacketChannel { get; }
    }
}
