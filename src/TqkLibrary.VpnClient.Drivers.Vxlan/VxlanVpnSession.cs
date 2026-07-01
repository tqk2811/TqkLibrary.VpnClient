using System.Threading.Tasks;
using TqkLibrary.VpnClient.Abstractions.Channels.Interfaces;
using TqkLibrary.VpnClient.Abstractions.Drivers.Interfaces;
using TqkLibrary.VpnClient.Abstractions.Drivers.Models;

namespace TqkLibrary.VpnClient.Drivers.Vxlan
{
    /// <summary>
    /// The single L3 session of a VXLAN connection. <see cref="PacketChannel"/> is the stable facade (bridged from the L2
    /// data session via the Ethernet fabric) and <see cref="Config"/> is the static config (VXLAN does no in-tunnel
    /// address negotiation, so neither changes across a reconnect).
    /// </summary>
    public sealed class VxlanVpnSession : IVpnSession
    {
        /// <summary>Creates a session over the given (stable) channel and config.</summary>
        public VxlanVpnSession(IPacketChannel packetChannel, TunnelConfig config)
        {
            PacketChannel = packetChannel;
            Config = config;
        }

        /// <inheritdoc/>
        public TunnelConfig Config { get; }

        /// <inheritdoc/>
        public IPacketChannel PacketChannel { get; }

        /// <inheritdoc/>
        public ValueTask DisposeAsync() => default;
    }
}
