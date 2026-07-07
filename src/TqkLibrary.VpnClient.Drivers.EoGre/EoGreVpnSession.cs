using System.Threading.Tasks;
using TqkLibrary.VpnClient.Abstractions.Channels.Interfaces;
using TqkLibrary.VpnClient.Abstractions.Drivers.Interfaces;
using TqkLibrary.VpnClient.Abstractions.Drivers.Models;

namespace TqkLibrary.VpnClient.Drivers.EoGre
{
    /// <summary>
    /// The single L3 session of an EoGRE / NVGRE connection. <see cref="PacketChannel"/> is the stable facade (bridged from
    /// the L2 data session via the Ethernet fabric) and <see cref="Config"/> is the static config (EoGRE/NVGRE do no
    /// in-tunnel address negotiation, so neither changes across a reconnect).
    /// </summary>
    public sealed class EoGreVpnSession : IVpnSession
    {
        /// <summary>Creates a session over the given (stable) channel and config.</summary>
        public EoGreVpnSession(IPacketChannel packetChannel, TunnelConfig config)
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
