using System.Threading.Tasks;
using TqkLibrary.VpnClient.Abstractions.Channels.Interfaces;
using TqkLibrary.VpnClient.Abstractions.Drivers.Interfaces;
using TqkLibrary.VpnClient.Abstractions.Drivers.Models;

namespace TqkLibrary.VpnClient.Drivers.GtpU
{
    /// <summary>The single L3 session of a GTP-U connection. <see cref="PacketChannel"/> is the stable facade.</summary>
    public sealed class GtpUVpnSession : IVpnSession
    {
        /// <summary>Creates a session over the given (stable) channel and config.</summary>
        public GtpUVpnSession(IPacketChannel packetChannel, TunnelConfig config)
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
