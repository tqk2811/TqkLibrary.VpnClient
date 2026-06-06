using TqkLibrary.Vpn.Abstractions.Channels.Interfaces;
using TqkLibrary.Vpn.Abstractions.Drivers.Interfaces;
using TqkLibrary.Vpn.Abstractions.Drivers.Models;

namespace TqkLibrary.Vpn.Drivers.Sstp
{
    /// <summary>The single PPP/L3 session of an SSTP connection.</summary>
    public sealed class SstpVpnSession : IVpnSession
    {
        /// <summary>Creates a session over the given channel and config.</summary>
        public SstpVpnSession(IPacketChannel packetChannel, TunnelConfig config)
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
