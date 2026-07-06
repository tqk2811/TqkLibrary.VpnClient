using System.Threading.Tasks;
using TqkLibrary.VpnClient.Abstractions.Channels.Interfaces;
using TqkLibrary.VpnClient.Abstractions.Drivers.Interfaces;
using TqkLibrary.VpnClient.Abstractions.Drivers.Models;

namespace TqkLibrary.VpnClient.Drivers.L2tpv3Eth
{
    /// <summary>
    /// The single L3 session of an L2TPv3 Ethernet-pseudowire connection. <see cref="PacketChannel"/> is the stable facade
    /// (bridged from the L2 data session via the Ethernet fabric) and <see cref="Config"/> is the static config (L2TPv3 static
    /// mode does no in-tunnel address negotiation, so neither changes across a reconnect).
    /// </summary>
    public sealed class L2tpv3EthVpnSession : IVpnSession
    {
        /// <summary>Creates a session over the given (stable) channel and config.</summary>
        public L2tpv3EthVpnSession(IPacketChannel packetChannel, TunnelConfig config)
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
