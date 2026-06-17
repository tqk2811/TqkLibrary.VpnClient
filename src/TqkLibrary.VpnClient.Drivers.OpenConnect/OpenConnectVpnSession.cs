using TqkLibrary.VpnClient.Abstractions.Channels.Interfaces;
using TqkLibrary.VpnClient.Abstractions.Drivers.Interfaces;
using TqkLibrary.VpnClient.Abstractions.Drivers.Models;

namespace TqkLibrary.VpnClient.Drivers.OpenConnect
{
    /// <summary>
    /// The single L3 session of an OpenConnect connection. <see cref="PacketChannel"/> is the stable facade and
    /// <see cref="Config"/> is the tunnel config the gateway pushed in the X-CSTP-* headers (neither changes across a
    /// reconnect — a returning session reuses the same auth cookie/address).
    /// </summary>
    public sealed class OpenConnectVpnSession : IVpnSession
    {
        /// <summary>Creates a session over the given (stable) channel and config.</summary>
        public OpenConnectVpnSession(IPacketChannel packetChannel, TunnelConfig config)
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
