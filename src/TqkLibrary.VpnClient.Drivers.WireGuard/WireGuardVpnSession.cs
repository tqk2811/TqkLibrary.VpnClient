using TqkLibrary.VpnClient.Abstractions.Channels.Interfaces;
using TqkLibrary.VpnClient.Abstractions.Drivers.Interfaces;
using TqkLibrary.VpnClient.Abstractions.Drivers.Models;

namespace TqkLibrary.VpnClient.Drivers.WireGuard
{
    /// <summary>
    /// The single L3 session of a WireGuard connection. <see cref="PacketChannel"/> is the stable facade and
    /// <see cref="Config"/> is the static config (WireGuard does no in-tunnel negotiation, so neither changes across a
    /// rekey or a reconnect).
    /// </summary>
    public sealed class WireGuardVpnSession : IVpnSession
    {
        /// <summary>Creates a session over the given (stable) channel and config.</summary>
        public WireGuardVpnSession(IPacketChannel packetChannel, TunnelConfig config)
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
