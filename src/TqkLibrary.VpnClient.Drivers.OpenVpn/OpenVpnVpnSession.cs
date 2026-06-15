using TqkLibrary.VpnClient.Abstractions.Channels.Interfaces;
using TqkLibrary.VpnClient.Abstractions.Drivers.Interfaces;
using TqkLibrary.VpnClient.Abstractions.Drivers.Models;
using TqkLibrary.VpnClient.Drivers.OpenVpn.Models;

namespace TqkLibrary.VpnClient.Drivers.OpenVpn
{
    /// <summary>The single L3 session of an OpenVPN tun connection. <see cref="PacketChannel"/> is the stable facade.</summary>
    public sealed class OpenVpnVpnSession : IVpnSession
    {
        /// <summary>Creates a session over the given (stable) channel and config.</summary>
        public OpenVpnVpnSession(IPacketChannel packetChannel, TunnelConfig config)
        {
            PacketChannel = packetChannel;
            Config = config;
        }

        /// <inheritdoc/>
        public TunnelConfig Config { get; private set; }

        /// <inheritdoc/>
        public IPacketChannel PacketChannel { get; }

        /// <summary>
        /// Raised after an auto-reconnect updates <see cref="Config"/>. When <see cref="OpenVpnReconnectInfo.AddressChanged"/>
        /// is true the consumer should rebuild its IP stack; otherwise existing in-tunnel sockets keep working.
        /// </summary>
        public event Action<OpenVpnReconnectInfo>? Reconfigured;

        /// <summary>Applies a reconnect's freshly pushed config to <see cref="Config"/> and raises <see cref="Reconfigured"/>.</summary>
        internal void ApplyReconnect(OpenVpnReconnectInfo info, TunnelConfig config)
        {
            Config = config;
            Reconfigured?.Invoke(info);
        }

        /// <inheritdoc/>
        public ValueTask DisposeAsync() => default;
    }
}
