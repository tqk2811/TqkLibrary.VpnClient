using System.Net;
using TqkLibrary.VpnClient.Abstractions.Channels.Interfaces;
using TqkLibrary.VpnClient.Abstractions.Drivers.Interfaces;
using TqkLibrary.VpnClient.Abstractions.Drivers.Models;
using TqkLibrary.VpnClient.Drivers.Ikev2.Models;

namespace TqkLibrary.VpnClient.Drivers.Ikev2
{
    /// <summary>The single L3 session of an IKEv2 connection. <see cref="PacketChannel"/> is the stable facade.</summary>
    public sealed class Ikev2VpnSession : IVpnSession
    {
        /// <summary>Creates a session over the given (stable) channel and config.</summary>
        public Ikev2VpnSession(IPacketChannel packetChannel, TunnelConfig config)
        {
            PacketChannel = packetChannel;
            Config = config;
        }

        /// <inheritdoc/>
        public TunnelConfig Config { get; }

        /// <inheritdoc/>
        public IPacketChannel PacketChannel { get; }

        /// <summary>
        /// Raised after an auto-reconnect updates <see cref="Config"/>. When <see cref="Ikev2ReconnectInfo.AddressChanged"/>
        /// is true the consumer should rebuild its IP stack; otherwise existing in-tunnel sockets keep working.
        /// </summary>
        public event Action<Ikev2ReconnectInfo>? Reconfigured;

        /// <summary>Applies a reconnect's new address/DNS to <see cref="Config"/> and raises <see cref="Reconfigured"/>.</summary>
        internal void ApplyReconnect(Ikev2ReconnectInfo info, IPAddress? dns)
        {
            Config.AssignedAddress = info.AssignedAddress;
            Config.DnsServers.Clear();
            if (dns != null) Config.DnsServers.Add(dns);
            Reconfigured?.Invoke(info);
        }

        /// <inheritdoc/>
        public ValueTask DisposeAsync() => default;
    }
}
