using System.Net;
using TqkLibrary.VpnClient.Abstractions.Channels.Interfaces;
using TqkLibrary.VpnClient.Abstractions.Drivers.Interfaces;
using TqkLibrary.VpnClient.Abstractions.Drivers.Models;
using TqkLibrary.VpnClient.Drivers.Pptp.Models;

namespace TqkLibrary.VpnClient.Drivers.Pptp
{
    /// <summary>The single PPP/L3 session of a PPTP connection. <see cref="PacketChannel"/> is the stable facade.</summary>
    public sealed class PptpVpnSession : IVpnSession
    {
        /// <summary>Creates a session over the given (stable) channel and config.</summary>
        public PptpVpnSession(IPacketChannel packetChannel, TunnelConfig config)
        {
            PacketChannel = packetChannel;
            Config = config;
        }

        /// <inheritdoc/>
        public TunnelConfig Config { get; }

        /// <inheritdoc/>
        public IPacketChannel PacketChannel { get; }

        /// <summary>
        /// Raised after an auto-reconnect updates <see cref="Config"/>. When <see cref="PptpReconnectInfo.AddressChanged"/>
        /// is true the consumer should rebuild its IP stack; otherwise existing in-tunnel sockets keep working.
        /// </summary>
        public event Action<PptpReconnectInfo>? Reconfigured;

        /// <summary>Applies a reconnect's new address/DNS to <see cref="Config"/> and raises <see cref="Reconfigured"/>.</summary>
        internal void ApplyReconnect(PptpReconnectInfo info, IPAddress? dns)
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
