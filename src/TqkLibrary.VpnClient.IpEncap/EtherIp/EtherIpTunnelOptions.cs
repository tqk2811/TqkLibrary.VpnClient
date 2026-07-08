using System;

namespace TqkLibrary.VpnClient.IpEncap.EtherIp
{
    /// <summary>
    /// Options for an <see cref="EtherIpTunnelChannel"/>. EtherIP (RFC 3378) has no optional wire fields — the header is a
    /// fixed 2 bytes — so, unlike <c>GreTunnelOptions</c>, the only knobs are the advertised MTU and this endpoint's MAC
    /// (surfaced as the L2 channel's <see cref="Abstractions.Channels.Interfaces.IEthernetChannel.LinkAddress"/>).
    /// </summary>
    public sealed class EtherIpTunnelOptions
    {
        /// <summary>Inner-frame MTU advertised to the fabric (EtherIP/IP overhead already deducted by the caller). Default 1400.</summary>
        public int Mtu { get; init; } = 1400;

        /// <summary>This endpoint's MAC address (6 bytes), surfaced as the channel's link address. Empty by default.</summary>
        public ReadOnlyMemory<byte> LinkAddress { get; init; }
    }
}
