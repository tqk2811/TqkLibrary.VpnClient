using System.Threading.Channels;

namespace TqkLibrary.VpnClient.Ethernet
{
    /// <summary>
    /// Tunables for an <see cref="EthernetAdapter"/>: the in-memory switch MTU and the per-host inbound backpressure
    /// queue (design 09 §"Hiệu năng").
    /// </summary>
    public sealed class EthernetAdapterOptions
    {
        /// <summary>The switch's link MTU in payload bytes (each host advertises <c>Mtu − 14</c> to its IP stack). Default 1500.</summary>
        public int SwitchMtu { get; init; } = 1500;

        /// <summary>The per-host inbound queue depth (packets) before backpressure kicks in. Default 256.</summary>
        public int InboundQueueCapacity { get; init; } = 256;

        /// <summary>
        /// What the per-host inbound queue does when full: <see cref="BoundedChannelFullMode.DropOldest"/> (default —
        /// favour fresh traffic, never block the switch deliver path), <c>DropNewest</c>, or <c>Wait</c>.
        /// </summary>
        public BoundedChannelFullMode InboundFullMode { get; init; } = BoundedChannelFullMode.DropOldest;

        /// <summary>Shared default instance.</summary>
        public static EthernetAdapterOptions Default { get; } = new EthernetAdapterOptions();
    }
}
