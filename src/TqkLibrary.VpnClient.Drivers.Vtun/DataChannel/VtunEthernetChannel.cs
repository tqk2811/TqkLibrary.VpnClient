using TqkLibrary.VpnClient.Abstractions.Channels.Enums;
using TqkLibrary.VpnClient.Abstractions.Channels.Interfaces;

namespace TqkLibrary.VpnClient.Drivers.Vtun.DataChannel
{
    /// <summary>
    /// The L2 data channel of an established vtun <c>type ether</c> (tap) tunnel: a thin <see cref="IEthernetChannel"/>
    /// that carries <b>full Ethernet frames</b> as vtun data frames. vtun in tap mode puts the raw Ethernet frame in the
    /// data-frame payload verbatim (no extra header), so this is a pass-through to the supplied <c>send</c> sink on egress
    /// and raises <see cref="InboundFrame"/> for each inbound data frame the driver's receive loop hands to
    /// <see cref="Deliver"/>. It plugs straight into the userspace Ethernet fabric (ARP + the <c>VirtualHost</c> bridge),
    /// which bridges down to the IP stack — the stack never binds here directly. Mirrors <c>N2nEthernetChannel</c> /
    /// <c>SoftEtherEthernetChannel</c>, but with no codec/transform (vtun framing + optional Blowfish are applied by the
    /// control channel around this payload).
    /// </summary>
    public sealed class VtunEthernetChannel : IEthernetChannel
    {
        const int EthernetHeaderLength = 14;
        const int MacAddressLength = 6;

        readonly byte[] _srcMac;
        readonly Func<ReadOnlyMemory<byte>, CancellationToken, ValueTask> _send;
        readonly Action? _onFrameSent;
        readonly Action? _onFrameReceived;

        /// <summary>
        /// Wraps a send sink. <paramref name="srcMac"/> is this edge's MAC. <paramref name="send"/> frames and puts an
        /// outbound Ethernet frame on the wire (the driver's data-frame writer). <paramref name="mtu"/> is the tunnel MTU.
        /// <paramref name="onFrameSent"/>/<paramref name="onFrameReceived"/> feed the driver's keepalive timers.
        /// </summary>
        public VtunEthernetChannel(ReadOnlyMemory<byte> srcMac,
            Func<ReadOnlyMemory<byte>, CancellationToken, ValueTask> send,
            int mtu = VtunDriverConstants.DefaultMtu,
            Action? onFrameSent = null,
            Action? onFrameReceived = null)
        {
            if (srcMac.Length != MacAddressLength) throw new ArgumentException("MAC address must be 6 bytes.", nameof(srcMac));
            if (mtu < 1) throw new ArgumentOutOfRangeException(nameof(mtu));
            _srcMac = srcMac.ToArray();
            _send = send ?? throw new ArgumentNullException(nameof(send));
            Mtu = mtu;
            _onFrameSent = onFrameSent;
            _onFrameReceived = onFrameReceived;
        }

        /// <inheritdoc/>
        public ReadOnlyMemory<byte> LinkAddress => _srcMac;

        /// <inheritdoc/>
        public LinkMedium Medium => LinkMedium.Ethernet;

        /// <inheritdoc/>
        public int Mtu { get; }

        /// <inheritdoc/>
        public int MaxHeaderLength => EthernetHeaderLength; // tap mode carries a full Ethernet frame

        /// <inheritdoc/>
        public bool RequiresLinkAddressResolution => true; // the fabric resolves next-hop MACs via ARP

        /// <inheritdoc/>
        public event Action<ReadOnlyMemory<byte>>? InboundFrame;

        /// <inheritdoc/>
        public ValueTask WriteFrameAsync(ReadOnlyMemory<byte> ethernetFrame, CancellationToken cancellationToken = default)
        {
            if (ethernetFrame.Length < EthernetHeaderLength) return default; // too short to be an Ethernet frame
            _onFrameSent?.Invoke();
            return _send(ethernetFrame, cancellationToken);
        }

        /// <summary>Raises <see cref="InboundFrame"/> for an inbound vtun data-frame payload (a raw Ethernet frame).</summary>
        public void Deliver(ReadOnlySpan<byte> ethernetFrame)
        {
            _onFrameReceived?.Invoke();
            if (ethernetFrame.Length >= EthernetHeaderLength) InboundFrame?.Invoke(ethernetFrame.ToArray());
        }

        /// <inheritdoc/>
        public ValueTask DisposeAsync()
        {
            InboundFrame = null;
            return default;
        }
    }
}
