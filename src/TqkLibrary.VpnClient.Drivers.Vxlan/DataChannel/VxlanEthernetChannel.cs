using System;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.Logging;
using TqkLibrary.VpnClient.Abstractions.Channels.Enums;
using TqkLibrary.VpnClient.Abstractions.Channels.Interfaces;
using TqkLibrary.VpnClient.Ethernet;

namespace TqkLibrary.VpnClient.Drivers.Vxlan.DataChannel
{
    /// <summary>
    /// The VXLAN data plane as an L2 <see cref="IEthernetChannel"/>: it carries full Ethernet frames behind an 8-byte
    /// VXLAN header (RFC 7348) over the UDP transport, so it plugs straight into the userspace Ethernet fabric (ARP + the
    /// <c>VirtualHost</c> bridge), which then bridges down to the IP stack — the stack never binds here directly. Because
    /// the payload is a complete Ethernet frame, <see cref="MaxHeaderLength"/> is 14 and
    /// <see cref="RequiresLinkAddressResolution"/> is true (the fabric resolves next-hop MACs via ARP).
    /// <para>
    /// Egress (<see cref="WriteFrameAsync"/>) prepends the VXLAN header (with the configured VNI) and hands the datagram
    /// to the supplied <c>sink</c> (the connection's transport write, to the static remote VTEP). Ingress is push-driven:
    /// the connection's receive loop decodes inbound VXLAN datagrams and calls <see cref="Deliver"/> with the recovered
    /// Ethernet frame, which raises <see cref="InboundFrame"/>. This type holds no socket itself, mirroring
    /// <c>N2nEthernetChannel</c> — but there is no transform, no header encryption and no per-datagram control field, so
    /// egress is just a fixed 8-byte prefix.
    /// </para>
    /// </summary>
    internal sealed class VxlanEthernetChannel : IEthernetChannel
    {
        readonly uint _vni;
        readonly byte[] _localMac;
        readonly Func<ReadOnlyMemory<byte>, CancellationToken, ValueTask> _sink;
        readonly ILogger? _logger;

        /// <summary>
        /// Wires the channel. <paramref name="vni"/> stamps every outbound VXLAN header; <paramref name="localMac"/> is
        /// this endpoint's MAC (surfaced as <see cref="LinkAddress"/>); <paramref name="sink"/> writes the encapsulated
        /// datagram to the transport; <paramref name="mtu"/> is the tunnel MTU.
        /// </summary>
        public VxlanEthernetChannel(uint vni, MacAddress localMac,
            Func<ReadOnlyMemory<byte>, CancellationToken, ValueTask> sink, int mtu = 1400, ILogger? logger = null)
        {
            if (vni > VxlanCodec.MaxVni)
                throw new ArgumentOutOfRangeException(nameof(vni), vni, "A VXLAN VNI is a 24-bit value (0..0xFFFFFF).");
            if (mtu < 1) throw new ArgumentOutOfRangeException(nameof(mtu));
            _vni = vni;
            _localMac = localMac.ToArray();
            _sink = sink ?? throw new ArgumentNullException(nameof(sink));
            _logger = logger;
            Mtu = mtu;
        }

        /// <inheritdoc/>
        public ReadOnlyMemory<byte> LinkAddress => _localMac;

        /// <inheritdoc/>
        public LinkMedium Medium => LinkMedium.Ethernet;

        /// <inheritdoc/>
        public int Mtu { get; }

        /// <inheritdoc/>
        public int MaxHeaderLength => EthernetFrame.HeaderLength;

        /// <inheritdoc/>
        public bool RequiresLinkAddressResolution => true;

        /// <inheritdoc/>
        public event Action<ReadOnlyMemory<byte>>? InboundFrame;

        /// <inheritdoc/>
        public ValueTask WriteFrameAsync(ReadOnlyMemory<byte> ethernetFrame, CancellationToken cancellationToken = default)
        {
            cancellationToken.ThrowIfCancellationRequested();
            if (ethernetFrame.Length < EthernetFrame.HeaderLength) return default; // too short to be an Ethernet frame

            byte[] datagram = VxlanCodec.EncodeVxlan(_vni, ethernetFrame.Span);
            return _sink(datagram, cancellationToken);
        }

        /// <summary>
        /// Surfaces one inbound Ethernet frame to the fabric. The connection's receive loop calls this for each VXLAN
        /// datagram it decoded (the frame already sliced out of the datagram). A frame too short to be an Ethernet frame
        /// is dropped.
        /// </summary>
        public void Deliver(ReadOnlyMemory<byte> ethernetFrame)
        {
            if (ethernetFrame.Length < EthernetFrame.HeaderLength) return;
            InboundFrame?.Invoke(ethernetFrame);
        }

        /// <inheritdoc/>
        public ValueTask DisposeAsync()
        {
            InboundFrame = null;
            return default;
        }
    }
}
