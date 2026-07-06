using System;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.Logging;
using TqkLibrary.VpnClient.Abstractions.Channels.Enums;
using TqkLibrary.VpnClient.Abstractions.Channels.Interfaces;
using TqkLibrary.VpnClient.Ethernet;

namespace TqkLibrary.VpnClient.Drivers.VxlanGpe.DataChannel
{
    /// <summary>
    /// The VXLAN-GPE data plane as an L2 <see cref="IEthernetChannel"/>: it carries full Ethernet frames behind an 8-byte
    /// VXLAN-GPE header (draft-ietf-nvo3-vxlan-gpe, Next Protocol 0x03 Ethernet) over the UDP transport, so it plugs
    /// straight into the userspace Ethernet fabric (ARP + the <c>VirtualHost</c> bridge), which then bridges down to the IP
    /// stack — the stack never binds here directly. Because the payload is a complete Ethernet frame,
    /// <see cref="MaxHeaderLength"/> is 14 and <see cref="RequiresLinkAddressResolution"/> is true (the fabric resolves
    /// next-hop MACs via ARP).
    /// <para>
    /// Egress (<see cref="WriteFrameAsync"/>) prepends the VXLAN-GPE header (with the configured VNI and Next Protocol) and
    /// hands the datagram to the supplied <c>sink</c> (the connection's transport write, to the static remote peer). Ingress
    /// is push-driven: the connection's receive loop decodes inbound VXLAN-GPE datagrams and calls <see cref="Deliver"/>
    /// with the recovered Ethernet frame, which raises <see cref="InboundFrame"/>. This type holds no socket itself,
    /// mirroring <c>VxlanEthernetChannel</c> — but the emitted header sets the P (Next-Protocol-present) bit and stamps the
    /// configured Next Protocol byte (default Ethernet).
    /// </para>
    /// </summary>
    internal sealed class VxlanGpeEthernetChannel : IEthernetChannel
    {
        readonly uint _vni;
        readonly byte _nextProtocol;
        readonly byte[] _localMac;
        readonly Func<ReadOnlyMemory<byte>, CancellationToken, ValueTask> _sink;
        readonly ILogger? _logger;

        /// <summary>
        /// Wires the channel. <paramref name="vni"/> stamps every outbound VXLAN-GPE header; <paramref name="nextProtocol"/>
        /// is the header Next Protocol byte (default <see cref="VxlanGpeHeader.NextProtocolEthernet"/>);
        /// <paramref name="localMac"/> is this endpoint's MAC (surfaced as <see cref="LinkAddress"/>);
        /// <paramref name="sink"/> writes the encapsulated datagram to the transport; <paramref name="mtu"/> is the tunnel MTU.
        /// </summary>
        public VxlanGpeEthernetChannel(uint vni, byte nextProtocol, MacAddress localMac,
            Func<ReadOnlyMemory<byte>, CancellationToken, ValueTask> sink, int mtu = 1400, ILogger? logger = null)
        {
            if (vni > VxlanGpeHeader.MaxVni)
                throw new ArgumentOutOfRangeException(nameof(vni), vni, "A VXLAN-GPE VNI is a 24-bit value (0..0xFFFFFF).");
            if (mtu < 1) throw new ArgumentOutOfRangeException(nameof(mtu));
            _vni = vni;
            _nextProtocol = nextProtocol;
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

            byte[] datagram = VxlanGpeHeader.EncodeVxlanGpe(_vni, _nextProtocol, ethernetFrame.Span);
            return _sink(datagram, cancellationToken);
        }

        /// <summary>
        /// Surfaces one inbound Ethernet frame to the fabric. The connection's receive loop calls this for each VXLAN-GPE
        /// datagram it decoded (the frame already sliced out of the datagram). A frame too short to be an Ethernet frame is
        /// dropped.
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
