using System;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.Logging;
using TqkLibrary.VpnClient.Abstractions.Channels.Enums;
using TqkLibrary.VpnClient.Abstractions.Channels.Interfaces;
using TqkLibrary.VpnClient.Ethernet;

namespace TqkLibrary.VpnClient.Drivers.EoGre.DataChannel
{
    /// <summary>
    /// The EoGRE / NVGRE data plane as an L2 <see cref="IEthernetChannel"/>: it carries full Ethernet frames behind a
    /// standard GRE header (protocol type 0x6558 Transparent Ethernet Bridging, RFC 2784/2890) inside a UDP payload
    /// (RFC 8086) over the UDP transport, so it plugs straight into the userspace Ethernet fabric (ARP + the
    /// <c>VirtualHost</c> bridge), which then bridges down to the IP stack — the stack never binds here directly. Because
    /// the payload is a complete Ethernet frame, <see cref="MaxHeaderLength"/> is 14 and
    /// <see cref="RequiresLinkAddressResolution"/> is true (the fabric resolves next-hop MACs via ARP).
    /// <para>
    /// Egress (<see cref="WriteFrameAsync"/>) prepends the GRE header via the reused GRE codec
    /// (<see cref="EoGreCodec.EncodeEoGre"/>) — optionally with the NVGRE VSID/FlowID Key, an RFC 2784 Checksum, and an
    /// incrementing RFC 2890 Sequence Number — and hands the datagram to the supplied <c>sink</c> (the connection's
    /// transport write, to the static remote endpoint). Ingress is push-driven: the connection's receive loop decodes
    /// inbound datagrams and calls <see cref="Deliver"/> with the recovered Ethernet frame, which raises
    /// <see cref="InboundFrame"/>. This type holds no socket itself, mirroring <c>GeneveEthernetChannel</c>.
    /// </para>
    /// </summary>
    internal sealed class EoGreEthernetChannel : IEthernetChannel
    {
        readonly uint? _vsid;
        readonly byte _flowId;
        readonly bool _includeChecksum;
        readonly bool _emitSequence;
        readonly byte[] _localMac;
        readonly Func<ReadOnlyMemory<byte>, CancellationToken, ValueTask> _sink;
        readonly ILogger? _logger;

        long _nextSequence; // next RFC 2890 Sequence Number to emit (only advanced when _emitSequence)

        /// <summary>
        /// Wires the channel. <paramref name="vsid"/> (with <paramref name="flowId"/>) stamps every outbound GRE Key when
        /// non-null (NVGRE); <paramref name="includeChecksum"/> / <paramref name="emitSequence"/> toggle the RFC 2784/2890
        /// C and S fields; <paramref name="localMac"/> is this endpoint's MAC (surfaced as <see cref="LinkAddress"/>);
        /// <paramref name="sink"/> writes the encapsulated datagram to the transport; <paramref name="mtu"/> is the tunnel MTU.
        /// </summary>
        public EoGreEthernetChannel(uint? vsid, byte flowId, bool includeChecksum, bool emitSequence, MacAddress localMac,
            Func<ReadOnlyMemory<byte>, CancellationToken, ValueTask> sink, int mtu = 1400, ILogger? logger = null)
        {
            if (vsid.HasValue && vsid.Value > EoGreCodec.MaxVsid)
                throw new ArgumentOutOfRangeException(nameof(vsid), vsid, "An NVGRE VSID is a 24-bit value (0..0xFFFFFF).");
            if (mtu < 1) throw new ArgumentOutOfRangeException(nameof(mtu));
            _vsid = vsid;
            _flowId = flowId;
            _includeChecksum = includeChecksum;
            _emitSequence = emitSequence;
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

            uint? sequence = null;
            if (_emitSequence)
                sequence = unchecked((uint)(Interlocked.Increment(ref _nextSequence) - 1));

            byte[] datagram = EoGreCodec.EncodeEoGre(ethernetFrame.Span, _vsid, _flowId, _includeChecksum, sequence);
            return _sink(datagram, cancellationToken);
        }

        /// <summary>
        /// Surfaces one inbound Ethernet frame to the fabric. The connection's receive loop calls this for each datagram it
        /// decoded (the frame already sliced out of the GRE packet). A frame too short to be an Ethernet frame is dropped.
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
