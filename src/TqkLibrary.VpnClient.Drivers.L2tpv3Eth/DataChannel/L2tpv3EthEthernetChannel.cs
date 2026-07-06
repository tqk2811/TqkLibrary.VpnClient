using System;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.Logging;
using TqkLibrary.VpnClient.Abstractions.Channels.Enums;
using TqkLibrary.VpnClient.Abstractions.Channels.Interfaces;
using TqkLibrary.VpnClient.Ethernet;

namespace TqkLibrary.VpnClient.Drivers.L2tpv3Eth.DataChannel
{
    /// <summary>
    /// The L2TPv3 Ethernet-pseudowire data plane as an L2 <see cref="IEthernetChannel"/>: it carries full Ethernet frames
    /// behind an L2TPv3 data header (RFC 3931 §4.1 Session ID + Cookie + optional Default L2-Specific Sublayer, RFC 4719
    /// Ethernet pseudowire) over the UDP transport, so it plugs straight into the userspace Ethernet fabric (ARP + the
    /// <c>VirtualHost</c> bridge), which then bridges down to the IP stack — the stack never binds here directly. Because the
    /// payload is a complete Ethernet frame, <see cref="MaxHeaderLength"/> is 14 and <see cref="RequiresLinkAddressResolution"/>
    /// is true (the fabric resolves next-hop MACs via ARP).
    /// <para>
    /// Egress (<see cref="WriteFrameAsync"/>) prepends the L2TPv3 data header (the configured <b>remote</b> Session ID, the
    /// shared Cookie, and — when sequencing is enabled — a 4-byte Default L2-Specific Sublayer carrying a per-channel 24-bit
    /// sequence counter) and hands the datagram to the supplied <c>sink</c> (the connection's transport write, to the static
    /// remote endpoint). Ingress is push-driven: the connection's receive loop decodes inbound datagrams and calls
    /// <see cref="Deliver"/> with the recovered Ethernet frame, which raises <see cref="InboundFrame"/>. This type holds no
    /// socket itself, mirroring <c>GeneveEthernetChannel</c>.
    /// </para>
    /// </summary>
    internal sealed class L2tpv3EthEthernetChannel : IEthernetChannel
    {
        readonly uint _remoteSessionId;
        readonly byte[] _cookie;
        readonly bool _sequencing;
        readonly byte[] _localMac;
        readonly Func<ReadOnlyMemory<byte>, CancellationToken, ValueTask> _sink;
        readonly ILogger? _logger;
        int _sequence = -1;   // Interlocked.Increment ⇒ first sent frame carries sequence 0

        /// <summary>
        /// Wires the channel. <paramref name="remoteSessionId"/> and <paramref name="cookie"/> stamp every outbound L2TPv3
        /// header; <paramref name="sequencing"/> toggles the Default L2-Specific Sublayer; <paramref name="localMac"/> is this
        /// endpoint's MAC (surfaced as <see cref="LinkAddress"/>); <paramref name="sink"/> writes the encapsulated datagram to
        /// the transport; <paramref name="mtu"/> is the tunnel MTU.
        /// </summary>
        public L2tpv3EthEthernetChannel(uint remoteSessionId, ReadOnlyMemory<byte> cookie, bool sequencing, MacAddress localMac,
            Func<ReadOnlyMemory<byte>, CancellationToken, ValueTask> sink, int mtu = 1400, ILogger? logger = null)
        {
            if (!L2tpv3DataHeader.IsValidDataSessionId(remoteSessionId))
                throw new ArgumentOutOfRangeException(nameof(remoteSessionId), remoteSessionId, "An L2TPv3 data Session ID must be non-zero and ≤ 0x7FFFFFFF.");
            if (!L2tpv3DataHeader.IsValidCookieLength(cookie.Length))
                throw new ArgumentOutOfRangeException(nameof(cookie), cookie.Length, "An L2TPv3 Cookie is 0, 4 or 8 bytes.");
            if (mtu < 1) throw new ArgumentOutOfRangeException(nameof(mtu));
            _remoteSessionId = remoteSessionId;
            _cookie = cookie.ToArray();
            _sequencing = sequencing;
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

            uint sequence = _sequencing ? (uint)(Interlocked.Increment(ref _sequence) & (int)L2tpv3DataHeader.MaxSequenceNumber) : 0;
            byte[] datagram = L2tpv3DataHeader.EncodeData(_remoteSessionId, _cookie, _sequencing, sequence, ethernetFrame.Span);
            return _sink(datagram, cancellationToken);
        }

        /// <summary>
        /// Surfaces one inbound Ethernet frame to the fabric. The connection's receive loop calls this for each L2TPv3
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
