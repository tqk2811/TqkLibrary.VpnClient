using System.Net;
using TqkLibrary.VpnClient.Abstractions.Channels.Enums;
using TqkLibrary.VpnClient.Abstractions.Channels.Interfaces;

namespace TqkLibrary.VpnClient.Ethernet
{
    /// <summary>
    /// One virtual machine on the userspace Ethernet LAN: it owns a MAC plus a switch port (<see cref="IEthernetChannel"/>)
    /// and exposes the <see cref="IPacketChannel"/> a userspace <c>TcpIpStack</c> binds to. This is the bridge that
    /// upholds the golden rule (design 00 §5): the IP stack only ever sees bare IP packets, never Ethernet.
    /// <para>
    /// Egress (stack → wire): <see cref="Routes"/> picks the next hop (the destination when it is on-link, the default
    /// gateway when it is not), its MAC is resolved through <see cref="INeighborResolver"/> (ARP/NDISC) and the
    /// IP packet is wrapped in an Ethernet frame. Ingress (wire → stack): the 14-byte header is stripped and the payload
    /// surfaced on <see cref="IPacketChannel.InboundIpPacket"/>; non-IP frames (ARP) surface on <see cref="InboundNonIpFrame"/>
    /// for the neighbor layer (L2.3/L2.4) to handle.
    /// </para>
    /// <para>
    /// The IP version + destination are read straight from fixed header offsets (RFC 791 / RFC 8200) rather than
    /// referencing the L3 <c>IpStack</c> project — that would be a horizontal dependency the layering forbids
    /// (design 10 §2). MTU is reported as link − 14 so the bound stack clamps MSS for the Ethernet overhead.
    /// </para>
    /// </summary>
    public sealed class VirtualHost : IPacketChannel
    {
        readonly MacAddress _mac;
        readonly IEthernetChannel _port;
        readonly INeighborResolver _resolver;
        readonly int _mtu;
        bool _disposed;

        /// <summary>
        /// Attaches a host with MAC <paramref name="mac"/> to switch port <paramref name="port"/>, resolving next-hop
        /// MACs through <paramref name="resolver"/>. Subscribes to the port's inbound frames; the host owns the port
        /// and disposes it (detaching from the switch) when disposed.
        /// </summary>
        public VirtualHost(MacAddress mac, IEthernetChannel port, INeighborResolver resolver)
        {
            _mac = mac;
            _port = port ?? throw new ArgumentNullException(nameof(port));
            _resolver = resolver ?? throw new ArgumentNullException(nameof(resolver));
            _mtu = Math.Max(0, port.Mtu - EthernetFrame.HeaderLength);
            _port.InboundFrame += OnInboundFrame;
        }

        /// <summary>This host's MAC address.</summary>
        public MacAddress Mac => _mac;

        /// <summary>
        /// This host's link: the prefix it is on and the router for everything else. Starts empty, which means every
        /// destination is treated as on-link; a driver fills it from its lease (<see cref="NextHopTable.Apply"/>)
        /// once one has arrived, which is after this host is built.
        /// </summary>
        public NextHopTable Routes { get; } = new NextHopTable();

        /// <inheritdoc/>
        public LinkMedium Medium => LinkMedium.Ip;

        /// <inheritdoc/>
        public int Mtu => _mtu;

        /// <inheritdoc/>
        /// <remarks>0: the 14-byte Ethernet header is already subtracted from <see cref="Mtu"/> and is invisible to the stack.</remarks>
        public int MaxHeaderLength => 0;

        /// <inheritdoc/>
        /// <remarks>false: link-address resolution happens inside this host (egress), not in the bound stack.</remarks>
        public bool RequiresLinkAddressResolution => false;

        /// <inheritdoc/>
        public event Action<ReadOnlyMemory<byte>>? InboundIpPacket;

        /// <summary>Raised for inbound non-IP frames (e.g. ARP) — the hook the L2.3/L2.4 neighbor layer subscribes to.</summary>
        public event Action<ReadOnlyMemory<byte>>? InboundNonIpFrame;

        /// <summary>Stack → wire: resolve the next-hop MAC, wrap the packet in an Ethernet frame, hand it to the switch.</summary>
        public async ValueTask WriteIpPacketAsync(ReadOnlyMemory<byte> ipPacket, CancellationToken cancellationToken = default)
        {
            if (_disposed || ipPacket.Length < 1)
                return;

            ushort etherType;
            IPAddress destination;
            byte version = (byte)(ipPacket.Span[0] >> 4);   // IP version nibble
            if (version == 4)
            {
                if (ipPacket.Length < 20)   // minimal IPv4 header
                    return;
                etherType = EthernetFrame.EtherTypeIpv4;
                destination = new IPAddress(ipPacket.Slice(16, 4).ToArray());   // RFC 791: dst @ offset 16
            }
            else if (version == 6)
            {
                if (ipPacket.Length < 40)   // fixed IPv6 header
                    return;
                etherType = EthernetFrame.EtherTypeIpv6;
                destination = new IPAddress(ipPacket.Slice(24, 16).ToArray());   // RFC 8200: dst @ offset 24
            }
            else
            {
                return;   // not an IP packet — nothing to wrap
            }

            // Off-link destinations go to the router, not to themselves: nothing on the segment answers ARP for a
            // public address, so resolving the destination would time out and drop the packet without a word.
            IPAddress nextHop = Routes.SelectNextHop(destination);
            ReadOnlyMemory<byte>? nextHopMac = await _resolver.ResolveAsync(nextHop, cancellationToken).ConfigureAwait(false);
            if (nextHopMac is null || nextHopMac.Value.Length != MacAddress.Size)
                return;   // unresolved → drop (a real ARP/NDISC resolver queues and retries)

            byte[] frame = EthernetFrame.Build(MacAddress.FromBytes(nextHopMac.Value.Span), _mac, etherType, ipPacket.Span);
            await _port.WriteFrameAsync(frame, cancellationToken).ConfigureAwait(false);
        }

        /// <summary>Wire → stack: strip the Ethernet header and surface the payload by EtherType.</summary>
        void OnInboundFrame(ReadOnlyMemory<byte> frame)
        {
            if (frame.Length < EthernetFrame.HeaderLength)
                return;

            ushort etherType = EthernetFrame.EtherType(frame.Span);
            if (etherType == EthernetFrame.EtherTypeIpv4 || etherType == EthernetFrame.EtherTypeIpv6)
                InboundIpPacket?.Invoke(EthernetFrame.Payload(frame));   // zero-copy slice; valid only in-handler (switch raises synchronously)
            else
                InboundNonIpFrame?.Invoke(frame);
        }

        /// <inheritdoc/>
        public async ValueTask DisposeAsync()
        {
            if (_disposed)
                return;
            _disposed = true;
            _port.InboundFrame -= OnInboundFrame;
            InboundIpPacket = null;
            InboundNonIpFrame = null;
            await _port.DisposeAsync().ConfigureAwait(false);
        }
    }
}
