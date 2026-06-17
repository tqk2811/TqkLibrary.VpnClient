using TqkLibrary.VpnClient.Abstractions.Channels.Enums;
using TqkLibrary.VpnClient.Abstractions.Channels.Interfaces;
using TqkLibrary.VpnClient.WireGuard.Routing;

namespace TqkLibrary.VpnClient.WireGuard.Transport
{
    /// <summary>
    /// The L3 packet channel of a <b>multi-peer</b> WireGuard interface: a single stable <see cref="IPacketChannel"/>
    /// in front of one per-peer <see cref="WireGuardChannel"/> (one transport / one key generation each), plus the
    /// outbound crypto-routing table (<see cref="WireGuardCryptoRouter"/>). It is WireGuard's data-plane routing in
    /// userspace:
    /// <list type="bullet">
    /// <item><b>Outbound</b> (<see cref="WriteIpPacketAsync"/>): read the inner packet's destination, pick the peer
    /// by longest-prefix match, and seal/send through that peer's channel. No matching peer ⇒ the packet is dropped
    /// (reported via the supplied drop callback), exactly like the real WireGuard kernel. With a <b>single</b> peer
    /// (point-to-point) every packet goes to it regardless of destination, so no IP header is required.</item>
    /// <item><b>Inbound</b> (<see cref="Deliver"/>): a type-4 datagram carries the receiver index of the session it
    /// targets, so it is offered to each peer's channel until one accepts it (its own index + a good tag); whichever
    /// peer opens it is the peer that originated it.</item>
    /// </list>
    /// A rekey installs a fresh transport for one peer via <see cref="SetPeerChannel"/> (make-before-break — the other
    /// peers are untouched); the facade in front of this channel never rebinds. The single-peer point-to-point case is
    /// just this with one peer whose allowed-ips are <c>0.0.0.0/0, ::/0</c>.
    /// </summary>
    public sealed class WireGuardMultiPeerChannel : IPacketChannel
    {
        readonly WireGuardCryptoRouter _router;
        readonly WireGuardChannel?[] _peerChannels;       // indexed by peer index; null until that peer's handshake binds
        readonly Action<ReadOnlyMemory<byte>> _forward;   // one cached delegate so per-peer -= actually detaches
        readonly Action? _onNoRoute;                      // a packet whose destination matched no peer (logged as a drop)
        readonly object _swap = new();

        /// <summary>
        /// Creates the channel for <paramref name="peerCount"/> peers routed by <paramref name="router"/>.
        /// <paramref name="mtu"/> is the tunnel MTU the bound IP stack clamps to. <paramref name="onNoRoute"/> fires
        /// when an outbound packet's destination matches no peer's allowed-ips (the driver logs it as a drop).
        /// </summary>
        public WireGuardMultiPeerChannel(WireGuardCryptoRouter router, int peerCount, int mtu = WireGuardConstants.DefaultMtu, Action? onNoRoute = null)
        {
            _router = router ?? throw new ArgumentNullException(nameof(router));
            if (peerCount < 1) throw new ArgumentOutOfRangeException(nameof(peerCount));
            if (mtu < 1) throw new ArgumentOutOfRangeException(nameof(mtu));
            _peerChannels = new WireGuardChannel?[peerCount];
            Mtu = mtu;
            _onNoRoute = onNoRoute;
            _forward = packet => InboundIpPacket?.Invoke(packet);
        }

        /// <summary>The number of peers this channel routes across.</summary>
        public int PeerCount => _peerChannels.Length;

        /// <inheritdoc/>
        public LinkMedium Medium => LinkMedium.Ip;

        /// <inheritdoc/>
        public int Mtu { get; }

        /// <inheritdoc/>
        public int MaxHeaderLength => 0; // WireGuard transport carries bare IP packets — no link header

        /// <inheritdoc/>
        public bool RequiresLinkAddressResolution => false;

        /// <inheritdoc/>
        public event Action<ReadOnlyMemory<byte>>? InboundIpPacket;

        /// <summary>
        /// Installs (or hot-swaps, on a rekey) the live channel for peer <paramref name="peerIndex"/>. Inbound packets
        /// that peer opens are forwarded to <see cref="InboundIpPacket"/>; the previously installed channel (if any) is
        /// detached. The other peers' channels are left running (make-before-break is per-peer).
        /// </summary>
        public void SetPeerChannel(int peerIndex, WireGuardChannel channel)
        {
            if (channel is null) throw new ArgumentNullException(nameof(channel));
            if ((uint)peerIndex >= (uint)_peerChannels.Length) throw new ArgumentOutOfRangeException(nameof(peerIndex));
            lock (_swap)
            {
                WireGuardChannel? old = _peerChannels[peerIndex];
                if (old != null) old.InboundIpPacket -= _forward;
                channel.InboundIpPacket += _forward;
                _peerChannels[peerIndex] = channel;
            }
        }

        /// <inheritdoc/>
        public ValueTask WriteIpPacketAsync(ReadOnlyMemory<byte> ipPacket, CancellationToken cancellationToken = default)
        {
            int peerIndex;
            if (IpPacketDestination.TryGetDestination(ipPacket.Span, out System.Net.IPAddress destination) &&
                _router.TryRoute(destination, out peerIndex))
            {
                // matched a peer by longest-prefix on the destination
            }
            else if (_peerChannels.Length == 1)
            {
                // Single point-to-point peer: every packet goes to it regardless of destination (the full-tunnel case),
                // so we do not require a parseable IP header here. With multiple peers the destination is mandatory.
                peerIndex = 0;
            }
            else
            {
                _onNoRoute?.Invoke(); // no peer covers this destination — drop (WireGuard crypto-routing)
                return default;
            }

            WireGuardChannel? channel = Volatile.Read(ref _peerChannels[peerIndex]);
            return channel?.WriteIpPacketAsync(ipPacket, cancellationToken) ?? default; // peer not yet handshaked ⇒ drop
        }

        /// <summary>
        /// Offers an inbound type-4 datagram to each peer's channel until one accepts it (its receiver index + a good
        /// tag), returning the index of the peer that opened it, or <c>-1</c> if none did (foreign/forged/replayed).
        /// </summary>
        public int Deliver(ReadOnlySpan<byte> datagram)
        {
            WireGuardChannel?[] channels = _peerChannels;
            for (int i = 0; i < channels.Length; i++)
            {
                WireGuardChannel? channel = Volatile.Read(ref channels[i]);
                if (channel != null && channel.Deliver(datagram)) return i;
            }
            return -1;
        }

        /// <inheritdoc/>
        public ValueTask DisposeAsync()
        {
            lock (_swap)
            {
                for (int i = 0; i < _peerChannels.Length; i++)
                {
                    WireGuardChannel? channel = _peerChannels[i];
                    if (channel != null) channel.InboundIpPacket -= _forward;
                    _peerChannels[i] = null;
                }
            }
            return default;
        }
    }
}
