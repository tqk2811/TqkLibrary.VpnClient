using TqkLibrary.VpnClient.Abstractions.Channels.Enums;
using TqkLibrary.VpnClient.Abstractions.Channels.Interfaces;
using TqkLibrary.VpnClient.WireGuard.DataChannel;

namespace TqkLibrary.VpnClient.WireGuard.Transport
{
    /// <summary>
    /// The L3 packet channel of one established WireGuard session: a thin <see cref="IPacketChannel"/> over a
    /// <see cref="WireGuardTransport"/>. WireGuard carries <b>bare IP packets</b> (no link header), so
    /// <see cref="Medium"/> is <see cref="LinkMedium.Ip"/> and <see cref="MaxHeaderLength"/> is 0.
    /// <para>
    /// <see cref="WriteIpPacketAsync"/> seals the inner IP packet into a type-4 transport datagram and hands it to the
    /// supplied <c>send</c> sink (the driver's UDP socket); <see cref="Deliver"/> opens an inbound type-4 datagram and
    /// raises <see cref="InboundIpPacket"/> with the recovered IP packet. A WireGuard keepalive opens to an empty
    /// payload — it is silently dropped, never surfaced to the IP stack. Each outbound seal and each accepted inbound
    /// datagram is reported to the driver (so it can drive the keepalive/rekey timers) via the supplied callbacks.
    /// </para>
    /// <para>
    /// One channel wraps one transport (one key generation). A rekey installs a fresh transport behind a
    /// <see cref="SwappablePacketChannel"/> at the driver level (make-before-break), so this type never mutates its
    /// keys in place — it is replaced wholesale.
    /// </para>
    /// </summary>
    public sealed class WireGuardChannel : IPacketChannel
    {
        readonly WireGuardTransport _transport;
        readonly Func<ReadOnlyMemory<byte>, CancellationToken, ValueTask> _send;
        readonly Action? _onPacketSealed;
        readonly Action? _onPacketReceived;

        /// <summary>
        /// Wraps <paramref name="transport"/>. <paramref name="send"/> puts a sealed type-4 datagram on the wire (the
        /// driver's UDP socket). <paramref name="mtu"/> is the tunnel MTU the bound IP stack clamps to.
        /// <paramref name="onPacketSealed"/> fires after every outbound seal and <paramref name="onPacketReceived"/>
        /// after every accepted inbound transport packet — the driver uses them to feed its keepalive/rekey timers.
        /// </summary>
        public WireGuardChannel(WireGuardTransport transport,
            Func<ReadOnlyMemory<byte>, CancellationToken, ValueTask> send,
            int mtu = WireGuardConstants.DefaultMtu,
            Action? onPacketSealed = null,
            Action? onPacketReceived = null)
        {
            _transport = transport ?? throw new ArgumentNullException(nameof(transport));
            _send = send ?? throw new ArgumentNullException(nameof(send));
            if (mtu < 1) throw new ArgumentOutOfRangeException(nameof(mtu));
            Mtu = mtu;
            _onPacketSealed = onPacketSealed;
            _onPacketReceived = onPacketReceived;
        }

        /// <summary>The underlying transport (exposed so the driver can read counters for rekey decisions).</summary>
        public WireGuardTransport Transport => _transport;

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

        /// <inheritdoc/>
        public ValueTask WriteIpPacketAsync(ReadOnlyMemory<byte> ipPacket, CancellationToken cancellationToken = default)
        {
            byte[] wire = _transport.Seal(ipPacket.Span); // synchronous: no span crosses the await
            _onPacketSealed?.Invoke();
            return _send(wire, cancellationToken);
        }

        /// <summary>
        /// Seals an empty payload into a keepalive type-4 datagram and sends it (whitepaper §6.5). Used by the driver's
        /// timer loop for passive/persistent keepalives.
        /// </summary>
        public ValueTask SendKeepaliveAsync(CancellationToken cancellationToken = default)
        {
            byte[] wire = _transport.Keepalive();
            _onPacketSealed?.Invoke();
            return _send(wire, cancellationToken);
        }

        /// <summary>
        /// Opens an inbound type-4 transport datagram. A data packet is raised on <see cref="InboundIpPacket"/>; a
        /// keepalive (empty payload) is dropped. Returns <c>true</c> if the datagram authenticated as a transport
        /// packet for this session (so the driver can mark the peer alive), <c>false</c> if it is foreign/forged/replayed.
        /// </summary>
        public bool Deliver(ReadOnlySpan<byte> datagram)
        {
            if (!_transport.TryOpen(datagram, out byte[] inner)) return false;
            _onPacketReceived?.Invoke();
            if (inner.Length > 0) InboundIpPacket?.Invoke(inner); // empty payload = keepalive; do not forward
            return true;
        }

        /// <inheritdoc/>
        public ValueTask DisposeAsync() => default;
    }
}
