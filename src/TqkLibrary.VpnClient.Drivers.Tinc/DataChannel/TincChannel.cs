using TqkLibrary.VpnClient.Abstractions.Channels.Enums;
using TqkLibrary.VpnClient.Abstractions.Channels.Interfaces;

namespace TqkLibrary.VpnClient.Drivers.Tinc.DataChannel
{
    /// <summary>
    /// The L3 packet channel of an established tinc data-plane session: a thin <see cref="IPacketChannel"/> over a
    /// <see cref="TincDataTransport"/>. tinc in <b>router</b> mode carries <b>bare IP packets</b> (no link header), so
    /// <see cref="Medium"/> is <see cref="LinkMedium.Ip"/> and <see cref="MaxHeaderLength"/> is 0.
    /// <para>
    /// <see cref="WriteIpPacketAsync"/> seals the inner IP packet into a UDP data datagram and hands it to the supplied
    /// <c>send</c> sink (the driver's UDP socket); <see cref="Deliver"/> opens an inbound datagram and raises
    /// <see cref="InboundIpPacket"/> with the recovered IP packet. Each outbound seal and each accepted inbound datagram
    /// is reported to the driver (so it can drive its liveness / re-key timers). Mirrors <c>NebulaChannel</c>.
    /// </para>
    /// </summary>
    public sealed class TincChannel : IPacketChannel
    {
        readonly TincDataTransport _transport;
        readonly Func<ReadOnlyMemory<byte>, CancellationToken, ValueTask> _send;
        readonly Action? _onPacketSealed;
        readonly Action? _onPacketReceived;

        /// <summary>
        /// Wraps <paramref name="transport"/>. <paramref name="send"/> puts a sealed UDP data datagram on the wire (the
        /// driver's UDP socket). <paramref name="mtu"/> is the tunnel MTU the bound IP stack clamps to.
        /// <paramref name="onPacketSealed"/>/<paramref name="onPacketReceived"/> feed the driver's liveness timers.
        /// </summary>
        public TincChannel(TincDataTransport transport,
            Func<ReadOnlyMemory<byte>, CancellationToken, ValueTask> send,
            int mtu = TincDriverConstants.DefaultMtu,
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

        /// <summary>The underlying transport (exposed so the driver can read counters for re-key decisions).</summary>
        public TincDataTransport Transport => _transport;

        /// <inheritdoc/>
        public LinkMedium Medium => LinkMedium.Ip;

        /// <inheritdoc/>
        public int Mtu { get; }

        /// <inheritdoc/>
        public int MaxHeaderLength => 0; // tinc router mode carries bare IP packets — no link header

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
        /// Opens an inbound data datagram and dispatches it by SPTPS record type: a router-mode IP packet (type 0) is
        /// raised on <see cref="InboundIpPacket"/>; a UDP probe request (<c>PKT_PROBE</c>, data[0]==0) is answered with a
        /// type-2 probe reply over the same socket so the peer can confirm bidirectional UDP (without it tinc keeps
        /// falling back to TCP). Returns <c>true</c> if the datagram authenticated for this session (so the driver can
        /// mark the peer alive), <c>false</c> if it is foreign / forged / replayed.
        /// </summary>
        public bool Deliver(ReadOnlySpan<byte> datagram)
        {
            if (!_transport.TryOpenRecord(datagram, out byte type, out byte[] payload)) return false;
            _onPacketReceived?.Invoke();

            if (type == TincDriverConstants.ProbePacketType)
            {
                HandleProbe(payload);
                return true;
            }
            if (type == TincDriverConstants.RouterPacketType && payload.Length > 0)
                InboundIpPacket?.Invoke(payload);
            return true;
        }

        // A probe with data[0]==0 is a request: reply with a type-2 probe (data[0]=2, the original length in the next
        // two bytes), padded to MIN_PROBE_SIZE, sealed back over the UDP socket. data[0]!=0 is a reply — drop.
        void HandleProbe(byte[] payload)
        {
            if (payload.Length < 1 || payload[0] != 0) return; // only answer requests
            int len = payload.Length;
            byte[] reply = new byte[Math.Max(len, TincDriverConstants.MinProbeSize)];
            reply[0] = 2; // type-2 probe reply (protocol ≥ 17.3)
            reply[1] = (byte)(len >> 8);
            reply[2] = (byte)len;
            byte[] wire = _transport.SealRecord(TincDriverConstants.ProbePacketType, reply);
            _ = _send(wire, CancellationToken.None);
        }

        /// <inheritdoc/>
        public ValueTask DisposeAsync() => default;
    }
}
