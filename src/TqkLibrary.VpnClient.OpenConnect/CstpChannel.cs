using TqkLibrary.VpnClient.Abstractions.Channels.Enums;
using TqkLibrary.VpnClient.Abstractions.Channels.Interfaces;
using TqkLibrary.VpnClient.Abstractions.Transport.Interfaces;
using TqkLibrary.VpnClient.OpenConnect.Enums;
using TqkLibrary.VpnClient.OpenConnect.Models;

namespace TqkLibrary.VpnClient.OpenConnect
{
    /// <summary>
    /// The L3 packet channel of an established CSTP-over-TLS tunnel: a thin <see cref="IPacketChannel"/> over the TLS
    /// <see cref="IByteStreamTransport"/> framed with <see cref="CstpFraming"/>. CSTP assigns the address in-band and
    /// carries <b>bare IP packets</b> (no PPP, no link header), so <see cref="Medium"/> is <see cref="LinkMedium.Ip"/>
    /// and <see cref="MaxHeaderLength"/> is 0.
    /// <para>
    /// <see cref="WriteIpPacketAsync"/> frames the IP packet as a CSTP <see cref="CstpPacketType.Data"/> packet and
    /// writes it (serialised so concurrent sends never interleave a frame). <see cref="RunReceiveLoopAsync"/> reads the
    /// stream, reassembles whole CSTP packets across TLS read boundaries and dispatches them: DATA/COMPRESSED raise
    /// <see cref="InboundIpPacket"/>; a DPD-REQUEST raises <see cref="DpdRequestReceived"/> (the driver answers with a
    /// DPD-RESPONSE); DISCONNECT/TERMINATE raise <see cref="PeerClosed"/>. Every accepted frame fires
    /// <see cref="PacketReceived"/> and every send fires <see cref="PacketSent"/> so the driver can drive its DPD /
    /// keep-alive timers. Re-implemented from the published CSTP wire behaviour — not copied from the GPL source.
    /// </para>
    /// </summary>
    public sealed class CstpChannel : IPacketChannel
    {
        readonly IByteStreamTransport _stream;
        readonly CstpFraming _framing = new();
        readonly SemaphoreSlim _writeLock = new(1, 1);
        readonly int _readBufferSize;

        /// <summary>Wraps an established TLS byte stream. <paramref name="mtu"/> is the tunnel MTU the bound IP stack clamps to.</summary>
        public CstpChannel(IByteStreamTransport stream, int mtu, int readBufferSize = 4096)
        {
            _stream = stream ?? throw new ArgumentNullException(nameof(stream));
            if (mtu < 1) throw new ArgumentOutOfRangeException(nameof(mtu));
            if (readBufferSize < 1) throw new ArgumentOutOfRangeException(nameof(readBufferSize));
            Mtu = mtu;
            _readBufferSize = readBufferSize;
        }

        /// <inheritdoc/>
        public LinkMedium Medium => LinkMedium.Ip;

        /// <inheritdoc/>
        public int Mtu { get; }

        /// <inheritdoc/>
        public int MaxHeaderLength => 0; // CSTP carries bare IP packets — no link header

        /// <inheritdoc/>
        public bool RequiresLinkAddressResolution => false;

        /// <inheritdoc/>
        public event Action<ReadOnlyMemory<byte>>? InboundIpPacket;

        /// <summary>Raised when a DPD-REQUEST arrives; the driver must answer with a DPD-RESPONSE.</summary>
        public event Action? DpdRequestReceived;

        /// <summary>Raised when the peer sent DISCONNECT or TERMINATE — the tunnel must be torn down (and maybe reconnected).</summary>
        public event Action? PeerClosed;

        /// <summary>Raised after every accepted inbound CSTP frame (any type) — proves the peer is alive.</summary>
        public event Action? PacketReceived;

        /// <summary>Raised after every outbound CSTP frame (any type) — resets the keep-alive send timer.</summary>
        public event Action? PacketSent;

        /// <inheritdoc/>
        public ValueTask WriteIpPacketAsync(ReadOnlyMemory<byte> ipPacket, CancellationToken cancellationToken = default)
            => SendFrameAsync(CstpPacketType.Data, ipPacket, cancellationToken);

        /// <summary>Sends a CSTP DPD-REQUEST (empty payload) — the driver's DPD probe.</summary>
        public ValueTask SendDpdRequestAsync(CancellationToken cancellationToken = default)
            => SendFrameAsync(CstpPacketType.DpdRequest, ReadOnlyMemory<byte>.Empty, cancellationToken);

        /// <summary>Sends a CSTP DPD-RESPONSE (empty payload) in answer to a received DPD-REQUEST.</summary>
        public ValueTask SendDpdResponseAsync(CancellationToken cancellationToken = default)
            => SendFrameAsync(CstpPacketType.DpdResponse, ReadOnlyMemory<byte>.Empty, cancellationToken);

        /// <summary>Sends a CSTP KEEPALIVE (empty payload) — idle keep-alive so the TLS/NAT mapping does not time out.</summary>
        public ValueTask SendKeepaliveAsync(CancellationToken cancellationToken = default)
            => SendFrameAsync(CstpPacketType.KeepAlive, ReadOnlyMemory<byte>.Empty, cancellationToken);

        /// <summary>Sends a CSTP DISCONNECT (orderly client teardown) — best-effort, swallowing any write fault.</summary>
        public async ValueTask SendDisconnectAsync(CancellationToken cancellationToken = default)
        {
            try { await SendFrameAsync(CstpPacketType.Disconnect, ReadOnlyMemory<byte>.Empty, cancellationToken).ConfigureAwait(false); }
            catch { /* the stream may already be gone; teardown proceeds regardless */ }
        }

        async ValueTask SendFrameAsync(CstpPacketType type, ReadOnlyMemory<byte> payload, CancellationToken cancellationToken)
        {
            byte[] framed = CstpFraming.Encode(type, payload.Span);
            await _writeLock.WaitAsync(cancellationToken).ConfigureAwait(false);
            try { await _stream.WriteAsync(framed, cancellationToken).ConfigureAwait(false); }
            finally { _writeLock.Release(); }
            PacketSent?.Invoke();
        }

        /// <summary>
        /// Reads and dispatches CSTP packets until the stream closes (read returns 0), the peer closes the session, or
        /// cancellation. Run as a background task once the tunnel is up.
        /// </summary>
        public async Task RunReceiveLoopAsync(CancellationToken cancellationToken = default)
        {
            byte[] buffer = new byte[_readBufferSize];
            while (!cancellationToken.IsCancellationRequested)
            {
                int read = await _stream.ReadAsync(buffer, cancellationToken).ConfigureAwait(false);
                if (read <= 0) { PeerClosed?.Invoke(); return; } // the gateway closed the TLS stream
                _framing.Append(buffer.AsSpan(0, read));
                while (_framing.TryReadPacket(out CstpPacket packet))
                {
                    PacketReceived?.Invoke(); // any frame (data or control) proves the peer is alive
                    if (!Dispatch(packet)) return; // DISCONNECT/TERMINATE end the loop
                }
            }
        }

        // Returns false when the loop should stop (peer closed the session).
        bool Dispatch(CstpPacket packet)
        {
            switch (packet.Type)
            {
                case CstpPacketType.Data:
                case CstpPacketType.Compressed:
                    // V5.b is TLS-only without compression negotiation; a COMPRESSED packet would need LZS/LZ4 (future
                    // work), so only forward an uncompressed DATA payload. A compressed payload is dropped, not crashed.
                    if (packet.Type == CstpPacketType.Data && packet.Payload.Length > 0)
                        InboundIpPacket?.Invoke(packet.Payload);
                    return true;
                case CstpPacketType.DpdRequest:
                    DpdRequestReceived?.Invoke();
                    return true;
                case CstpPacketType.DpdResponse:
                case CstpPacketType.KeepAlive:
                    return true; // liveness already recorded by PacketReceived
                case CstpPacketType.Disconnect:
                case CstpPacketType.Terminate:
                    PeerClosed?.Invoke();
                    return false;
                default:
                    return true; // unknown control type — ignore, keep the tunnel up
            }
        }

        /// <inheritdoc/>
        public ValueTask DisposeAsync()
        {
            _writeLock.Dispose();
            return default;
        }
    }
}
