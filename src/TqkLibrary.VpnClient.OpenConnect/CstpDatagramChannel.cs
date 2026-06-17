using TqkLibrary.VpnClient.Abstractions.Channels.Enums;
using TqkLibrary.VpnClient.Abstractions.Channels.Interfaces;
using TqkLibrary.VpnClient.Abstractions.Transport.Interfaces;
using TqkLibrary.VpnClient.OpenConnect.Enums;
using TqkLibrary.VpnClient.OpenConnect.Models;

namespace TqkLibrary.VpnClient.OpenConnect
{
    /// <summary>
    /// The L3 packet channel of an established CSTP-over-<b>DTLS</b> tunnel: the datagram twin of
    /// <see cref="CstpChannel"/>. It rides an <see cref="IDatagramTransport"/> (a <c>DtlsDatagramTransport</c> wrapping
    /// the UDP pipe) and frames each packet with <see cref="CstpDatagramFraming"/> — a single type byte, no STF magic,
    /// no length prefix, because one datagram is exactly one CSTP packet. Like <see cref="CstpChannel"/> it carries
    /// <b>bare IP packets</b> (no PPP), so <see cref="Medium"/> is <see cref="LinkMedium.Ip"/> and
    /// <see cref="MaxHeaderLength"/> is 0; it raises the same DPD / peer-close / liveness events so the driver's
    /// <see cref="CstpDpdState"/> timer logic (and its DPD reply) are shared verbatim across the TLS and DTLS paths.
    /// Re-implemented from the published CSTP/DTLS wire behaviour — not copied from the GPL source.
    /// </summary>
    public sealed class CstpDatagramChannel : IPacketChannel
    {
        readonly IDatagramTransport _transport;
        readonly SemaphoreSlim _writeLock = new(1, 1);
        readonly int _readBufferSize;
        readonly bool _ownsTransport;
        int _disposed;

        /// <summary>
        /// Wraps an established DTLS datagram <paramref name="transport"/>. <paramref name="mtu"/> is the tunnel MTU the
        /// bound IP stack clamps to. When <paramref name="ownsTransport"/> is true (the default) disposing this channel
        /// disposes the transport.
        /// </summary>
        public CstpDatagramChannel(IDatagramTransport transport, int mtu, int readBufferSize = 2048, bool ownsTransport = true)
        {
            _transport = transport ?? throw new ArgumentNullException(nameof(transport));
            if (mtu < 1) throw new ArgumentOutOfRangeException(nameof(mtu));
            if (readBufferSize < 1) throw new ArgumentOutOfRangeException(nameof(readBufferSize));
            Mtu = mtu;
            _readBufferSize = readBufferSize;
            _ownsTransport = ownsTransport;
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

        /// <summary>Raised after every accepted inbound CSTP datagram (any type) — proves the peer is alive.</summary>
        public event Action? PacketReceived;

        /// <summary>Raised after every outbound CSTP datagram (any type) — resets the keep-alive send timer.</summary>
        public event Action? PacketSent;

        /// <inheritdoc/>
        public ValueTask WriteIpPacketAsync(ReadOnlyMemory<byte> ipPacket, CancellationToken cancellationToken = default)
            => SendFrameAsync(CstpPacketType.Data, ipPacket, cancellationToken);

        /// <summary>Sends a CSTP DPD-REQUEST (type byte only) — the driver's DPD probe.</summary>
        public ValueTask SendDpdRequestAsync(CancellationToken cancellationToken = default)
            => SendFrameAsync(CstpPacketType.DpdRequest, ReadOnlyMemory<byte>.Empty, cancellationToken);

        /// <summary>Sends a CSTP DPD-RESPONSE (type byte only) in answer to a received DPD-REQUEST.</summary>
        public ValueTask SendDpdResponseAsync(CancellationToken cancellationToken = default)
            => SendFrameAsync(CstpPacketType.DpdResponse, ReadOnlyMemory<byte>.Empty, cancellationToken);

        /// <summary>Sends a CSTP KEEPALIVE (type byte only) — idle keep-alive so the DTLS/NAT mapping does not time out.</summary>
        public ValueTask SendKeepaliveAsync(CancellationToken cancellationToken = default)
            => SendFrameAsync(CstpPacketType.KeepAlive, ReadOnlyMemory<byte>.Empty, cancellationToken);

        /// <summary>Sends a CSTP DISCONNECT (orderly client teardown) — best-effort, swallowing any write fault.</summary>
        public async ValueTask SendDisconnectAsync(CancellationToken cancellationToken = default)
        {
            try { await SendFrameAsync(CstpPacketType.Disconnect, ReadOnlyMemory<byte>.Empty, cancellationToken).ConfigureAwait(false); }
            catch { /* the transport may already be gone; teardown proceeds regardless */ }
        }

        async ValueTask SendFrameAsync(CstpPacketType type, ReadOnlyMemory<byte> payload, CancellationToken cancellationToken)
        {
            byte[] framed = CstpDatagramFraming.Encode(type, payload.Span);
            await _writeLock.WaitAsync(cancellationToken).ConfigureAwait(false);
            try { await _transport.SendAsync(framed, cancellationToken).ConfigureAwait(false); }
            finally { _writeLock.Release(); }
            PacketSent?.Invoke();
        }

        /// <summary>
        /// Receives and dispatches CSTP datagrams until cancellation or the peer closes the session. Run as a background
        /// task once the DTLS tunnel is up. A datagram with a bad/empty frame is dropped (UDP is unreliable) rather than
        /// crashing the loop.
        /// </summary>
        public async Task RunReceiveLoopAsync(CancellationToken cancellationToken = default)
        {
            byte[] buffer = new byte[_readBufferSize];
            while (!cancellationToken.IsCancellationRequested)
            {
                int read;
                try { read = await _transport.ReceiveAsync(buffer, cancellationToken).ConfigureAwait(false); }
                catch (OperationCanceledException) { return; }
                if (read <= 0) continue; // a 0-length datagram is not an EOF on a datagram pipe — keep listening
                CstpPacket packet;
                try { packet = CstpDatagramFraming.Decode(buffer.AsSpan(0, read)); }
                catch (FormatException) { continue; } // malformed datagram — drop, do not desync (no stream to lose)
                PacketReceived?.Invoke(); // any frame (data or control) proves the peer is alive
                if (!Dispatch(packet)) return; // DISCONNECT/TERMINATE end the loop
            }
        }

        // Returns false when the loop should stop (peer closed the session).
        bool Dispatch(CstpPacket packet)
        {
            switch (packet.Type)
            {
                case CstpPacketType.Data:
                case CstpPacketType.Compressed:
                    // Mirror CstpChannel: compression negotiation is future work, so only forward an uncompressed DATA
                    // payload; a COMPRESSED payload is dropped, not crashed.
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
        public async ValueTask DisposeAsync()
        {
            if (Interlocked.Exchange(ref _disposed, 1) != 0) return;
            _writeLock.Dispose();
            if (_ownsTransport) await _transport.DisposeAsync().ConfigureAwait(false);
        }
    }
}
