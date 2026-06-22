using System;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;
using TqkLibrary.VpnClient.Abstractions.Transport.Interfaces;
using TqkLibrary.VpnClient.Ppp.Interfaces;

namespace TqkLibrary.VpnClient.Pptp.Gre
{
    /// <summary>
    /// The PPTP GRE data-plane channel (RFC 2637 §4): an <see cref="IPppFrameChannel"/> over an
    /// <see cref="IDatagramTransport"/> raw-IP proto-47 pipe. Outbound PPP frames are wrapped in an Enhanced GRE
    /// header (peer Call ID, an incrementing sequence number, and a piggy-backed acknowledgment of the highest
    /// sequence received); inbound GRE packets addressed to our local Call ID are unwrapped and surfaced as PPP
    /// frames. A dedicated receive loop (started by <see cref="Start"/>) mirrors the L2TP native-ESP loop pattern:
    /// an identity guard drops a stale loop after teardown, and disposing the transport unblocks the receive.
    /// <para>The HDLC Address/Control (<c>FF 03</c>) is stripped on send and re-prepended on receive (RFC 2637 §4.3
    /// carries the PPP frame without it); the consuming PPP engine tolerates either form.</para>
    /// </summary>
    public sealed class PptpGreChannel : IPppFrameChannel, IAsyncDisposable
    {
        readonly IDatagramTransport _transport;
        readonly ushort _localCallId;
        readonly ushort _peerCallId;
        readonly ILogger _logger;

        readonly object _gate = new object();
        CancellationTokenSource? _loopCts;
        Task? _loopTask;
        bool _disposed;

        uint _nextSeq;            // next sequence number to send (increments per payload packet, §4.4)
        uint _highestRecvSeq;     // highest sequence number received, for the piggy-backed ack
        bool _hasReceivedSeq;     // whether any payload packet has been received yet
        bool _ackPending;         // a received seq not yet acknowledged toward the peer

        /// <summary>
        /// Creates a GRE channel over <paramref name="transport"/> (a connected raw-IP proto-47 pipe).
        /// <paramref name="localCallId"/> is the Call ID the peer addresses to us (inbound filter);
        /// <paramref name="peerCallId"/> is the Call ID we stamp on outbound packets.
        /// </summary>
        public PptpGreChannel(IDatagramTransport transport, ushort localCallId, ushort peerCallId, ILogger? logger = null)
        {
            _transport = transport ?? throw new ArgumentNullException(nameof(transport));
            _localCallId = localCallId;
            _peerCallId = peerCallId;
            _logger = logger ?? NullLogger.Instance;
        }

        /// <inheritdoc/>
        public event Action<ReadOnlyMemory<byte>>? FrameReceived;

        /// <summary>Starts the inbound GRE receive loop (idempotent).</summary>
        public void Start()
        {
            lock (_gate)
            {
                if (_disposed) throw new ObjectDisposedException(nameof(PptpGreChannel));
                if (_loopTask != null) return;
                _loopCts = new CancellationTokenSource();
                _loopTask = Task.Run(() => ReceiveLoopAsync(_loopCts.Token));
            }
        }

        /// <inheritdoc/>
        public ValueTask SendAsync(ReadOnlyMemory<byte> frame, CancellationToken cancellationToken = default)
        {
            ReadOnlyMemory<byte> body = StripAddressControl(frame);

            uint seq;
            uint? ack;
            lock (_gate)
            {
                seq = _nextSeq++;
                ack = _ackPending ? _highestRecvSeq : (uint?)null;
                _ackPending = false;
            }

            var packet = new PptpGrePacket
            {
                CallId = _peerCallId,
                SequenceNumber = seq,
                AckNumber = ack,
                Payload = body,
            };
            return _transport.SendAsync(PptpGreCodec.Encode(packet), cancellationToken);
        }

        async Task ReceiveLoopAsync(CancellationToken cancellationToken)
        {
            byte[] buffer = new byte[ushort.MaxValue];
            try
            {
                while (!cancellationToken.IsCancellationRequested)
                {
                    int n = await _transport.ReceiveAsync(buffer, cancellationToken).ConfigureAwait(false);
                    // Identity guard + cancellation: drop a stale loop after teardown (the CTS we started with).
                    if (cancellationToken.IsCancellationRequested) break;
                    if (n <= 0) continue;

                    if (!PptpGreCodec.TryDecode(buffer.AsSpan(0, n), out PptpGrePacket? packet) || packet is null)
                    {
                        _logger.LogTrace("PPTP GRE: dropped a malformed packet ({Length} bytes).", n);
                        continue;
                    }
                    if (packet.CallId != _localCallId)
                    {
                        _logger.LogTrace("PPTP GRE: dropped a packet for call {CallId} (expected {Local}).", packet.CallId, _localCallId);
                        continue;
                    }

                    if (packet.SequenceNumber.HasValue && packet.Payload.Length > 0)
                    {
                        lock (_gate)
                        {
                            uint seq = packet.SequenceNumber.Value;
                            if (!_hasReceivedSeq || seq > _highestRecvSeq)
                                _highestRecvSeq = seq;
                            _hasReceivedSeq = true;
                            _ackPending = true;
                        }
                        FrameReceived?.Invoke(PrependAddressControl(packet.Payload));
                    }
                    // Ack-only packets (no sequence / empty payload) carry the peer's ack of our sends; no PPP frame to raise.
                }
            }
            catch (OperationCanceledException) { }
            catch
            {
                // The raw socket was disposed on teardown, or a receive error occurred. Do not touch shared state
                // here; a real link drop surfaces to the supervisor above via the absence of frames.
            }
        }

        // GRE carries the PPP frame without the HDLC Address/Control; strip a leading FF 03 if present.
        static ReadOnlyMemory<byte> StripAddressControl(ReadOnlyMemory<byte> frame)
        {
            ReadOnlySpan<byte> span = frame.Span;
            if (span.Length >= 2 && span[0] == 0xFF && span[1] == 0x03)
                return frame.Slice(2);
            return frame;
        }

        // Re-prepend FF 03 so the surfaced frame matches the canonical [FF 03][proto:2][info] form.
        static ReadOnlyMemory<byte> PrependAddressControl(ReadOnlyMemory<byte> body)
        {
            var framed = new byte[body.Length + 2];
            framed[0] = 0xFF;
            framed[1] = 0x03;
            body.CopyTo(framed.AsMemory(2));
            return framed;
        }

        /// <summary>Stops the receive loop and disposes the underlying transport.</summary>
        public async ValueTask DisposeAsync()
        {
            CancellationTokenSource? cts;
            Task? loop;
            lock (_gate)
            {
                if (_disposed) return;
                _disposed = true;
                cts = _loopCts;
                loop = _loopTask;
                _loopCts = null;
                _loopTask = null;
            }

            cts?.Cancel();
            // Disposing the transport unblocks a pending ReceiveAsync (the L2TP native-ESP teardown pattern).
            await _transport.DisposeAsync().ConfigureAwait(false);
            if (loop != null)
            {
                try { await loop.ConfigureAwait(false); }
                catch { /* loop teardown errors are benign */ }
            }
            cts?.Dispose();
        }
    }
}
