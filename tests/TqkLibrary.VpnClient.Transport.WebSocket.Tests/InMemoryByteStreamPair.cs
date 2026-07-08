using System;
using System.Threading;
using System.Threading.Channels;
using System.Threading.Tasks;
using TqkLibrary.VpnClient.Abstractions.Transport.Interfaces;

namespace TqkLibrary.VpnClient.Transport.WebSocket.Tests
{
    /// <summary>
    /// A throwaway, lossless, ordered in-memory duplex byte pipe implementing <see cref="IByteStreamTransport"/> on both
    /// ends — the byte-stream analogue of a connected socket pair. Each direction is a one-way <see cref="OneWayPipe"/>;
    /// <see cref="Endpoint.WriteAsync"/> enqueues a copied chunk that the peer's <see cref="Endpoint.ReadAsync"/> drains
    /// (returning up to the caller's buffer size, so the reassembler still sees arbitrary read boundaries). No sockets,
    /// no TLS — test scaffolding only. Adapted from the identical harness in the Transport.IpsecTcp tests.
    /// </summary>
    sealed class InMemoryByteStreamPair
    {
        public InMemoryByteStreamPair()
        {
            var clientToServer = new OneWayPipe();
            var serverToClient = new OneWayPipe();
            Client = new Endpoint(inbound: serverToClient, outbound: clientToServer);
            Server = new Endpoint(inbound: clientToServer, outbound: serverToClient);
        }

        public Endpoint Client { get; }
        public Endpoint Server { get; }

        /// <summary>One duplex end: reads its inbound pipe, writes its outbound pipe, completes outbound on dispose.</summary>
        public sealed class Endpoint : IByteStreamTransport
        {
            readonly OneWayPipe _inbound;
            readonly OneWayPipe _outbound;

            public Endpoint(OneWayPipe inbound, OneWayPipe outbound) { _inbound = inbound; _outbound = outbound; }

            public ValueTask ConnectAsync(CancellationToken cancellationToken = default) => default;

            public ValueTask<int> ReadAsync(Memory<byte> buffer, CancellationToken cancellationToken = default)
                => _inbound.ReadAsync(buffer, cancellationToken);

            public ValueTask WriteAsync(ReadOnlyMemory<byte> buffer, CancellationToken cancellationToken = default)
            {
                _outbound.Write(buffer.Span);
                return default;
            }

            public ValueTask DisposeAsync()
            {
                _outbound.Complete();   // signals EOF (ReadAsync => 0) to the peer draining this direction
                return default;
            }
        }

        /// <summary>One direction of the pipe: an unbounded queue of chunks plus a leftover slice for partial reads.</summary>
        public sealed class OneWayPipe
        {
            readonly Channel<byte[]> _channel = Channel.CreateUnbounded<byte[]>();
            ReadOnlyMemory<byte> _leftover = ReadOnlyMemory<byte>.Empty;

            public void Write(ReadOnlySpan<byte> data) => _channel.Writer.TryWrite(data.ToArray());

            public void Complete() => _channel.Writer.TryComplete();

            public async ValueTask<int> ReadAsync(Memory<byte> buffer, CancellationToken cancellationToken)
            {
                while (_leftover.IsEmpty)
                {
                    if (!await _channel.Reader.WaitToReadAsync(cancellationToken).ConfigureAwait(false))
                        return 0;   // writer completed and drained => closed
                    if (_channel.Reader.TryRead(out byte[]? chunk) && chunk!.Length > 0)
                        _leftover = chunk;
                }

                int n = Math.Min(buffer.Length, _leftover.Length);
                _leftover.Slice(0, n).CopyTo(buffer);
                _leftover = _leftover.Slice(n);
                return n;
            }
        }
    }
}
