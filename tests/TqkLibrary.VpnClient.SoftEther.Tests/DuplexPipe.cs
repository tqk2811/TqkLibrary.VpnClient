using System;
using System.Threading;
using System.Threading.Channels;
using System.Threading.Tasks;
using TqkLibrary.VpnClient.Abstractions.Transport.Interfaces;

namespace TqkLibrary.VpnClient.SoftEther.Tests
{
    /// <summary>
    /// An in-memory full-duplex <see cref="IByteStreamTransport"/> backed by two byte channels (one per direction). Two
    /// of these wired crosswise form a loopback pipe between two ends (client ⇄ stub server / connection ⇄ peer). A
    /// read after the writer closes returns 0 (EOF). Shared test scaffolding for the SoftEther offline suites.
    /// </summary>
    sealed class DuplexPipe : IByteStreamTransport
    {
        readonly Channel<byte[]> _inbound;
        readonly Channel<byte[]> _outbound;
        byte[] _readRemainder = Array.Empty<byte>();
        int _readOffset;

        DuplexPipe(Channel<byte[]> inbound, Channel<byte[]> outbound)
        {
            _inbound = inbound;
            _outbound = outbound;
        }

        public static (DuplexPipe client, DuplexPipe server) CreatePair()
        {
            var x = Channel.CreateUnbounded<byte[]>();
            var y = Channel.CreateUnbounded<byte[]>();
            return (new DuplexPipe(x, y), new DuplexPipe(y, x));
        }

        public ValueTask ConnectAsync(CancellationToken cancellationToken = default) => default;

        public async ValueTask<int> ReadAsync(Memory<byte> buffer, CancellationToken cancellationToken = default)
        {
            if (_readOffset >= _readRemainder.Length)
            {
                try { _readRemainder = await _inbound.Reader.ReadAsync(cancellationToken).ConfigureAwait(false); }
                catch (ChannelClosedException) { return 0; }   // peer closed → EOF
                _readOffset = 0;
            }
            int n = Math.Min(buffer.Length, _readRemainder.Length - _readOffset);
            _readRemainder.AsSpan(_readOffset, n).CopyTo(buffer.Span);
            _readOffset += n;
            return n;
        }

        public ValueTask WriteAsync(ReadOnlyMemory<byte> buffer, CancellationToken cancellationToken = default)
        {
            _outbound.Writer.TryWrite(buffer.ToArray());
            return default;
        }

        public ValueTask DisposeAsync()
        {
            _outbound.Writer.TryComplete();
            return default;
        }
    }
}
