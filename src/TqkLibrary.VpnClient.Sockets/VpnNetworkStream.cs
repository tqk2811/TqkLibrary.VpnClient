using System.IO;
using TqkLibrary.VpnClient.IpStack.Tcp;

namespace TqkLibrary.VpnClient.Sockets
{
    /// <summary>A <see cref="Stream"/> over a userspace <see cref="TcpConnection"/>, suitable for HttpClient.</summary>
    /// <remarks>
    /// The synchronous <c>Read</c>/<c>Write</c>/<c>Flush</c> block the calling thread inside <see cref="TcpConnection"/>
    /// (no async-over-sync, no thread-pool hop) and honour <see cref="ReadTimeout"/>/<see cref="WriteTimeout"/>; the async
    /// members ignore those and use their <see cref="CancellationToken"/> instead. One writer at a time (and one reader):
    /// concurrent writers may interleave bytes — the caller serialises, as with <c>NetworkStream</c>.
    /// </remarks>
    public sealed class VpnNetworkStream : Stream
    {
        readonly TcpConnection _connection;
        int _readTimeout = Timeout.Infinite;
        int _writeTimeout = Timeout.Infinite;

        internal VpnNetworkStream(TcpConnection connection) => _connection = connection;

        /// <inheritdoc/>
        public override bool CanRead => true;

        /// <inheritdoc/>
        public override bool CanWrite => true;

        /// <inheritdoc/>
        public override bool CanSeek => false;

        /// <inheritdoc/>
        public override bool CanTimeout => true;

        /// <inheritdoc/>
        /// <remarks>Milliseconds, or <see cref="Timeout.Infinite"/> (default). Applies to the synchronous <c>Read</c> only; on expiry it throws <see cref="IOException"/>.</remarks>
        public override int ReadTimeout
        {
            get => _readTimeout;
            set => _readTimeout = ValidateTimeout(value);
        }

        /// <inheritdoc/>
        /// <remarks>Milliseconds, or <see cref="Timeout.Infinite"/> (default). Applies to the synchronous <c>Write</c> only; on expiry it throws <see cref="IOException"/>.</remarks>
        public override int WriteTimeout
        {
            get => _writeTimeout;
            set => _writeTimeout = ValidateTimeout(value);
        }

        /// <inheritdoc/>
        public override long Length => throw new NotSupportedException();

        /// <inheritdoc/>
        public override long Position { get => throw new NotSupportedException(); set => throw new NotSupportedException(); }

        /// <inheritdoc/>
        public override Task<int> ReadAsync(byte[] buffer, int offset, int count, CancellationToken cancellationToken)
            => _connection.ReadAsync(buffer, offset, count, cancellationToken);

        /// <inheritdoc/>
        /// <remarks>Backpressured + error-propagating: awaits the peer window when the send buffer is full, throws <see cref="IOException"/> if the connection has faulted/closed.</remarks>
        public override Task WriteAsync(byte[] buffer, int offset, int count, CancellationToken cancellationToken)
            => _connection.SendAsync(buffer.AsMemory(offset, count), cancellationToken);

        /// <inheritdoc/>
        public override int Read(byte[] buffer, int offset, int count)
            => _connection.Read(buffer.AsSpan(offset, count), _readTimeout);

        /// <inheritdoc/>
        /// <remarks>Same backpressure and fault semantics as <see cref="WriteAsync(byte[], int, int, CancellationToken)"/>, blocking the calling thread.</remarks>
        public override void Write(byte[] buffer, int offset, int count)
            => _connection.Send(buffer.AsSpan(offset, count), _writeTimeout);

#if NETSTANDARD2_1_OR_GREATER || NETCOREAPP2_1_OR_GREATER
        /// <inheritdoc/>
        public override int Read(Span<byte> buffer) => _connection.Read(buffer, _readTimeout);

        /// <inheritdoc/>
        public override void Write(ReadOnlySpan<byte> buffer) => _connection.Send(buffer, _writeTimeout);

        /// <inheritdoc/>
        public override ValueTask<int> ReadAsync(Memory<byte> buffer, CancellationToken cancellationToken = default)
            => new ValueTask<int>(_connection.ReadAsync(buffer, cancellationToken));

        /// <inheritdoc/>
        public override ValueTask WriteAsync(ReadOnlyMemory<byte> buffer, CancellationToken cancellationToken = default)
            => new ValueTask(_connection.SendAsync(buffer, cancellationToken));
#endif

        /// <inheritdoc/>
        /// <remarks>Surfaces a pending fault (RST / give-up) to the caller without blocking; the data is already in the TCP send buffer.</remarks>
        public override void Flush() => _connection.ThrowIfNotWritable();

        /// <inheritdoc/>
        /// <remarks>Surfaces a pending fault (RST / give-up) to the caller; the data is already in the TCP send buffer, so it does not block on ACKs.</remarks>
        public override Task FlushAsync(CancellationToken cancellationToken)
            => _connection.SendAsync(ReadOnlyMemory<byte>.Empty, cancellationToken);

        /// <inheritdoc/>
        public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();

        /// <inheritdoc/>
        public override void SetLength(long value) => throw new NotSupportedException();

        /// <summary>
        /// Ends the connection immediately with an RST, instead of the half-close
        /// <see cref="Stream.Dispose()"/> performs.
        /// </summary>
        /// <remarks>
        /// Disposing sends a FIN, which only says we have finished sending. A peer that is not
        /// finished — or simply has nothing more to say — never answers with its own, and the
        /// connection sits in FIN-WAIT-2 holding a port and a receive queue inside the tunnel. A
        /// caller abandoning a request (a cancelled download, a browser closing a tab) should say
        /// so with this: the peer frees its side too.
        /// </remarks>
        public void Abort() => _connection.Abort();

        /// <inheritdoc/>
        protected override void Dispose(bool disposing)
        {
            if (disposing) _connection.CloseSend();
            base.Dispose(disposing);
        }

        // Same rule as NetworkStream: a positive number of milliseconds, or Timeout.Infinite.
        static int ValidateTimeout(int value)
        {
            if (value <= 0 && value != Timeout.Infinite)
                throw new ArgumentOutOfRangeException(nameof(value), "Timeout must be positive or Timeout.Infinite.");
            return value;
        }
    }
}
