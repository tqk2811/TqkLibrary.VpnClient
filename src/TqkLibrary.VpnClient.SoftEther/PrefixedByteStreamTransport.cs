using TqkLibrary.VpnClient.Abstractions.Transport.Interfaces;

namespace TqkLibrary.VpnClient.SoftEther
{
    /// <summary>
    /// Wraps an <see cref="IByteStreamTransport"/> with a one-shot read <b>prefix</b>: bytes that were already pulled off
    /// the stream (by the HTTP/PACK handshake reader, which reads in chunks and can over-read past a message body into
    /// the start of the data session) are served first, then reads fall through to the inner transport.
    /// <para>
    /// This is the seam between the SoftEther control handshake and the data session: a genuine server coalesces the
    /// final <c>welcome</c> HTTP response and the first data block(s) into one TLS record, so the handshake reader
    /// inevitably buffers a few data-session bytes. Discarding them desynchronises the block reader (it then reads a
    /// frame count from the middle of a frame). Re-injecting them here keeps the byte stream contiguous.
    /// </para>
    /// Writes and connect/dispose pass straight through; only reads consult the prefix (drained left-to-right, then
    /// dropped). Not thread-safe for concurrent reads — the data session uses a single read loop per connection.
    /// </summary>
    public sealed class PrefixedByteStreamTransport : IByteStreamTransport
    {
        readonly IByteStreamTransport _inner;
        byte[] _prefix;
        int _offset;

        /// <summary>
        /// Wraps <paramref name="inner"/>, serving <paramref name="prefix"/> (copied) before any inner bytes. An empty or
        /// null prefix makes this a transparent pass-through.
        /// </summary>
        public PrefixedByteStreamTransport(IByteStreamTransport inner, ReadOnlySpan<byte> prefix)
        {
            _inner = inner ?? throw new ArgumentNullException(nameof(inner));
            _prefix = prefix.Length == 0 ? Array.Empty<byte>() : prefix.ToArray();
            _offset = 0;
        }

        /// <summary>The underlying transport this wraps (so callers can dispose/track the real connection).</summary>
        public IByteStreamTransport Inner => _inner;

        /// <inheritdoc/>
        public ValueTask ConnectAsync(CancellationToken cancellationToken = default)
            => _inner.ConnectAsync(cancellationToken);

        /// <inheritdoc/>
        public ValueTask<int> ReadAsync(Memory<byte> buffer, CancellationToken cancellationToken = default)
        {
            int remaining = _prefix.Length - _offset;
            if (remaining > 0)
            {
                int take = Math.Min(remaining, buffer.Length);
                _prefix.AsSpan(_offset, take).CopyTo(buffer.Span);
                _offset += take;
                if (_offset >= _prefix.Length)
                    _prefix = Array.Empty<byte>();   // prefix drained — let it be collected
                return new ValueTask<int>(take);
            }
            return _inner.ReadAsync(buffer, cancellationToken);
        }

        /// <inheritdoc/>
        public ValueTask WriteAsync(ReadOnlyMemory<byte> buffer, CancellationToken cancellationToken = default)
            => _inner.WriteAsync(buffer, cancellationToken);

        /// <inheritdoc/>
        public ValueTask DisposeAsync() => _inner.DisposeAsync();
    }
}
