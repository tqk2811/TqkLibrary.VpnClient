namespace TqkLibrary.Vpn.Abstractions.Transport.Interfaces
{
    /// <summary>A reliable, ordered duplex byte pipe (TCP, TLS, SSH). Backs PPP-over-stream and SSL-VPN transports.</summary>
    public interface IByteStreamTransport : IAsyncDisposable
    {
        /// <summary>Establishes the underlying connection (and any TLS handshake).</summary>
        ValueTask ConnectAsync(CancellationToken cancellationToken = default);

        /// <summary>Reads up to <paramref name="buffer"/>.Length bytes; returns bytes read (0 = closed).</summary>
        ValueTask<int> ReadAsync(Memory<byte> buffer, CancellationToken cancellationToken = default);

        /// <summary>Writes all bytes of <paramref name="buffer"/>.</summary>
        ValueTask WriteAsync(ReadOnlyMemory<byte> buffer, CancellationToken cancellationToken = default);
    }
}
