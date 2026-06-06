namespace TqkLibrary.Vpn.Abstractions.Transport.Interfaces
{
    /// <summary>
    /// An unreliable datagram pipe (UDP). Each send/receive is one datagram with preserved boundaries.
    /// The <c>EspIkeDemuxTransport</c> decorator splits IKE vs ESP on UDP/4500 (RFC 3948).
    /// </summary>
    public interface IDatagramTransport : IAsyncDisposable
    {
        /// <summary>Binds the local (ephemeral) socket and resolves the remote endpoint.</summary>
        ValueTask ConnectAsync(CancellationToken cancellationToken = default);

        /// <summary>Receives one datagram into <paramref name="buffer"/>; returns its length.</summary>
        ValueTask<int> ReceiveAsync(Memory<byte> buffer, CancellationToken cancellationToken = default);

        /// <summary>Sends <paramref name="datagram"/> as one datagram.</summary>
        ValueTask SendAsync(ReadOnlyMemory<byte> datagram, CancellationToken cancellationToken = default);
    }
}
