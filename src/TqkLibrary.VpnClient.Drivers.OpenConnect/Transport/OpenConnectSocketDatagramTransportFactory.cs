using System.Net;
using System.Net.Sockets;
using TqkLibrary.VpnClient.Abstractions.Transport.Interfaces;

namespace TqkLibrary.VpnClient.Drivers.OpenConnect.Transport
{
    /// <summary>
    /// The production <see cref="IOpenConnectDatagramTransportFactory"/>: opens a real connected UDP socket to the
    /// gateway's DTLS endpoint, yielding the <b>plaintext</b> datagram pipe the connection wraps in DTLS. One datagram is
    /// one CSTP packet (no framing at this layer). The socket I/O is exercised live (lab Q.1); the offline tests drive
    /// the DTLS path through an in-process loopback factory instead. Mirrors <c>WireGuardSocketTransportFactory</c>'s
    /// <c>UdpDatagramSocket</c>.
    /// </summary>
    public sealed class OpenConnectSocketDatagramTransportFactory : IOpenConnectDatagramTransportFactory
    {
        readonly int _receiveBufferSize;

        /// <summary>Creates the factory. <paramref name="receiveBufferSize"/> bounds one datagram read (default 65535).</summary>
        public OpenConnectSocketDatagramTransportFactory(int receiveBufferSize = 65535)
        {
            if (receiveBufferSize < 1) throw new ArgumentOutOfRangeException(nameof(receiveBufferSize));
            _receiveBufferSize = receiveBufferSize;
        }

        /// <inheritdoc/>
        public async Task<IDatagramTransport> ConnectAsync(string host, IPEndPoint remote, CancellationToken cancellationToken)
        {
            if (remote is null) throw new ArgumentNullException(nameof(remote));
            var socket = new UdpDatagramSocket(remote, _receiveBufferSize);
            await socket.ConnectAsync(cancellationToken).ConfigureAwait(false);
            return socket;
        }

        /// <summary>A connected UDP datagram pipe over a real socket (live-only; mirrors the WireGuard/OpenVPN driver UDP socket).</summary>
        sealed class UdpDatagramSocket : IDatagramTransport
        {
            readonly IPEndPoint _remote;
            readonly UdpClient _client;

            public UdpDatagramSocket(IPEndPoint remote, int receiveBufferSize)
            {
                _ = receiveBufferSize; // the caller sizes its own receive buffer; kept for parity with the WireGuard socket
                _remote = remote;
                _client = new UdpClient(remote.AddressFamily);
            }

            public ValueTask ConnectAsync(CancellationToken cancellationToken = default)
            {
                _client.Connect(_remote); // sets the default peer; sends/receives are then connection-style
                return default;
            }

            public ValueTask SendAsync(ReadOnlyMemory<byte> datagram, CancellationToken cancellationToken = default)
            {
#if NET5_0_OR_GREATER
                return new ValueTask(_client.Client.SendAsync(datagram, SocketFlags.None, cancellationToken).AsTask());
#else
                byte[] copy = datagram.ToArray();
                return new ValueTask(_client.SendAsync(copy, copy.Length)); // connected ⇒ no endpoint
#endif
            }

            public async ValueTask<int> ReceiveAsync(Memory<byte> buffer, CancellationToken cancellationToken = default)
            {
#if NET5_0_OR_GREATER
                return await _client.Client.ReceiveAsync(buffer, SocketFlags.None, cancellationToken).ConfigureAwait(false);
#else
                using (cancellationToken.Register(() => { try { _client.Dispose(); } catch { } }))
                {
                    UdpReceiveResult result = await _client.ReceiveAsync().ConfigureAwait(false);
                    cancellationToken.ThrowIfCancellationRequested();
                    int n = Math.Min(result.Buffer.Length, buffer.Length);
                    result.Buffer.AsMemory(0, n).CopyTo(buffer);
                    return n;
                }
#endif
            }

            public ValueTask DisposeAsync()
            {
                try { _client.Dispose(); } catch { }
                return default;
            }
        }
    }
}
