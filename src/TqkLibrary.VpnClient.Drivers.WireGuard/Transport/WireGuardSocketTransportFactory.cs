using System.Net;
using System.Net.Sockets;
using TqkLibrary.VpnClient.Abstractions.Transport.Interfaces;

namespace TqkLibrary.VpnClient.Drivers.WireGuard.Transport
{
    /// <summary>
    /// The production <see cref="IWireGuardTransportFactory"/>: opens a real connected UDP socket to the WireGuard
    /// endpoint. WireGuard is UDP-only — one datagram is one message, no framing — so the transport is a thin
    /// <see cref="IDatagramTransport"/> plus a receive loop that raises each datagram to the connection's handler. The
    /// socket I/O is exercised live (lab Q.1); the offline tests drive the connection through an in-process factory.
    /// Mirrors <c>OpenVpnSocketTransportFactory</c>'s <c>UdpDatagramSocket</c>.
    /// </summary>
    public sealed class WireGuardSocketTransportFactory : IWireGuardTransportFactory
    {
        readonly int _receiveBufferSize;

        /// <summary>Creates the factory. <paramref name="receiveBufferSize"/> bounds one datagram read (default 65535).</summary>
        public WireGuardSocketTransportFactory(int receiveBufferSize = 65535)
        {
            if (receiveBufferSize < 1) throw new ArgumentOutOfRangeException(nameof(receiveBufferSize));
            _receiveBufferSize = receiveBufferSize;
        }

        /// <inheritdoc/>
        public async Task<WireGuardTransportHandle> ConnectAsync(IPEndPoint remote, CancellationToken cancellationToken)
        {
            if (remote is null) throw new ArgumentNullException(nameof(remote));
            var socket = new UdpDatagramSocket(remote, _receiveBufferSize);
            await socket.ConnectAsync(cancellationToken).ConfigureAwait(false);
            return new WireGuardTransportHandle(socket, socket.SetReceiver, socket.RunReceiveLoopAsync);
        }

        /// <summary>A connected UDP datagram pipe over a real socket (live-only; mirrors the OpenVPN driver's UDP socket).</summary>
        sealed class UdpDatagramSocket : IDatagramTransport
        {
            readonly IPEndPoint _remote;
            readonly UdpClient _client;
            readonly int _receiveBufferSize;
            Action<ReadOnlyMemory<byte>>? _receiver;

            public UdpDatagramSocket(IPEndPoint remote, int receiveBufferSize)
            {
                _remote = remote;
                _receiveBufferSize = receiveBufferSize;
                _client = new UdpClient(remote.AddressFamily);
            }

            public void SetReceiver(Action<ReadOnlyMemory<byte>> receiver) => _receiver = receiver;

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

            /// <summary>Reads and dispatches datagrams to the wired handler until cancellation (UDP has no end-of-stream).</summary>
            public async Task RunReceiveLoopAsync(CancellationToken cancellationToken = default)
            {
                byte[] buffer = new byte[_receiveBufferSize];
                try
                {
                    while (!cancellationToken.IsCancellationRequested)
                    {
                        int read = await ReceiveAsync(buffer, cancellationToken).ConfigureAwait(false);
                        if (read <= 0) continue; // a 0-length datagram is not a close on UDP — keep listening
                        _receiver?.Invoke(buffer.AsSpan(0, read).ToArray());
                    }
                }
                catch (OperationCanceledException) { } // cancellation is the normal way this loop ends
            }

            public ValueTask DisposeAsync()
            {
                try { _client.Dispose(); } catch { }
                return default;
            }
        }
    }
}
