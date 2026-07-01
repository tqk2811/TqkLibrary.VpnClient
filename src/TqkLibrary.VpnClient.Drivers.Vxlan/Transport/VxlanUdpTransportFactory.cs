using System;
using System.Net;
using System.Net.Sockets;
using System.Threading;
using System.Threading.Tasks;
using TqkLibrary.VpnClient.Abstractions.Transport.Interfaces;

namespace TqkLibrary.VpnClient.Drivers.Vxlan.Transport
{
    /// <summary>
    /// The production <see cref="IVxlanTransportFactory"/>: opens a real connected UDP socket to the remote VTEP. VXLAN is
    /// UDP-only — one datagram is one message, no framing — so the transport is a thin <see cref="IDatagramTransport"/>
    /// plus a receive loop that raises each datagram to the connection's handler. It binds an ephemeral local port and
    /// connects to the remote (IPv4 or IPv6, following the endpoint's <see cref="AddressFamily"/>). The socket I/O is
    /// exercised live (lab); the offline tests drive the connection through an in-process factory. Mirrors
    /// <c>N2nSocketTransportFactory</c>.
    /// </summary>
    public sealed class VxlanUdpTransportFactory : IVxlanTransportFactory
    {
        readonly int _receiveBufferSize;
        readonly IPAddress? _localBind;

        /// <summary>
        /// Creates the factory. <paramref name="receiveBufferSize"/> bounds one datagram read (default 65535);
        /// <paramref name="localBind"/> pins the local source address (null → any of the remote's family).
        /// </summary>
        public VxlanUdpTransportFactory(int receiveBufferSize = 65535, IPAddress? localBind = null)
        {
            if (receiveBufferSize < 1) throw new ArgumentOutOfRangeException(nameof(receiveBufferSize));
            _receiveBufferSize = receiveBufferSize;
            _localBind = localBind;
        }

        /// <inheritdoc/>
        public async Task<VxlanTransportHandle> ConnectAsync(IPEndPoint remote, CancellationToken cancellationToken)
        {
            if (remote is null) throw new ArgumentNullException(nameof(remote));
            var socket = new UdpDatagramSocket(remote, _receiveBufferSize, _localBind);
            await socket.ConnectAsync(cancellationToken).ConfigureAwait(false);
            return new VxlanTransportHandle(socket, socket.SetReceiver, socket.RunReceiveLoopAsync);
        }

        /// <summary>A connected UDP datagram pipe over a real socket (live-only). Binds an ephemeral local port and
        /// connects to the remote VTEP; supports IPv4 and IPv6.</summary>
        sealed class UdpDatagramSocket : IDatagramTransport
        {
            readonly IPEndPoint _remote;
            readonly int _receiveBufferSize;
            readonly IPAddress? _localBind;
            Socket? _socket;
            Action<ReadOnlyMemory<byte>>? _receiver;

            public UdpDatagramSocket(IPEndPoint remote, int receiveBufferSize, IPAddress? localBind)
            {
                _remote = remote;
                _receiveBufferSize = receiveBufferSize;
                _localBind = localBind;
            }

            public void SetReceiver(Action<ReadOnlyMemory<byte>> receiver) => _receiver = receiver;

            public ValueTask ConnectAsync(CancellationToken cancellationToken = default)
            {
                cancellationToken.ThrowIfCancellationRequested();
                var socket = new Socket(_remote.AddressFamily, SocketType.Dgram, ProtocolType.Udp);
                try
                {
                    IPAddress bindAddress = _localBind
                        ?? (_remote.AddressFamily == AddressFamily.InterNetworkV6 ? IPAddress.IPv6Any : IPAddress.Any);
                    socket.Bind(new IPEndPoint(bindAddress, 0)); // ephemeral local port
                    socket.Connect(_remote);                     // connected ⇒ sends/receives are connection-style
                }
                catch
                {
                    socket.Dispose();
                    throw;
                }
                _socket = socket;
                return default;
            }

            public ValueTask SendAsync(ReadOnlyMemory<byte> datagram, CancellationToken cancellationToken = default)
            {
                Socket socket = _socket ?? throw new InvalidOperationException("The UDP transport is not connected.");
#if NET5_0_OR_GREATER
                return new ValueTask(socket.SendAsync(datagram, SocketFlags.None, cancellationToken).AsTask());
#else
                ArraySegment<byte> segment = GetArraySegment(datagram);
                return new ValueTask(socket.SendAsync(segment, SocketFlags.None)); // connected ⇒ no endpoint
#endif
            }

            public async ValueTask<int> ReceiveAsync(Memory<byte> buffer, CancellationToken cancellationToken = default)
            {
                Socket socket = _socket ?? throw new InvalidOperationException("The UDP transport is not connected.");
#if NET5_0_OR_GREATER
                return await socket.ReceiveAsync(buffer, SocketFlags.None, cancellationToken).ConfigureAwait(false);
#else
                ArraySegment<byte> segment = GetArraySegment(buffer);
                using (cancellationToken.Register(() => { try { socket.Dispose(); } catch { } }))
                {
                    int n = await socket.ReceiveAsync(segment, SocketFlags.None).ConfigureAwait(false);
                    cancellationToken.ThrowIfCancellationRequested();
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
                try { _socket?.Dispose(); } catch { }
                _socket = null;
                return default;
            }

#if !NET5_0_OR_GREATER
            // netstandard2.0 has no Memory<T> Send/Receive overloads: fall back to the array-backed ArraySegment path.
            static ArraySegment<byte> GetArraySegment(ReadOnlyMemory<byte> memory)
            {
                if (System.Runtime.InteropServices.MemoryMarshal.TryGetArray(memory, out ArraySegment<byte> segment))
                    return segment;
                byte[] copy = memory.ToArray();
                return new ArraySegment<byte>(copy, 0, copy.Length);
            }

            static ArraySegment<byte> GetArraySegment(Memory<byte> memory)
            {
                if (System.Runtime.InteropServices.MemoryMarshal.TryGetArray((ReadOnlyMemory<byte>)memory, out ArraySegment<byte> segment))
                    return segment;
                throw new NotSupportedException("Receive buffer must be array-backed on netstandard2.0.");
            }
#endif
        }
    }
}
