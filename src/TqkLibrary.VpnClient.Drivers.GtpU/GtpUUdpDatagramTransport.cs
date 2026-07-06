using System;
using System.Net;
using System.Net.Sockets;
using System.Threading;
using System.Threading.Tasks;
using TqkLibrary.VpnClient.Abstractions.Transport.Interfaces;

namespace TqkLibrary.VpnClient.Drivers.GtpU
{
    /// <summary>
    /// A connected UDP datagram pipe over a real socket, carrying a GTP-U tunnel's inner payload. <b>Passive</b> by design:
    /// it exposes one-datagram <see cref="SendAsync"/> / <see cref="ReceiveAsync"/> but does <i>not</i> run its own receive
    /// pump — the <see cref="Abstractions.Channels.Interfaces.IPacketChannel"/> on top (a reused <c>RawIpPassthroughChannel</c>
    /// behind a <see cref="GtpUFramingTransport"/>) drives its own receive loop by calling <see cref="ReceiveAsync"/>.
    /// Supports both IPv4 and IPv6 by following the remote endpoint's <see cref="AddressFamily"/>. Mirrors the FOU driver's
    /// <c>FouUdpDatagramTransport</c>.
    /// </summary>
    internal sealed class GtpUUdpDatagramTransport : IDatagramTransport
    {
        readonly IPEndPoint _remote;
        readonly IPAddress? _localBind;
        Socket? _socket;

        /// <summary>Creates the transport for the given remote (host:port). <paramref name="localBind"/> pins the local source address (null → any).</summary>
        public GtpUUdpDatagramTransport(IPEndPoint remote, IPAddress? localBind = null)
        {
            _remote = remote ?? throw new ArgumentNullException(nameof(remote));
            _localBind = localBind;
        }

        /// <summary>Opens the UDP socket, binds an ephemeral local port and connects it to the remote (sets the default peer).</summary>
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

        /// <summary>Sends <paramref name="datagram"/> as one UDP datagram to the connected remote.</summary>
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

        /// <summary>Receives one UDP datagram into <paramref name="buffer"/>; returns its length.</summary>
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

        /// <summary>Closes the UDP socket (unblocks a pending receive on the channel's loop).</summary>
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
            // A non-array-backed Memory<byte> cannot be received into directly on netstandard2.0; the callers here
            // (RawIpPassthroughChannel / GtpUFramingTransport) always pass an array-backed buffer.
            throw new NotSupportedException("Receive buffer must be array-backed on netstandard2.0.");
        }
#endif
    }
}
