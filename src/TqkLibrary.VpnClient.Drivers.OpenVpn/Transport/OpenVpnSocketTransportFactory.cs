using System.Net;
using System.Net.Sockets;
using System.Runtime.InteropServices;
using TqkLibrary.VpnClient.OpenVpn;
using TqkLibrary.VpnClient.OpenVpn.Enums;
using TqkLibrary.VpnClient.OpenVpn.Transport;

namespace TqkLibrary.VpnClient.Drivers.OpenVpn.Transport
{
    /// <summary>
    /// The production <see cref="IOpenVpnTransportFactory"/>: opens a real outer socket. For <see cref="OpenVpnProtocol.Udp"/>
    /// it connects a UDP socket and wraps it in an <see cref="OpenVpnUdpTransport"/> (no framing — one datagram is one
    /// packet); for <see cref="OpenVpnProtocol.Tcp"/> it connects a raw TCP socket (OpenVPN runs TLS <em>inside</em> the
    /// control channel, not on the transport) and wraps it in an <see cref="OpenVpnTcpTransport"/> (16-bit length
    /// framing). The socket I/O is exercised live (lab Q.1); the offline tests drive the connection through an in-process
    /// factory instead.
    /// </summary>
    public sealed class OpenVpnSocketTransportFactory : IOpenVpnTransportFactory
    {
        readonly OpenVpnProtocol _protocol;

        /// <summary>Creates the factory for the given wire protocol (UDP or TCP).</summary>
        public OpenVpnSocketTransportFactory(OpenVpnProtocol protocol) => _protocol = protocol;

        /// <inheritdoc/>
        public async Task<OpenVpnTransportHandle> ConnectAsync(IPEndPoint remote, CancellationToken cancellationToken)
        {
            if (remote is null) throw new ArgumentNullException(nameof(remote));
            if (_protocol == OpenVpnProtocol.Tcp)
            {
                var stream = new TcpByteStream(remote);
                await stream.ConnectAsync(cancellationToken).ConfigureAwait(false);
                var transport = new OpenVpnTcpTransport(stream);
                return new OpenVpnTransportHandle(transport, transport.RunReceiveLoopAsync, stream);
            }
            else
            {
                var socket = new UdpDatagramSocket(remote);
                await socket.ConnectAsync(cancellationToken).ConfigureAwait(false);
                var transport = new OpenVpnUdpTransport(socket);
                return new OpenVpnTransportHandle(transport, transport.RunReceiveLoopAsync, socket);
            }
        }

        /// <summary>A connected UDP datagram pipe over a real socket (live-only; mirrors the <c>TlsByteStream</c> TFM handling).</summary>
        sealed class UdpDatagramSocket : Abstractions.Transport.Interfaces.IDatagramTransport
        {
            // Windows-only ioctl: when false, a UDP send that draws an ICMP "port unreachable" no longer makes the *next*
            // receive/send on the connected socket throw SocketException(ConnectionReset, WSAECONNRESET). Without this the
            // receive loop faults on the first spurious ICMP, the connection reconnects, the socket is disposed, and an
            // in-flight send NREs (UdpClient.Client goes null) inside a timer callback — crashing the process.
            const int SIO_UDP_CONNRESET = unchecked((int)0x9800000C);

            readonly IPEndPoint _remote;
            readonly UdpClient _client;
            readonly Socket _socket;   // captured once so a concurrent dispose can't turn UdpClient.Client into a null deref

            public UdpDatagramSocket(IPEndPoint remote)
            {
                _remote = remote;
                _client = new UdpClient(remote.AddressFamily);
                _socket = _client.Client;
            }

            public ValueTask ConnectAsync(CancellationToken cancellationToken = default)
            {
                _client.Connect(_remote); // sets the default peer; sends/receives are then connection-style
                if (RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
                {
                    // Swallow the ICMP-unreachable → ConnectionReset behaviour (best-effort; not all stacks honour it).
                    try { _socket.IOControl(SIO_UDP_CONNRESET, new byte[] { 0, 0, 0, 0 }, null); } catch { }
                }
                return default;
            }

            public ValueTask SendAsync(ReadOnlyMemory<byte> datagram, CancellationToken cancellationToken = default)
            {
#if NET5_0_OR_GREATER
                return new ValueTask(_socket.SendAsync(datagram, SocketFlags.None, cancellationToken).AsTask());
#else
                byte[] copy = datagram.ToArray();
                return new ValueTask(_client.SendAsync(copy, copy.Length)); // connected ⇒ no endpoint
#endif
            }

            public async ValueTask<int> ReceiveAsync(Memory<byte> buffer, CancellationToken cancellationToken = default)
            {
#if NET5_0_OR_GREATER
                return await _socket.ReceiveAsync(buffer, SocketFlags.None, cancellationToken).ConfigureAwait(false);
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

        /// <summary>A raw (non-TLS) TCP byte stream over a real socket — OpenVPN's <c>proto tcp</c> transport (live-only).</summary>
        sealed class TcpByteStream : Abstractions.Transport.Interfaces.IByteStreamTransport
        {
            readonly IPEndPoint _remote;
            TcpClient? _tcp;
            NetworkStream? _stream;

            public TcpByteStream(IPEndPoint remote) => _remote = remote;

            public async ValueTask ConnectAsync(CancellationToken cancellationToken = default)
            {
                var tcp = new TcpClient(_remote.AddressFamily);
                _tcp = tcp;
#if NET5_0_OR_GREATER
                await tcp.ConnectAsync(_remote.Address, _remote.Port, cancellationToken).ConfigureAwait(false);
#else
                using (cancellationToken.Register(() => { try { tcp.Dispose(); } catch { } }))
                {
                    try { await tcp.ConnectAsync(_remote.Address, _remote.Port).ConfigureAwait(false); }
                    catch (Exception) when (cancellationToken.IsCancellationRequested) { }
                }
                cancellationToken.ThrowIfCancellationRequested();
#endif
                _stream = tcp.GetStream();
            }

            public async ValueTask<int> ReadAsync(Memory<byte> buffer, CancellationToken cancellationToken = default)
            {
                NetworkStream stream = _stream ?? throw new InvalidOperationException("The TCP stream is not connected.");
#if NET5_0_OR_GREATER
                return await stream.ReadAsync(buffer, cancellationToken).ConfigureAwait(false);
#else
                if (MemoryMarshal.TryGetArray<byte>(buffer, out ArraySegment<byte> segment))
                    return await stream.ReadAsync(segment.Array!, segment.Offset, segment.Count, cancellationToken).ConfigureAwait(false);
                byte[] temp = new byte[buffer.Length];
                int read = await stream.ReadAsync(temp, 0, temp.Length, cancellationToken).ConfigureAwait(false);
                temp.AsMemory(0, read).CopyTo(buffer);
                return read;
#endif
            }

            public async ValueTask WriteAsync(ReadOnlyMemory<byte> buffer, CancellationToken cancellationToken = default)
            {
                NetworkStream stream = _stream ?? throw new InvalidOperationException("The TCP stream is not connected.");
#if NET5_0_OR_GREATER
                await stream.WriteAsync(buffer, cancellationToken).ConfigureAwait(false);
#else
                if (MemoryMarshal.TryGetArray(buffer, out ArraySegment<byte> segment))
                    await stream.WriteAsync(segment.Array!, segment.Offset, segment.Count, cancellationToken).ConfigureAwait(false);
                else
                {
                    byte[] temp = buffer.ToArray();
                    await stream.WriteAsync(temp, 0, temp.Length, cancellationToken).ConfigureAwait(false);
                }
#endif
            }

            public ValueTask DisposeAsync()
            {
                try { _stream?.Dispose(); } catch { }
                try { _tcp?.Dispose(); } catch { }
                return default;
            }
        }
    }
}
