using System.Net;
using System.Net.Sockets;
using Microsoft.Extensions.Logging;
using TqkLibrary.VpnClient.Abstractions.Transport.Interfaces;
using TqkLibrary.VpnClient.Transport.RawIp.Helpers;

namespace TqkLibrary.VpnClient.Transport.RawIp
{
    /// <summary>
    /// An <see cref="IDatagramTransport"/> over a raw IP socket: each datagram is one IP-protocol payload (e.g. an ESP
    /// packet starting with its SPI) carried directly on an IP protocol number with no UDP/TCP wrapper.
    /// <para><b>Send</b> hands the payload to the socket and the OS prepends the IP header (no IP_HDRINCL).
    /// <b>Receive</b> on an IPv4 raw socket gets the whole IP datagram including its header, so the header is stripped
    /// (<see cref="RawIpv4"/>); datagrams from another source are skipped and IP fragments are dropped (a raw socket may
    /// surface them un-reassembled, so the payload is incomplete). IPv6 raw delivers no header — not supported here yet.</para>
    /// <para><b>Threading:</b> the blocking socket calls run on the thread pool and poll with a short receive timeout so
    /// cancellation/teardown is honoured promptly; disposing closes the socket, which unblocks a pending receive
    /// (netstandard2.0 has no cancellable <c>ReceiveFrom</c>). One sender + one receiver at a time, like a raw socket.</para>
    /// </summary>
    public sealed class RawIpDatagramTransport : IDatagramTransport
    {
        // A full IPv4 datagram (max header 60 + payload) always fits this scratch; the receive loop owns it (single reader).
        const int ReceiveBufferSize = 65535;
        const int ReceivePollMilliseconds = 250;

        readonly Socket _socket;
        readonly IPAddress _remoteAddress;
        readonly EndPoint _remoteEndPoint;
        readonly ILogger? _logger;
        readonly byte[] _receiveScratch = new byte[ReceiveBufferSize];
        int _disposed;

        /// <summary>Wraps an already-opened raw <paramref name="socket"/> targeting <paramref name="remoteAddress"/>.</summary>
        public RawIpDatagramTransport(Socket socket, IPAddress remoteAddress, ILogger? logger = null)
        {
            _socket = socket ?? throw new ArgumentNullException(nameof(socket));
            _remoteAddress = remoteAddress ?? throw new ArgumentNullException(nameof(remoteAddress));
            _remoteEndPoint = new IPEndPoint(remoteAddress, 0);
            _logger = logger;
            try { _socket.ReceiveTimeout = ReceivePollMilliseconds; } catch { }
        }

        /// <inheritdoc/>
        public ValueTask ConnectAsync(CancellationToken cancellationToken = default)
        {
            ThrowIfDisposed();
            // Raw IP has no handshake: the socket is already open and the remote is fixed.
            return default;
        }

        /// <inheritdoc/>
        public async ValueTask SendAsync(ReadOnlyMemory<byte> datagram, CancellationToken cancellationToken = default)
        {
            ThrowIfDisposed();
            cancellationToken.ThrowIfCancellationRequested();
            byte[] copy = datagram.ToArray();
            // Send the payload only: the OS adds the IP header (protocol = the socket's protocol number).
            await Task.Run(() => _socket.SendTo(copy, 0, copy.Length, SocketFlags.None, _remoteEndPoint), cancellationToken)
                .ConfigureAwait(false);
        }

        /// <inheritdoc/>
        public async ValueTask<int> ReceiveAsync(Memory<byte> buffer, CancellationToken cancellationToken = default)
        {
            ThrowIfDisposed();
            return await Task.Run(() =>
            {
                while (true)
                {
                    cancellationToken.ThrowIfCancellationRequested();
                    EndPoint from = AnyEndPoint();
                    int received;
                    try
                    {
                        received = _socket.ReceiveFrom(_receiveScratch, 0, _receiveScratch.Length, SocketFlags.None, ref from);
                    }
                    catch (SocketException ex) when (ex.SocketErrorCode == SocketError.TimedOut)
                    {
                        continue; // poll timeout — re-check cancellation, keep waiting (a raw socket has no read deadline)
                    }
                    if (!IsFromRemote(from)) continue;           // a raw socket sees every proto packet to this host — keep the gateway's only
                    if (!TryExtractPayload(_receiveScratch.AsSpan(0, received), out ReadOnlySpan<byte> payload)) continue;
                    int n = Math.Min(payload.Length, buffer.Length);
                    payload.Slice(0, n).CopyTo(buffer.Span);
                    return n;
                }
            }, cancellationToken).ConfigureAwait(false);
        }

        EndPoint AnyEndPoint() => new IPEndPoint(
            _remoteAddress.AddressFamily == AddressFamily.InterNetworkV6 ? IPAddress.IPv6Any : IPAddress.Any, 0);

        bool IsFromRemote(EndPoint from) => from is IPEndPoint ip && ip.Address.Equals(_remoteAddress);

        // IPv4 raw receive carries the IP header: validate it, drop fragments, and return the protocol payload.
        bool TryExtractPayload(ReadOnlySpan<byte> datagram, out ReadOnlySpan<byte> payload)
        {
            payload = default;
            if (_remoteAddress.AddressFamily != AddressFamily.InterNetwork)
                return false; // IPv6 raw delivers no header — handled when v6 native ESP lands
            if (RawIpv4.IsFragment(datagram))
            {
                _logger?.LogDebug("Dropping inbound raw-IP fragment ({Length} bytes); a raw socket has no reassembly.", datagram.Length);
                return false;
            }
            int offset = RawIpv4.PayloadOffset(datagram);
            if (offset < 0) return false;
            payload = datagram.Slice(offset);
            return true;
        }

        /// <inheritdoc/>
        public ValueTask DisposeAsync()
        {
            if (Interlocked.Exchange(ref _disposed, 1) != 0) return default;
            try { _socket.Dispose(); } catch { }
            return default;
        }

        void ThrowIfDisposed()
        {
            if (Volatile.Read(ref _disposed) != 0)
                throw new ObjectDisposedException(nameof(RawIpDatagramTransport));
        }
    }
}
