using System.Net;
using System.Net.Sockets;
using System.Runtime.InteropServices;
using TqkLibrary.VpnClient.Abstractions.Net;
using TqkLibrary.VpnClient.Abstractions.Transport.Interfaces;

namespace TqkLibrary.VpnClient.Drivers.Pptp.Transport
{
    /// <summary>
    /// The real PPTP control-connection byte stream: a plain <see cref="TcpClient"/> to the PAC on TCP/1723
    /// (RFC 2637 §2.1), exposed as an <see cref="IByteStreamTransport"/> for <see cref="PptpControlConnection"/>.
    /// Unlike SSTP's <c>TlsByteStream</c> this carries no TLS — the PPTP control channel is plaintext TCP.
    /// <para><see cref="ConnectAsync"/> honours its <see cref="CancellationToken"/> on both target frameworks
    /// (native overloads on net5.0+; cancel-by-dispose on netstandard2.0).</para>
    /// </summary>
    public sealed class PptpControlTcpTransport : IByteStreamTransport, IDisposable
    {
        /// <summary>The IANA-registered PPTP control-connection port (RFC 2637 §2.1).</summary>
        public const int DefaultPort = 1723;

        readonly string _host;
        readonly int _port;
        readonly AddressFamilyPreference _addressFamilyPreference;
        readonly IHostResolver _hostResolver;
        TcpClient? _tcp;
        NetworkStream? _stream;

        /// <summary>
        /// Creates a control-connection byte stream to <paramref name="host"/>:<paramref name="port"/> (not yet
        /// connected). <paramref name="addressFamilyPreference"/> selects IPv4/IPv6 when the host resolves to both;
        /// <paramref name="hostResolver"/> performs the name→address lookup (default: DNS).
        /// </summary>
        public PptpControlTcpTransport(string host, int port = DefaultPort,
            AddressFamilyPreference addressFamilyPreference = AddressFamilyPreference.Auto, IHostResolver? hostResolver = null)
        {
            _host = host ?? throw new ArgumentNullException(nameof(host));
            _port = port;
            _addressFamilyPreference = addressFamilyPreference;
            _hostResolver = hostResolver ?? DnsHostResolver.Default;
        }

        /// <inheritdoc/>
        public async ValueTask ConnectAsync(CancellationToken cancellationToken = default)
        {
            IPAddress address = await _hostResolver.ResolveAsync(_host, _addressFamilyPreference, cancellationToken).ConfigureAwait(false);
            var tcp = new TcpClient(address.AddressFamily) { NoDelay = true };
            _tcp = tcp;
#if NET5_0_OR_GREATER
            await tcp.ConnectAsync(address, _port, cancellationToken).ConfigureAwait(false);
#else
            // netstandard2.0 TcpClient.ConnectAsync has no CancellationToken overload — cancel by disposing the socket.
            using (cancellationToken.Register(() => { try { tcp.Dispose(); } catch { } }))
            {
                try { await tcp.ConnectAsync(address, _port).ConfigureAwait(false); }
                catch (Exception) when (cancellationToken.IsCancellationRequested) { }
            }
            cancellationToken.ThrowIfCancellationRequested();
#endif
            _stream = tcp.GetStream();
        }

        /// <inheritdoc/>
        public async ValueTask<int> ReadAsync(Memory<byte> buffer, CancellationToken cancellationToken = default)
        {
            NetworkStream stream = _stream ?? throw new InvalidOperationException("The PPTP control connection is not connected.");
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

        /// <inheritdoc/>
        public async ValueTask WriteAsync(ReadOnlyMemory<byte> buffer, CancellationToken cancellationToken = default)
        {
            NetworkStream stream = _stream ?? throw new InvalidOperationException("The PPTP control connection is not connected.");
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

        /// <inheritdoc/>
        public ValueTask DisposeAsync()
        {
            Dispose();
            return default;
        }

        /// <inheritdoc/>
        public void Dispose()
        {
            _stream?.Dispose();
            _tcp?.Dispose();
        }
    }
}
