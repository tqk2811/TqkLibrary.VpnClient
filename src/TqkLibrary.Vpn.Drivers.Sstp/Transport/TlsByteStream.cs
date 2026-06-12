using System.Net.Security;
using System.Net.Sockets;
using System.Runtime.InteropServices;
using System.Security.Cryptography.X509Certificates;
using TqkLibrary.Vpn.Abstractions.Transport.Interfaces;

namespace TqkLibrary.Vpn.Drivers.Sstp.Transport
{
    /// <summary>
    /// The real TLS-over-TCP byte stream behind <see cref="ITlsByteStream"/>: a <see cref="TcpClient"/> wrapped in an
    /// <see cref="SslStream"/>. SSTP authenticates the server through its crypto binding rather than PKI, so the TLS
    /// validation callback accepts any certificate and captures it for <see cref="RemoteCertificate"/>.
    /// <para>
    /// This is the concrete implementation of the byte-pipe seam injected into <see cref="SstpTransport"/>; a future
    /// shared <c>Transport.Tls</c> project (roadmap F.1) and a configurable certificate-validation callback
    /// (roadmap P0.6) build on it. <see cref="ConnectAsync"/> honours its <see cref="CancellationToken"/> on both
    /// target frameworks (native overloads on net8.0; cancel-by-dispose on netstandard2.0).
    /// </para>
    /// </summary>
    public sealed class TlsByteStream : ITlsByteStream, IDisposable
    {
        readonly string _host;
        readonly int _port;
        TcpClient? _tcp;
        SslStream? _ssl;

        /// <summary>Creates a TLS byte stream to <paramref name="host"/>:<paramref name="port"/> (not yet connected).</summary>
        public TlsByteStream(string host, int port = 443)
        {
            _host = host;
            _port = port;
        }

        /// <inheritdoc/>
        public X509Certificate2? RemoteCertificate { get; private set; }

        /// <inheritdoc/>
        public async ValueTask ConnectAsync(CancellationToken cancellationToken = default)
        {
            var tcp = new TcpClient();
            _tcp = tcp;
#if NET5_0_OR_GREATER
            await tcp.ConnectAsync(_host, _port, cancellationToken).ConfigureAwait(false);
#else
            // netstandard2.0 TcpClient.ConnectAsync has no CancellationToken overload — cancel by disposing the socket.
            using (cancellationToken.Register(() => { try { tcp.Dispose(); } catch { } }))
            {
                try { await tcp.ConnectAsync(_host, _port).ConfigureAwait(false); }
                catch (Exception) when (cancellationToken.IsCancellationRequested) { }
            }
            cancellationToken.ThrowIfCancellationRequested();
#endif

            // The TLS cert is authenticated by the SSTP crypto binding, not PKI, so accept it and capture it.
            var ssl = new SslStream(tcp.GetStream(), leaveInnerStreamOpen: false, (_, certificate, _, _) =>
            {
                if (certificate != null) RemoteCertificate = new X509Certificate2(certificate);
                return true;
            });
            _ssl = ssl;
#if NET5_0_OR_GREATER
            await ssl.AuthenticateAsClientAsync(new SslClientAuthenticationOptions { TargetHost = _host }, cancellationToken).ConfigureAwait(false);
#else
            using (cancellationToken.Register(() => { try { ssl.Dispose(); } catch { } }))
            {
                try { await ssl.AuthenticateAsClientAsync(_host).ConfigureAwait(false); }
                catch (Exception) when (cancellationToken.IsCancellationRequested) { }
            }
            cancellationToken.ThrowIfCancellationRequested();
#endif
        }

        /// <inheritdoc/>
        public async ValueTask<int> ReadAsync(Memory<byte> buffer, CancellationToken cancellationToken = default)
        {
            SslStream ssl = _ssl ?? throw new InvalidOperationException("The TLS stream is not connected.");
#if NET5_0_OR_GREATER
            return await ssl.ReadAsync(buffer, cancellationToken).ConfigureAwait(false);
#else
            if (MemoryMarshal.TryGetArray<byte>(buffer, out ArraySegment<byte> segment))
                return await ssl.ReadAsync(segment.Array!, segment.Offset, segment.Count, cancellationToken).ConfigureAwait(false);
            byte[] temp = new byte[buffer.Length];
            int read = await ssl.ReadAsync(temp, 0, temp.Length, cancellationToken).ConfigureAwait(false);
            temp.AsMemory(0, read).CopyTo(buffer);
            return read;
#endif
        }

        /// <inheritdoc/>
        public async ValueTask WriteAsync(ReadOnlyMemory<byte> buffer, CancellationToken cancellationToken = default)
        {
            SslStream ssl = _ssl ?? throw new InvalidOperationException("The TLS stream is not connected.");
#if NET5_0_OR_GREATER
            await ssl.WriteAsync(buffer, cancellationToken).ConfigureAwait(false);
#else
            if (MemoryMarshal.TryGetArray(buffer, out ArraySegment<byte> segment))
                await ssl.WriteAsync(segment.Array!, segment.Offset, segment.Count, cancellationToken).ConfigureAwait(false);
            else
            {
                byte[] temp = buffer.ToArray();
                await ssl.WriteAsync(temp, 0, temp.Length, cancellationToken).ConfigureAwait(false);
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
            _ssl?.Dispose();
            _tcp?.Dispose();
            RemoteCertificate?.Dispose();
        }
    }
}
