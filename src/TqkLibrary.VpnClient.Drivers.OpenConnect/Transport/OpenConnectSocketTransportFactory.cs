using System.Net;
using System.Net.Security;
using System.Net.Sockets;
using System.Runtime.InteropServices;
using System.Security.Cryptography.X509Certificates;
using TqkLibrary.VpnClient.Abstractions.Transport.Interfaces;

namespace TqkLibrary.VpnClient.Drivers.OpenConnect.Transport
{
    /// <summary>
    /// The production <see cref="IOpenConnectTransportFactory"/>: opens a real TCP socket and completes the TLS
    /// handshake, yielding the byte stream the HTTP auth/CONNECT and the CSTP tunnel ride. An optional
    /// <see cref="RemoteCertificateValidationCallback"/> validates the gateway certificate (null = accept any — the
    /// AnyConnect cookie still authorises the tunnel, but production callers should pin/validate the cert). The socket
    /// I/O is exercised live (lab Q.1, roadmap V5.b); the offline tests drive the connection through an in-process
    /// loopback factory instead. The inlined TLS stream mirrors <c>TlsByteStream</c> (roadmap F.1 will hoist a single
    /// shared <c>Transport.Tls</c> the SSTP/OpenConnect drivers both use).
    /// </summary>
    public sealed class OpenConnectSocketTransportFactory : IOpenConnectTransportFactory
    {
        readonly RemoteCertificateValidationCallback? _certificateValidationCallback;

        /// <summary>Creates the factory. <paramref name="certificateValidationCallback"/> validates the gateway cert (null = accept any).</summary>
        public OpenConnectSocketTransportFactory(RemoteCertificateValidationCallback? certificateValidationCallback = null)
            => _certificateValidationCallback = certificateValidationCallback;

        /// <inheritdoc/>
        public async Task<OpenConnectTransportHandle> ConnectAsync(string host, IPEndPoint remote, CancellationToken cancellationToken)
        {
            if (remote is null) throw new ArgumentNullException(nameof(remote));
            var stream = new TlsByteStream(host, remote, _certificateValidationCallback);
            await stream.ConnectAsync(cancellationToken).ConfigureAwait(false);
            return new OpenConnectTransportHandle(stream);
        }

        /// <summary>A TLS-over-TCP byte stream to a resolved endpoint, keeping <paramref name="_host"/> as the SNI/TargetHost (live-only).</summary>
        sealed class TlsByteStream : IByteStreamTransport
        {
            readonly string _host;
            readonly IPEndPoint _remote;
            readonly RemoteCertificateValidationCallback? _certificateValidationCallback;
            TcpClient? _tcp;
            SslStream? _ssl;

            public TlsByteStream(string host, IPEndPoint remote, RemoteCertificateValidationCallback? certificateValidationCallback)
            {
                _host = host;
                _remote = remote;
                _certificateValidationCallback = certificateValidationCallback;
            }

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
                var ssl = new SslStream(tcp.GetStream(), leaveInnerStreamOpen: false, (sender, cert, chain, errors) =>
                    _certificateValidationCallback?.Invoke(sender, cert, chain, errors) ?? true);
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

            public ValueTask DisposeAsync()
            {
                try { _ssl?.Dispose(); } catch { }
                try { _tcp?.Dispose(); } catch { }
                return default;
            }
        }
    }
}
