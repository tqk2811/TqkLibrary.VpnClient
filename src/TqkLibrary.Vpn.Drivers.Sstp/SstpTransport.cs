using System.Net.Security;
using System.Net.Sockets;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using TqkLibrary.Vpn.Drivers.Sstp.Enums;
using TqkLibrary.Vpn.Drivers.Sstp.Models;

namespace TqkLibrary.Vpn.Drivers.Sstp
{
    /// <summary>
    /// The SSTP transport: a TLS connection to the server, the SSTP_DUPLEX_POST HTTP handshake, and framing
    /// of SSTP control/data packets over the TLS stream ([MS-SSTP] §2.2.1, §3).
    /// </summary>
    public sealed class SstpTransport : IDisposable
    {
        readonly string _host;
        readonly int _port;
        readonly SemaphoreSlim _writeLock = new(1, 1);
        TcpClient? _tcp;
        SslStream? _ssl;

        /// <summary>Creates a transport for the given server.</summary>
        public SstpTransport(string host, int port = 443)
        {
            _host = host;
            _port = port;
        }

        /// <summary>The server's TLS certificate (needed for the SSTP crypto binding).</summary>
        public X509Certificate2? ServerCertificate { get; private set; }

        /// <summary>Connects TCP+TLS and performs the SSTP_DUPLEX_POST handshake.</summary>
        public async Task ConnectAsync(CancellationToken cancellationToken = default)
        {
            _tcp = new TcpClient();
            await _tcp.ConnectAsync(_host, _port).ConfigureAwait(false);

            // The TLS cert is authenticated by the SSTP crypto binding, not PKI, so accept it and capture it.
            _ssl = new SslStream(_tcp.GetStream(), leaveInnerStreamOpen: false, (_, certificate, _, _) =>
            {
                if (certificate != null) ServerCertificate = new X509Certificate2(certificate);
                return true;
            });
            await _ssl.AuthenticateAsClientAsync(_host).ConfigureAwait(false);

            await PerformHttpHandshakeAsync(cancellationToken).ConfigureAwait(false);
        }

        async Task PerformHttpHandshakeAsync(CancellationToken cancellationToken)
        {
            string request =
                $"SSTP_DUPLEX_POST {SstpConstants.DuplexUri} HTTP/1.1\r\n" +
                $"Host: {_host}\r\n" +
                $"SSTPCORRELATIONID: {{{Guid.NewGuid():D}}}\r\n" +
                "Content-Length: 18446744073709551615\r\n" +
                "\r\n";
            byte[] requestBytes = Encoding.ASCII.GetBytes(request);
            await _ssl!.WriteAsync(requestBytes, 0, requestBytes.Length, cancellationToken).ConfigureAwait(false);

            string statusLine = await ReadHttpHeadersAsync(cancellationToken).ConfigureAwait(false);
            if (statusLine.IndexOf(" 200", StringComparison.Ordinal) < 0)
                throw new InvalidOperationException($"SSTP handshake rejected: '{statusLine}'.");
        }

        async Task<string> ReadHttpHeadersAsync(CancellationToken cancellationToken)
        {
            var buffer = new List<byte>(256);
            byte[] one = new byte[1];
            while (true)
            {
                int read = await _ssl!.ReadAsync(one, 0, 1, cancellationToken).ConfigureAwait(false);
                if (read == 0) throw new IOException("Connection closed during SSTP HTTP handshake.");
                buffer.Add(one[0]);
                int n = buffer.Count;
                if (n >= 4 && buffer[n - 4] == 0x0D && buffer[n - 3] == 0x0A && buffer[n - 2] == 0x0D && buffer[n - 1] == 0x0A)
                    break;
            }
            string headers = Encoding.ASCII.GetString(buffer.ToArray());
            int eol = headers.IndexOf("\r\n", StringComparison.Ordinal);
            return eol >= 0 ? headers.Substring(0, eol) : headers;
        }

        /// <summary>Sends an SSTP control message.</summary>
        public Task SendControlAsync(SstpMessageType type, IReadOnlyList<SstpAttribute> attributes, CancellationToken cancellationToken = default)
        {
            byte[] body = SstpControlCodec.BuildBody(type, attributes);
            return SendPacketAsync(control: true, body, cancellationToken);
        }

        /// <summary>Sends an SSTP data packet carrying <paramref name="payload"/> (e.g. HDLC-framed PPP bytes).</summary>
        public Task SendDataAsync(ReadOnlyMemory<byte> payload, CancellationToken cancellationToken = default)
            => SendPacketAsync(control: false, payload, cancellationToken);

        async Task SendPacketAsync(bool control, ReadOnlyMemory<byte> body, CancellationToken cancellationToken)
        {
            int length = 4 + body.Length;
            byte[] packet = new byte[length];
            packet[0] = SstpConstants.Version;
            packet[1] = (byte)(control ? 0x01 : 0x00);
            packet[2] = (byte)((length >> 8) & 0x0F);
            packet[3] = (byte)(length & 0xff);
            body.Span.CopyTo(packet.AsSpan(4));

            await _writeLock.WaitAsync(cancellationToken).ConfigureAwait(false);
            try
            {
                await _ssl!.WriteAsync(packet, 0, packet.Length, cancellationToken).ConfigureAwait(false);
            }
            finally
            {
                _writeLock.Release();
            }
        }

        /// <summary>Reads one SSTP packet; returns whether it is a control packet and its body (after the 4-byte header).</summary>
        public async Task<(bool isControl, byte[] body)> ReadPacketAsync(CancellationToken cancellationToken = default)
        {
            byte[] header = await ReadExactlyAsync(4, cancellationToken).ConfigureAwait(false);
            bool isControl = (header[1] & 0x01) != 0;
            int length = ((header[2] & 0x0F) << 8) | header[3];
            int bodyLength = length - 4;
            byte[] body = bodyLength > 0 ? await ReadExactlyAsync(bodyLength, cancellationToken).ConfigureAwait(false) : Array.Empty<byte>();
            return (isControl, body);
        }

        async Task<byte[]> ReadExactlyAsync(int count, CancellationToken cancellationToken)
        {
            byte[] buffer = new byte[count];
            int offset = 0;
            while (offset < count)
            {
                int read = await _ssl!.ReadAsync(buffer, offset, count - offset, cancellationToken).ConfigureAwait(false);
                if (read == 0) throw new IOException("Connection closed while reading an SSTP packet.");
                offset += read;
            }
            return buffer;
        }

        /// <inheritdoc/>
        public void Dispose()
        {
            _ssl?.Dispose();
            _tcp?.Dispose();
            ServerCertificate?.Dispose();
            _writeLock.Dispose();
        }
    }
}
