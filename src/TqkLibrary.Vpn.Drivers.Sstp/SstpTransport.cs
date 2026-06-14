using System.Security.Cryptography.X509Certificates;
using System.Text;
using TqkLibrary.Vpn.Drivers.Sstp.Enums;
using TqkLibrary.Vpn.Drivers.Sstp.Models;
using TqkLibrary.Vpn.Drivers.Sstp.Transport;

namespace TqkLibrary.Vpn.Drivers.Sstp
{
    /// <summary>
    /// The SSTP transport: the SSTP_DUPLEX_POST HTTP handshake and framing of SSTP control/data packets over a TLS
    /// byte stream ([MS-SSTP] §2.2.1, §3). The TLS connection itself is an injected <see cref="ITlsByteStream"/>
    /// (default <see cref="TlsByteStream"/>), so the framing logic can be exercised offline over a fake stream
    /// and the TLS layer can later be shared (roadmap F.1).
    /// </summary>
    public sealed class SstpTransport : IDisposable
    {
        readonly ITlsByteStream _stream;
        readonly string _host;
        readonly TimeSpan _readTimeout;
        readonly SemaphoreSlim _writeLock = new(1, 1);

        /// <summary>
        /// Creates a transport over an explicit byte stream (the test/composition seam). <paramref name="host"/> is the
        /// value sent in the HTTP <c>Host:</c> header of the SSTP_DUPLEX_POST handshake. <paramref name="readTimeout"/>
        /// caps how long any single read may block without progress before a <see cref="TimeoutException"/> is raised
        /// (a hung server mid-handshake/data, roadmap P1.5); <c>null</c> or <see cref="Timeout.InfiniteTimeSpan"/>
        /// disables it (the default, so the framing seam tests are unaffected).
        /// </summary>
        public SstpTransport(ITlsByteStream stream, string host = "", TimeSpan? readTimeout = null)
        {
            _stream = stream ?? throw new ArgumentNullException(nameof(stream));
            _host = host ?? string.Empty;
            _readTimeout = readTimeout ?? Timeout.InfiniteTimeSpan;
        }

        /// <summary>Creates a transport over a real TLS connection to the given server.</summary>
        public SstpTransport(string host, int port = 443, TimeSpan? readTimeout = null)
            : this(new TlsByteStream(host, port), host, readTimeout)
        {
        }

        /// <summary>The server's TLS certificate (needed for the SSTP crypto binding); valid after <see cref="ConnectAsync"/>.</summary>
        public X509Certificate2? ServerCertificate => _stream.RemoteCertificate;

        /// <summary>Connects the byte stream and performs the SSTP_DUPLEX_POST handshake.</summary>
        public async Task ConnectAsync(CancellationToken cancellationToken = default)
        {
            await _stream.ConnectAsync(cancellationToken).ConfigureAwait(false);
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
            await _stream.WriteAsync(requestBytes, cancellationToken).ConfigureAwait(false);

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
                int read = await ReadWithTimeoutAsync(one, cancellationToken).ConfigureAwait(false);
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

        /// <summary>Sends an SSTP data packet carrying <paramref name="payload"/> (e.g. RAW PPP bytes).</summary>
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
                await _stream.WriteAsync(packet, cancellationToken).ConfigureAwait(false);
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
                int read = await ReadWithTimeoutAsync(buffer.AsMemory(offset, count - offset), cancellationToken).ConfigureAwait(false);
                if (read == 0) throw new IOException("Connection closed while reading an SSTP packet.");
                offset += read;
            }
            return buffer;
        }

        // Reads from the stream, capping a single no-progress wait at _readTimeout. The clock resets on every call, so
        // a multi-segment packet is bounded by "no bytes for _readTimeout" rather than "whole packet in _readTimeout".
        // A timeout is surfaced as TimeoutException so the caller can tell it apart from caller-driven cancellation
        // (which propagates unchanged) and from a clean EOF (which still returns 0).
        async ValueTask<int> ReadWithTimeoutAsync(Memory<byte> buffer, CancellationToken cancellationToken)
        {
            if (_readTimeout == Timeout.InfiniteTimeSpan)
                return await _stream.ReadAsync(buffer, cancellationToken).ConfigureAwait(false);

            using var timeoutCts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
            timeoutCts.CancelAfter(_readTimeout);
            try
            {
                return await _stream.ReadAsync(buffer, timeoutCts.Token).ConfigureAwait(false);
            }
            catch (OperationCanceledException) when (timeoutCts.IsCancellationRequested && !cancellationToken.IsCancellationRequested)
            {
                throw new TimeoutException($"No SSTP data received within {_readTimeout}.");
            }
        }

        /// <inheritdoc/>
        public void Dispose()
        {
            (_stream as IDisposable)?.Dispose();
            _writeLock.Dispose();
        }
    }
}
