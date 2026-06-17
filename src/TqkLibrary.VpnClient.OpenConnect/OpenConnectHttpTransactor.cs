using System.Collections.Generic;
using System.Globalization;
using System.Text;
using TqkLibrary.VpnClient.Abstractions.Transport.Interfaces;
using TqkLibrary.VpnClient.OpenConnect.Models;

namespace TqkLibrary.VpnClient.OpenConnect
{
    /// <summary>
    /// Drives the OpenConnect HTTP exchanges (config-auth POSTs and the tunnel <c>CONNECT</c>) over a single
    /// <see cref="IByteStreamTransport"/> — the TLS byte stream that, after a 200 to <c>CONNECT</c>, carries the CSTP
    /// tunnel. The reader is byte-exact: it stops at the header terminator and then reads <i>exactly</i>
    /// <c>Content-Length</c> body bytes, so it never swallows the first CSTP frame that immediately follows the CONNECT
    /// response. <see cref="PostAsync"/> runs one auth request/response; <see cref="ConnectTunnelAsync"/> runs the
    /// CONNECT and returns the response (with no body) leaving the stream positioned at the start of the tunnel. I/O
    /// only — the request/response <i>codecs</i> live in <see cref="OpenConnectAuthCodec"/> / <see cref="OpenConnectConnectCodec"/>.
    /// </summary>
    public sealed class OpenConnectHttpTransactor
    {
        const string Crlf = "\r\n";

        readonly IByteStreamTransport _stream;
        readonly string _host;

        /// <summary>Wraps an established byte stream. <paramref name="host"/> is the <c>Host:</c> header value.</summary>
        public OpenConnectHttpTransactor(IByteStreamTransport stream, string host)
        {
            _stream = stream ?? throw new ArgumentNullException(nameof(stream));
            _host = string.IsNullOrEmpty(host) ? throw new ArgumentException("Host required.", nameof(host)) : host;
        }

        /// <summary>
        /// POSTs <paramref name="xmlBody"/> (a config-auth document) to <paramref name="path"/> as
        /// <c>application/x-www-form-urlencoded</c> (the content type ocserv expects for the AnyConnect auth XML) and
        /// returns the parsed response. Used for the auth handshake (init → form → reply → success).
        /// </summary>
        public async Task<OpenConnectHttpResponse> PostAsync(string path, string xmlBody, string? cookie = null,
            CancellationToken cancellationToken = default)
        {
            byte[] body = Encoding.UTF8.GetBytes(xmlBody ?? string.Empty);
            var sb = new StringBuilder();
            sb.Append("POST ").Append(path).Append(" HTTP/1.1").Append(Crlf);
            sb.Append("Host: ").Append(_host).Append(Crlf);
            sb.Append("User-Agent: ").Append(OpenConnectAuthCodec.AnyConnectVersion).Append(Crlf);
            sb.Append("Content-Type: application/x-www-form-urlencoded").Append(Crlf);
            sb.Append("X-Transcend-Version: 1").Append(Crlf);
            if (!string.IsNullOrEmpty(cookie))
                sb.Append("Cookie: ").Append(cookie!.IndexOf('=') > 0 ? cookie : "webvpn=" + cookie).Append(Crlf);
            sb.Append("Content-Length: ").Append(body.Length.ToString(CultureInfo.InvariantCulture)).Append(Crlf);
            sb.Append(Crlf);

            byte[] head = Encoding.ASCII.GetBytes(sb.ToString());
            await _stream.WriteAsync(head, cancellationToken).ConfigureAwait(false);
            if (body.Length > 0) await _stream.WriteAsync(body, cancellationToken).ConfigureAwait(false);

            return await ReadResponseAsync(readBody: true, cancellationToken).ConfigureAwait(false);
        }

        /// <summary>
        /// Sends a pre-built request line + header block (already CRLF-terminated by a blank line, e.g. from
        /// <see cref="OpenConnectConnectCodec.BuildConnectRequest"/>) and reads the response. The CONNECT response has
        /// no body, so the reader stops at the header terminator and the byte stream is left at the first CSTP frame.
        /// </summary>
        public async Task<OpenConnectHttpResponse> ConnectTunnelAsync(string requestText, CancellationToken cancellationToken = default)
        {
            byte[] request = Encoding.ASCII.GetBytes(requestText);
            await _stream.WriteAsync(request, cancellationToken).ConfigureAwait(false);
            // A successful CONNECT carries no body; only on an error status would a body be sent. We read the body only
            // when Content-Length says so, so a 200 never reads into the tunnel.
            return await ReadResponseAsync(readBody: false, cancellationToken).ConfigureAwait(false);
        }

        // Reads one HTTP response: the header block up to (and consuming) the CRLFCRLF, then exactly Content-Length
        // body bytes when present. byte-by-byte for the header so we never over-read into the tunnel stream.
        async Task<OpenConnectHttpResponse> ReadResponseAsync(bool readBody, CancellationToken cancellationToken)
        {
            string headerText = await ReadHeaderBlockAsync(cancellationToken).ConfigureAwait(false);
            string[] lines = headerText.Split(new[] { Crlf }, StringSplitOptions.None);
            if (lines.Length == 0 || lines[0].Length == 0)
                throw new FormatException("Empty HTTP response from the OpenConnect gateway.");

            (int status, string reason) = ParseStatusLine(lines[0]);
            var headers = new List<KeyValuePair<string, string>>();
            int contentLength = 0;
            bool haveLength = false;
            for (int i = 1; i < lines.Length; i++)
            {
                if (lines[i].Length == 0) continue;
                int colon = lines[i].IndexOf(':');
                if (colon <= 0) continue;
                string name = lines[i].Substring(0, colon).Trim().ToLowerInvariant();
                string value = lines[i].Substring(colon + 1).Trim();
                headers.Add(new KeyValuePair<string, string>(name, value));
                if (name == "content-length" && int.TryParse(value, NumberStyles.Integer, CultureInfo.InvariantCulture, out int cl))
                {
                    contentLength = cl;
                    haveLength = true;
                }
            }

            string body = string.Empty;
            // Read the body when a Content-Length advertises one. For CONNECT we pass readBody:false so a (rare) error
            // body is left unread — but if a length is present we still must drain it to keep the stream framed.
            if (haveLength && contentLength > 0 && (readBody || status != 200))
            {
                byte[] bodyBytes = await ReadExactAsync(contentLength, cancellationToken).ConfigureAwait(false);
                body = Encoding.UTF8.GetString(bodyBytes);
            }

            return new OpenConnectHttpResponse(status, reason, headers, headerText, body);
        }

        async Task<string> ReadHeaderBlockAsync(CancellationToken cancellationToken)
        {
            var buffer = new List<byte>(512);
            byte[] one = new byte[1];
            while (true)
            {
                int read = await _stream.ReadAsync(one, cancellationToken).ConfigureAwait(false);
                if (read <= 0) throw new IOException("The OpenConnect TLS stream closed before the HTTP header block completed.");
                buffer.Add(one[0]);
                int n = buffer.Count;
                if (n >= 4 && buffer[n - 4] == (byte)'\r' && buffer[n - 3] == (byte)'\n'
                           && buffer[n - 2] == (byte)'\r' && buffer[n - 1] == (byte)'\n')
                {
                    // Strip the trailing CRLFCRLF — the caller splits on CRLF.
                    return Encoding.ASCII.GetString(buffer.ToArray(), 0, n - 4);
                }
            }
        }

        async Task<byte[]> ReadExactAsync(int count, CancellationToken cancellationToken)
        {
            byte[] buffer = new byte[count];
            int offset = 0;
            while (offset < count)
            {
                int read = await _stream.ReadAsync(buffer.AsMemory(offset, count - offset), cancellationToken).ConfigureAwait(false);
                if (read <= 0) throw new IOException("The OpenConnect TLS stream closed mid-body.");
                offset += read;
            }
            return buffer;
        }

        static (int status, string reason) ParseStatusLine(string line)
        {
            string[] parts = line.Split(new[] { ' ' }, 3, StringSplitOptions.RemoveEmptyEntries);
            if (parts.Length < 2 || !parts[0].StartsWith("HTTP/", StringComparison.OrdinalIgnoreCase)
                || !int.TryParse(parts[1], out int code))
                throw new FormatException($"Malformed HTTP status line: '{line}'.");
            return (code, parts.Length >= 3 ? parts[2] : string.Empty);
        }
    }
}
