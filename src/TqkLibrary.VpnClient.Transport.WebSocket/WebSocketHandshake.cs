using System.Security.Cryptography;
using System.Text;

namespace TqkLibrary.VpnClient.Transport.WebSocket
{
    /// <summary>
    /// Stateless helpers for the RFC 6455 §4 opening handshake — the HTTP/1.1 Upgrade exchange that precedes framing.
    /// Re-implemented from the RFC (not copied from any GPL/AGPL source).
    /// <para>
    /// A client sends a <c>GET</c> request carrying <c>Upgrade: websocket</c>, <c>Connection: Upgrade</c>, a random
    /// 16-byte <c>Sec-WebSocket-Key</c> (base64) and <c>Sec-WebSocket-Version: 13</c> (§1.3/§4.1). The server replies
    /// <c>101 Switching Protocols</c> with <c>Sec-WebSocket-Accept</c> = <c>base64(SHA1(key ‖ "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"))</c>
    /// (§4.2.2). The §1.3 worked example: key <c>dGhlIHNhbXBsZSBub25jZQ==</c> ⇒ accept <c>s3pPLMBiTxaQ9kYGzzhZRbK+xOo=</c>.
    /// </para>
    /// </summary>
    public static class WebSocketHandshake
    {
        /// <summary>The RFC 6455 §1.3 magic GUID concatenated with the client key before hashing.</summary>
        public const string AcceptGuid = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";

        /// <summary>
        /// Computes the RFC 6455 §4.2.2 <c>Sec-WebSocket-Accept</c> value for a given client
        /// <paramref name="secWebSocketKey"/>: <c>base64(SHA1(key ‖ AcceptGuid))</c>. SHA-1 and Base64 come from the BCL,
        /// so the result is identical on both target frameworks.
        /// </summary>
        public static string ComputeAccept(string secWebSocketKey)
        {
            if (secWebSocketKey is null) throw new ArgumentNullException(nameof(secWebSocketKey));
            byte[] input = Encoding.ASCII.GetBytes(secWebSocketKey + AcceptGuid);
            using SHA1 sha1 = SHA1.Create();
            byte[] hash = sha1.ComputeHash(input);
            return Convert.ToBase64String(hash);
        }

        /// <summary>
        /// Builds the client's HTTP/1.1 Upgrade request bytes (ASCII, CRLF-terminated) for
        /// <paramref name="host"/> and resource <paramref name="path"/> (empty ⇒ <c>"/"</c>), carrying
        /// <paramref name="secWebSocketKey"/> and, when supplied, a <paramref name="subProtocol"/>
        /// (<c>Sec-WebSocket-Protocol</c>).
        /// </summary>
        public static byte[] BuildClientRequest(string host, string path, string secWebSocketKey, string? subProtocol = null)
        {
            if (host is null) throw new ArgumentNullException(nameof(host));
            if (secWebSocketKey is null) throw new ArgumentNullException(nameof(secWebSocketKey));
            if (string.IsNullOrEmpty(path)) path = "/";

            var sb = new StringBuilder();
            sb.Append("GET ").Append(path).Append(" HTTP/1.1\r\n");
            sb.Append("Host: ").Append(host).Append("\r\n");
            sb.Append("Upgrade: websocket\r\n");
            sb.Append("Connection: Upgrade\r\n");
            sb.Append("Sec-WebSocket-Key: ").Append(secWebSocketKey).Append("\r\n");
            sb.Append("Sec-WebSocket-Version: 13\r\n");
            if (!string.IsNullOrEmpty(subProtocol))
                sb.Append("Sec-WebSocket-Protocol: ").Append(subProtocol).Append("\r\n");
            sb.Append("\r\n");
            return Encoding.ASCII.GetBytes(sb.ToString());
        }

        /// <summary>
        /// ASCII-decodes <paramref name="response"/> and validates it as a server handshake reply (see the string
        /// overload).
        /// </summary>
        public static bool TryParseResponse(ReadOnlySpan<byte> response, string expectedAccept)
            => TryParseResponse(Encoding.ASCII.GetString(response.ToArray()), expectedAccept);

        /// <summary>
        /// Validates a server handshake reply: the status line must be <c>101</c> (Switching Protocols) and the
        /// <c>Sec-WebSocket-Accept</c> header must equal <paramref name="expectedAccept"/> (from
        /// <see cref="ComputeAccept"/>). Returns <c>false</c> on any other status, a missing/mismatched accept header, or
        /// a malformed response — the caller turns that into a connect failure.
        /// </summary>
        public static bool TryParseResponse(string response, string expectedAccept)
        {
            if (response is null || expectedAccept is null) return false;

            int headerEnd = response.IndexOf("\r\n\r\n", StringComparison.Ordinal);
            string headerSection = headerEnd >= 0 ? response.Substring(0, headerEnd) : response;
            string[] lines = headerSection.Split(new[] { "\r\n" }, StringSplitOptions.None);
            if (lines.Length == 0) return false;

            // Status line, e.g. "HTTP/1.1 101 Switching Protocols" — the 101 status code is the second token.
            string[] statusTokens = lines[0].Split(' ');
            if (statusTokens.Length < 2 || statusTokens[1] != "101") return false;

            string? accept = null;
            for (int i = 1; i < lines.Length; i++)
            {
                int colon = lines[i].IndexOf(':');
                if (colon < 0) continue;
                string name = lines[i].Substring(0, colon).Trim();
                if (name.Equals("Sec-WebSocket-Accept", StringComparison.OrdinalIgnoreCase))
                {
                    accept = lines[i].Substring(colon + 1).Trim();
                    break;
                }
            }

            return accept != null && string.Equals(accept, expectedAccept, StringComparison.Ordinal);
        }
    }
}
