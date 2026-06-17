using System.Collections.Generic;

namespace TqkLibrary.VpnClient.OpenConnect.Models
{
    /// <summary>
    /// A parsed HTTP response read off the OpenConnect TLS byte stream during auth / CONNECT: the status code and
    /// reason, the headers (kept in order, names lower-cased for lookup), and the decoded body text. The raw header
    /// block is retained too so the CONNECT response can be re-parsed by <see cref="OpenConnectConnectCodec"/> (which
    /// reads the <c>X-CSTP-*</c> lines from the original text).
    /// </summary>
    public sealed class OpenConnectHttpResponse
    {
        /// <summary>Creates a response.</summary>
        public OpenConnectHttpResponse(int statusCode, string reason, IReadOnlyList<KeyValuePair<string, string>> headers,
            string rawHeaderText, string body)
        {
            StatusCode = statusCode;
            Reason = reason ?? string.Empty;
            Headers = headers ?? new List<KeyValuePair<string, string>>();
            RawHeaderText = rawHeaderText ?? string.Empty;
            Body = body ?? string.Empty;
        }

        /// <summary>The HTTP status code (200, 401, …).</summary>
        public int StatusCode { get; }

        /// <summary>The status reason phrase (may be empty).</summary>
        public string Reason { get; }

        /// <summary>The response headers in receive order; names are lower-cased.</summary>
        public IReadOnlyList<KeyValuePair<string, string>> Headers { get; }

        /// <summary>The raw status line + header block (CRLF-separated, no trailing blank line) — for re-parsing X-CSTP-* headers.</summary>
        public string RawHeaderText { get; }

        /// <summary>The decoded response body (empty for a CONNECT 200 that has no body).</summary>
        public string Body { get; }

        /// <summary>Returns the first header value matching <paramref name="name"/> (case-insensitive), or null.</summary>
        public string? GetHeader(string name)
        {
            foreach (KeyValuePair<string, string> h in Headers)
                if (string.Equals(h.Key, name, StringComparison.OrdinalIgnoreCase)) return h.Value;
            return null;
        }

        /// <summary>Returns every header value matching <paramref name="name"/> (case-insensitive), in order.</summary>
        public IEnumerable<string> GetHeaders(string name)
        {
            foreach (KeyValuePair<string, string> h in Headers)
                if (string.Equals(h.Key, name, StringComparison.OrdinalIgnoreCase)) yield return h.Value;
        }
    }
}
