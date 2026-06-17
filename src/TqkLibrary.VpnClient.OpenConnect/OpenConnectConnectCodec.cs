using System.Globalization;
using System.Net;
using System.Net.Sockets;
using System.Text;
using TqkLibrary.VpnClient.OpenConnect.Models;

namespace TqkLibrary.VpnClient.OpenConnect
{
    /// <summary>
    /// Pure codec for the OpenConnect HTTP <c>CONNECT</c> exchange that promotes an authenticated HTTPS session to a
    /// CSTP tunnel. After auth (<see cref="OpenConnectAuthCodec"/>) yields the session cookie, the client sends
    /// <c>CONNECT /CSCOSSLC/tunnel HTTP/1.1</c> with the cookie and its requested CSTP options; the gateway answers
    /// <c>HTTP/1.1 200 OK</c> with the tunnel <c>X-CSTP-*</c> headers. <see cref="BuildConnectRequest"/> serialises the
    /// request; <see cref="ParseConnectResponse"/> parses the response headers into an <see cref="OpenConnectTunnelInfo"/>.
    /// No I/O. Modelled from the documented behaviour (draft-mavrogiannopoulos-openconnect / ocserv), not GPL source.
    /// </summary>
    public static class OpenConnectConnectCodec
    {
        /// <summary>The request-target ocserv/AnyConnect tunnels run CSTP over.</summary>
        public const string TunnelPath = "/CSCOSSLC/tunnel";

        const string Crlf = "\r\n";

        /// <summary>
        /// Builds the <c>CONNECT /CSCOSSLC/tunnel</c> request line plus headers (terminated by a blank line). The
        /// session <paramref name="cookie"/> is sent as <c>Cookie: webvpn=…</c>; the requested MTU (when given) goes in
        /// <c>X-CSTP-Base-MTU</c>. The returned text is ASCII-ready for the TLS stream.
        /// </summary>
        public static string BuildConnectRequest(string host, string cookie, int? requestedMtu = null)
        {
            if (string.IsNullOrEmpty(host)) throw new ArgumentException("Host required.", nameof(host));
            if (string.IsNullOrEmpty(cookie)) throw new ArgumentException("Session cookie required.", nameof(cookie));

            var sb = new StringBuilder();
            sb.Append("CONNECT ").Append(TunnelPath).Append(" HTTP/1.1").Append(Crlf);
            sb.Append("Host: ").Append(host).Append(Crlf);
            sb.Append("User-Agent: ").Append(OpenConnectAuthCodec.AnyConnectVersion).Append(Crlf);
            // The cookie may already be "webvpn=value"; otherwise treat it as the raw value.
            string cookieHeader = cookie.IndexOf('=') > 0 ? cookie : "webvpn=" + cookie;
            sb.Append("Cookie: ").Append(cookieHeader).Append(Crlf);
            sb.Append("X-CSTP-Version: 1").Append(Crlf);
            sb.Append("X-CSTP-Hostname: client").Append(Crlf);
            sb.Append("X-CSTP-Address-Type: IPv6,IPv4").Append(Crlf);
            if (requestedMtu.HasValue)
                sb.Append("X-CSTP-Base-MTU: ").Append(requestedMtu.Value.ToString(CultureInfo.InvariantCulture)).Append(Crlf);
            sb.Append("X-DTLS-Master-Secret: ").Append(Crlf); // placeholder; real DTLS keying is V5.b
            sb.Append(Crlf); // end of headers
            return sb.ToString();
        }

        /// <summary>
        /// Parses an HTTP CONNECT response (status line + headers, blank-line terminated) into the tunnel config.
        /// Throws <see cref="FormatException"/> on a malformed status line and <see cref="UnauthorizedAccessException"/>
        /// when the gateway rejected the tunnel (any non-200 status — e.g. 401/403/502). Unknown headers are ignored.
        /// </summary>
        public static OpenConnectTunnelInfo ParseConnectResponse(string responseText)
        {
            if (string.IsNullOrEmpty(responseText)) throw new FormatException("Empty CONNECT response.");
            string[] lines = SplitHeaderLines(responseText);
            if (lines.Length == 0) throw new FormatException("CONNECT response has no status line.");

            (int status, string reason) = ParseStatusLine(lines[0]);
            if (status != 200)
                throw new UnauthorizedAccessException($"OpenConnect gateway rejected the tunnel: HTTP {status} {reason}.");

            var info = new OpenConnectTunnelInfo();
            bool haveMtu = false; // X-CSTP-MTU wins over X-CSTP-Base-MTU when both are present
            for (int i = 1; i < lines.Length; i++)
            {
                if (!TrySplitHeader(lines[i], out string name, out string value)) continue;
                ApplyHeader(info, name, value, ref haveMtu);
            }
            return info;
        }

        static void ApplyHeader(OpenConnectTunnelInfo info, string name, string value, ref bool haveMtu)
        {
            switch (name.ToLowerInvariant())
            {
                case "x-cstp-address":
                    if (ParseIp(value) is IPAddress addr)
                    {
                        if (addr.AddressFamily == AddressFamily.InterNetworkV6) info.AddressV6 = addr;
                        else info.Address = addr;
                    }
                    break;
                case "x-cstp-address-ip6":
                    ParseV6Cidr(info, value);
                    break;
                case "x-cstp-netmask":
                    if (ParseIp(value) is IPAddress mask) info.Netmask = mask;
                    break;
                case "x-cstp-dns":
                    if (ParseIp(value) is IPAddress dns) info.DnsServers.Add(dns);
                    break;
                case "x-cstp-split-include":
                    info.Routes.Add(value);
                    break;
                case "x-cstp-mtu":
                    if (int.TryParse(value, out int mtu)) { info.Mtu = mtu; haveMtu = true; }
                    break;
                case "x-cstp-base-mtu":
                    if (!haveMtu && int.TryParse(value, out int baseMtu)) info.Mtu = baseMtu;
                    break;
                case "x-cstp-dpd":
                    if (int.TryParse(value, out int dpd)) info.Dpd = dpd;
                    break;
                case "x-cstp-keepalive":
                    if (int.TryParse(value, out int ka)) info.Keepalive = ka;
                    break;
                case "x-cstp-rekey-method":
                    info.RekeyMethod = value;
                    break;
                case "x-cstp-rekey-time":
                    if (int.TryParse(value, out int rt)) info.RekeyTime = rt;
                    break;
                case "set-cookie":
                    info.SessionCookie = OpenConnectAuthCodec.ExtractCookie("Set-Cookie: " + value) ?? info.SessionCookie;
                    break;
            }
        }

        static (int status, string reason) ParseStatusLine(string line)
        {
            // "HTTP/1.1 200 CONNECTED" — version, code, optional reason phrase.
            string[] parts = line.Split(new[] { ' ' }, 3, StringSplitOptions.RemoveEmptyEntries);
            if (parts.Length < 2 || !parts[0].StartsWith("HTTP/", StringComparison.OrdinalIgnoreCase)
                || !int.TryParse(parts[1], out int code))
                throw new FormatException($"Malformed HTTP status line: '{line}'.");
            return (code, parts.Length >= 3 ? parts[2] : string.Empty);
        }

        static string[] SplitHeaderLines(string text)
        {
            // Headers end at the first blank line; the body (if any) is ignored here.
            int blank = text.IndexOf("\r\n\r\n", StringComparison.Ordinal);
            string head = blank >= 0 ? text.Substring(0, blank) : text;
            return head.Split(new[] { "\r\n", "\n" }, StringSplitOptions.RemoveEmptyEntries);
        }

        static bool TrySplitHeader(string line, out string name, out string value)
        {
            int colon = line.IndexOf(':');
            if (colon <= 0) { name = string.Empty; value = string.Empty; return false; }
            name = line.Substring(0, colon).Trim();
            value = line.Substring(colon + 1).Trim();
            return true;
        }

        static void ParseV6Cidr(OpenConnectTunnelInfo info, string value)
        {
            // "2001:db8::1234/64"
            string addr = value;
            int slash = value.IndexOf('/');
            if (slash >= 0)
            {
                addr = value.Substring(0, slash);
                if (int.TryParse(value.Substring(slash + 1), out int prefix)) info.PrefixLengthV6 = prefix;
            }
            if (ParseIp(addr) is IPAddress ip && ip.AddressFamily == AddressFamily.InterNetworkV6)
                info.AddressV6 = ip;
        }

        static IPAddress? ParseIp(string s) => IPAddress.TryParse(s, out IPAddress? ip) ? ip : null;
    }
}
