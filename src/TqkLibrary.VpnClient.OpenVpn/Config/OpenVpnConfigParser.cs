using System.Text;
using TqkLibrary.VpnClient.OpenVpn.Enums;

namespace TqkLibrary.VpnClient.OpenVpn.Config
{
    /// <summary>
    /// Parses a .ovpn profile text into an <see cref="OpenVpnProfile"/>. Pure text → model (no file I/O): inline
    /// material between tags (<c>&lt;ca&gt;…&lt;/ca&gt;</c>) is kept verbatim as PEM, while the file-path form
    /// (<c>ca ca.crt</c>) records the path for the caller to load. Comments (<c>#</c>/<c>;</c>) and blank lines are
    /// ignored; double-quoted arguments are supported; <c>&lt;connection&gt;</c> blocks are flattened; unrecognised
    /// directives are preserved in <see cref="OpenVpnProfile.OtherDirectives"/>.
    /// </summary>
    public static class OpenVpnConfigParser
    {
        /// <summary>Parses .ovpn configuration text into a profile.</summary>
        public static OpenVpnProfile Parse(string text)
        {
            if (text is null) throw new ArgumentNullException(nameof(text));
            var profile = new OpenVpnProfile();
            string[] lines = text.Split(new[] { "\r\n", "\r", "\n" }, StringSplitOptions.None);
            ParseLines(lines, 0, lines.Length, profile);
            return profile;
        }

        static void ParseLines(string[] lines, int start, int end, OpenVpnProfile profile)
        {
            for (int i = start; i < end; i++)
            {
                string raw = lines[i];
                string line = raw.Trim();
                if (line.Length == 0 || line[0] == '#' || line[0] == ';') continue;

                // Inline block: <tag> ... </tag>
                if (line[0] == '<' && line[line.Length - 1] == '>' && !line.StartsWith("</"))
                {
                    string tag = line.Substring(1, line.Length - 2).Trim().ToLowerInvariant();
                    string close = "</" + tag + ">";
                    int j = i + 1;
                    var body = new List<string>();
                    while (j < end && lines[j].Trim().ToLowerInvariant() != close)
                    {
                        body.Add(lines[j]);
                        j++;
                    }
                    ApplyInlineBlock(tag, body, lines, i + 1, j, profile);
                    i = j; // skip past the closing tag (j points at it, or end)
                    continue;
                }

                string[] tokens = Tokenize(line);
                if (tokens.Length == 0) continue;
                ApplyDirective(tokens, profile);
            }
        }

        static void ApplyInlineBlock(string tag, List<string> body, string[] lines, int bodyStart, int bodyEnd, OpenVpnProfile profile)
        {
            if (tag == "connection")
            {
                ParseLines(lines, bodyStart, bodyEnd, profile); // flatten: its remote/proto/port directives apply to the profile
                return;
            }

            string content = string.Join("\n", body).Trim();
            var inline = new OpenVpnFileOrInline { Inline = content };
            switch (tag)
            {
                case "ca": profile.Ca = inline; break;
                case "cert": profile.Cert = inline; break;
                case "key": profile.Key = inline; break;
                case "tls-auth": profile.TlsAuth = inline; break;
                case "tls-crypt": profile.TlsCrypt = inline; break;
                case "tls-crypt-v2": profile.TlsCryptV2 = inline; break;
                // unknown inline tags are ignored (rare; not part of a client profile)
            }
        }

        static void ApplyDirective(string[] tokens, OpenVpnProfile profile)
        {
            string name = tokens[0].ToLowerInvariant();
            string? Arg(int n) => tokens.Length > n ? tokens[n] : null;

            switch (name)
            {
                case "client":
                case "tls-client":
                    profile.IsClient = true;
                    break;

                case "dev":
                case "dev-type":
                    if (Arg(1) is string dev) profile.Device = dev.StartsWith("tap") ? OpenVpnDeviceType.Tap : OpenVpnDeviceType.Tun;
                    break;

                case "proto":
                    if (Arg(1) is string proto) profile.Protocol = ParseProtocol(proto) ?? profile.Protocol;
                    break;

                case "port":
                    if (TryInt(Arg(1), out int port)) profile.Port = port;
                    break;

                case "remote":
                    if (Arg(1) is string host)
                    {
                        int remotePort = TryInt(Arg(2), out int p) ? p : profile.Port;
                        OpenVpnProtocol? remoteProto = Arg(3) is string rp ? ParseProtocol(rp) : null;
                        profile.Remotes.Add(new OpenVpnRemote(host, remotePort, remoteProto));
                    }
                    break;

                case "ca": profile.Ca = FilePathOrKeepInline(profile.Ca, Arg(1)); break;
                case "cert": profile.Cert = FilePathOrKeepInline(profile.Cert, Arg(1)); break;
                case "key": profile.Key = FilePathOrKeepInline(profile.Key, Arg(1)); break;

                case "tls-auth":
                    profile.TlsAuth = FilePathOrKeepInline(profile.TlsAuth, Arg(1));
                    if (TryInt(Arg(2), out int dir)) profile.KeyDirection = dir;
                    break;
                case "tls-crypt": profile.TlsCrypt = FilePathOrKeepInline(profile.TlsCrypt, Arg(1)); break;
                case "tls-crypt-v2": profile.TlsCryptV2 = FilePathOrKeepInline(profile.TlsCryptV2, Arg(1)); break;
                case "key-direction":
                    if (TryInt(Arg(1), out int kd)) profile.KeyDirection = kd;
                    break;

                case "auth-user-pass":
                    profile.AuthUserPass = true;
                    profile.AuthUserPassFile = Arg(1);
                    break;

                case "cipher": profile.Cipher = Arg(1); break;
                case "auth": profile.Auth = Arg(1); break;
                case "key-derivation":
                    // OpenVPN 2.6: "tls-ekm" derives the data keys via RFC 5705; anything else keeps the key-method-2 PRF.
                    if (string.Equals(Arg(1), "tls-ekm", StringComparison.OrdinalIgnoreCase))
                        profile.KeyDerivation = OpenVpnKeyDerivationMode.TlsEkm;
                    break;
                case "data-ciphers":
                case "data-ciphers-fallback":
                    if (Arg(1) is string list)
                        foreach (string c in list.Split(':'))
                            if (c.Length > 0) profile.DataCiphers.Add(c);
                    break;

                case "remote-cert-tls":
                    if (Arg(1) == "server") profile.RemoteCertTlsServer = true;
                    break;

                case "comp-lzo": profile.Compression = Arg(1) ?? "yes"; break;
                case "compress": profile.Compression = Arg(1) ?? "stub"; break;

                case "reneg-sec":
                    if (TryInt(Arg(1), out int reneg)) profile.RenegSec = reneg;
                    break;
                case "tun-mtu":
                    if (TryInt(Arg(1), out int mtu)) profile.TunMtu = mtu;
                    break;

                default:
                    if (!profile.OtherDirectives.TryGetValue(name, out List<string[]>? occurrences))
                        profile.OtherDirectives[name] = occurrences = new List<string[]>();
                    occurrences.Add(tokens.Length > 1 ? tokens.Skip(1).ToArray() : Array.Empty<string>());
                    break;
            }
        }

        // The file-path form, unless inline material was already captured for this slot (inline always wins).
        static OpenVpnFileOrInline? FilePathOrKeepInline(OpenVpnFileOrInline? existing, string? path)
        {
            if (path is null) return existing;
            if (existing is { IsInline: true }) return existing; // inline block already won
            return new OpenVpnFileOrInline { FilePath = path };
        }

        static OpenVpnProtocol? ParseProtocol(string value)
        {
            value = value.ToLowerInvariant();
            if (value.StartsWith("tcp")) return OpenVpnProtocol.Tcp;
            if (value.StartsWith("udp")) return OpenVpnProtocol.Udp;
            return null;
        }

        static bool TryInt(string? value, out int result)
            => int.TryParse(value, out result);

        // Splits a directive line on whitespace, honouring double-quoted arguments (which may contain spaces).
        static string[] Tokenize(string line)
        {
            var tokens = new List<string>();
            int i = 0, n = line.Length;
            while (i < n)
            {
                while (i < n && char.IsWhiteSpace(line[i])) i++;
                if (i >= n) break;
                if (line[i] == '"')
                {
                    i++;
                    var sb = new StringBuilder();
                    while (i < n && line[i] != '"') sb.Append(line[i++]);
                    if (i < n) i++; // closing quote
                    tokens.Add(sb.ToString());
                }
                else
                {
                    int s = i;
                    while (i < n && !char.IsWhiteSpace(line[i])) i++;
                    tokens.Add(line.Substring(s, i - s));
                }
            }
            return tokens.ToArray();
        }
    }
}
