using System.Net;
using System.Net.Sockets;
using TqkLibrary.VpnClient.WireGuard.Config;

namespace TqkLibrary.VpnClient.Tunnels
{
    /// <summary>
    /// Reads a wg-quick <c>.conf</c> — the file a WireGuard provider hands out — into the
    /// <see cref="WireGuardConfig"/> the driver takes, plus the peer's endpoint.
    /// </summary>
    /// <remarks>
    /// Only the keys that describe the tunnel are read. wg-quick's operating-system directives
    /// (<c>Table</c>, <c>PostUp</c>, <c>MTU</c>, …) are ignored on purpose: nothing here touches
    /// routes or interfaces, so a file carrying them still works, it just does not get them.
    /// </remarks>
    public static class WireGuardConfFile
    {
        /// <summary>The port a wg-quick file means when its Endpoint carries only a host.</summary>
        public const int DefaultPort = 51820;

        /// <summary>Parses the file at <paramref name="path"/>.</summary>
        /// <param name="path">The wg-quick file.</param>
        /// <param name="defaultPersistentKeepaliveSeconds">
        /// Used when the file sets no <c>PersistentKeepalive</c>; 0 keeps the file's answer, which is
        /// WireGuard's own default of off. See <see cref="Parse(string, int)"/>.
        /// </param>
        public static (WireGuardConfig Config, string Host, int Port) Load(
            string path, int defaultPersistentKeepaliveSeconds = 0)
            => Parse(File.ReadAllText(path), defaultPersistentKeepaliveSeconds);

        /// <summary>Parses wg-quick configuration text.</summary>
        /// <param name="text">The file's contents.</param>
        /// <param name="defaultPersistentKeepaliveSeconds">
        /// What to use when the text sets no <c>PersistentKeepalive</c>. 0 — the default here — reads
        /// the file exactly as written, which is what a parser should do. A caller that has to hold
        /// the tunnel up passes a real interval instead: most providers' files leave the key out, and
        /// a peer behind NAT that sends nothing for a minute loses its mapping, after which the
        /// tunnel is silently dead in one direction with nothing in the protocol to report it.
        /// </param>
        public static (WireGuardConfig Config, string Host, int Port) Parse(
            string text, int defaultPersistentKeepaliveSeconds = 0)
        {
            if (text is null) throw new ArgumentNullException(nameof(text));

            byte[]? privateKey = null, peerPublicKey = null, presharedKey = null;
            IPAddress? address = null, addressV6 = null;
            int prefix = 32, prefixV6 = 128;
            var dnsServers = new List<IPAddress>();
            var allowedIps = new List<string>();
            int keepalive = 0;
            string host = "";
            int port = DefaultPort;
            string section = "";

            foreach (string rawLine in text.Split('\n'))
            {
                string line = rawLine.Trim();
                if (line.Length == 0 || line[0] == '#' || line[0] == ';') continue;
                if (line[0] == '[' && line[line.Length - 1] == ']')
                {
                    section = line.Substring(1, line.Length - 2).Trim().ToLowerInvariant();
                    continue;
                }

                int eq = line.IndexOf('=');
                if (eq < 0) continue;
                string key = line.Substring(0, eq).Trim().ToLowerInvariant();
                string val = line.Substring(eq + 1).Trim();

                if (section == "interface")
                {
                    switch (key)
                    {
                        case "privatekey":
                            privateKey = Convert.FromBase64String(val);
                            break;
                        case "address":
                            foreach (string a in val.Split(','))
                            {
                                (IPAddress ip, int p) = ParseCidr(a.Trim());
                                if (ip.AddressFamily == AddressFamily.InterNetwork) { address = ip; prefix = p; }
                                else { addressV6 = ip; prefixV6 = p; }
                            }
                            break;
                        case "dns":
                            foreach (string d in val.Split(','))
                            {
                                if (IPAddress.TryParse(d.Trim(), out IPAddress? ip)) dnsServers.Add(ip);
                            }
                            break;
                    }
                }
                else if (section == "peer")
                {
                    switch (key)
                    {
                        case "publickey":
                            peerPublicKey = Convert.FromBase64String(val);
                            break;
                        case "presharedkey":
                            presharedKey = Convert.FromBase64String(val);
                            break;
                        case "allowedips":
                            foreach (string a in val.Split(',')) allowedIps.Add(a.Trim());
                            break;
                        case "persistentkeepalive":
                            int.TryParse(val, out keepalive);
                            break;
                        case "endpoint":
                            // Last colon, so an IPv6 literal endpoint keeps its own colons.
                            int colon = val.LastIndexOf(':');
                            if (colon > 0)
                            {
                                host = val.Substring(0, colon).Trim('[', ']');
                                int.TryParse(val.Substring(colon + 1), out port);
                            }
                            else
                            {
                                host = val;
                            }
                            break;
                    }
                }
            }

            if (privateKey is null)
                throw new InvalidDataException("The WireGuard .conf has no PrivateKey under [Interface].");
            if (peerPublicKey is null)
                throw new InvalidDataException("The WireGuard .conf has no PublicKey under [Peer].");
            if (host.Length == 0)
                throw new InvalidDataException("The WireGuard .conf has no [Peer] Endpoint <host>:<port>.");
            if (port <= 0) port = DefaultPort;

            var config = new WireGuardConfig
            {
                PrivateKey = privateKey,
                PeerPublicKey = peerPublicKey,
                PresharedKey = presharedKey,
                Address = address,
                PrefixLength = prefix,
                AddressV6 = addressV6,
                PrefixLengthV6 = prefixV6,
                DnsServers = dnsServers,
                // A file that routes nothing is a file with no purpose here, so an absent AllowedIPs
                // is read as "everything" rather than left empty.
                AllowedIps = allowedIps.Count > 0 ? allowedIps : new List<string> { "0.0.0.0/0", "::/0" },
                PersistentKeepaliveSeconds = keepalive > 0
                    ? keepalive
                    : Math.Max(0, defaultPersistentKeepaliveSeconds),
            };
            return (config, host, port);
        }

        // "10.50.0.2/24" -> (10.50.0.2, 24); no slash means the single address.
        static (IPAddress Ip, int Prefix) ParseCidr(string cidr)
        {
            int slash = cidr.IndexOf('/');
            if (slash < 0)
            {
                IPAddress only = IPAddress.Parse(cidr);
                return (only, only.AddressFamily == AddressFamily.InterNetworkV6 ? 128 : 32);
            }
            IPAddress ip = IPAddress.Parse(cidr.Substring(0, slash));
            int prefix = int.Parse(cidr.Substring(slash + 1));
            return (ip, prefix);
        }
    }
}
