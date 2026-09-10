using System.Net;
using System.Net.Sockets;
using TqkLibrary.VpnClient.Abstractions.Drivers.Models;

namespace TqkLibrary.VpnClient.OpenVpn.DataChannel
{
    /// <summary>
    /// A parsed OpenVPN <c>PUSH_REPLY</c> — the comma-separated options the server pushes after <c>PUSH_REQUEST</c>:
    /// the tunnel address (<c>ifconfig</c>), routes, DNS (<c>dhcp-option DNS</c>), the data-channel <c>peer-id</c>, the
    /// keepalive timers (<c>ping</c>/<c>ping-restart</c>), the negotiated <c>cipher</c> and the <c>topology</c>.
    /// <see cref="ToTunnelConfig"/> maps it onto the shared <see cref="TunnelConfig"/> the userspace stack consumes.
    /// </summary>
    public sealed class OpenVpnPushReply
    {
        /// <summary>The <c>PUSH_REPLY</c> prefix that introduces the option list.</summary>
        public const string Prefix = "PUSH_REPLY";

        /// <summary>The tunnel address from <c>ifconfig &lt;local&gt; …</c>.</summary>
        public IPAddress? IfconfigLocal { get; private set; }

        /// <summary>The second <c>ifconfig</c> argument: the peer address (net30) or the netmask (subnet topology).</summary>
        public IPAddress? IfconfigRemoteOrMask { get; private set; }

        /// <summary>
        /// The default gateway from <c>route-gateway &lt;ip&gt;</c>. It matters in tap (bridged) mode, where the host is
        /// on a real Ethernet segment and has to send off-link packets to this router rather than to the destination.
        /// </summary>
        public IPAddress? RouteGateway { get; private set; }

        /// <summary><c>topology</c> value (<c>subnet</c>/<c>net30</c>/<c>p2p</c>); null when unset (tun ⇒ net30).</summary>
        public string? Topology { get; private set; }

        /// <summary>The data-channel <c>peer-id</c> the server assigned (stamped on outgoing P_DATA_V2), if any.</summary>
        public uint? PeerId { get; private set; }

        /// <summary>The negotiated data <c>cipher</c> (e.g. <c>AES-256-GCM</c>), if pushed.</summary>
        public string? Cipher { get; private set; }

        /// <summary>The compression directive (<c>comp-lzo no</c>, <c>compress stub-v2</c>, …), verbatim; null = none.</summary>
        public string? Compression { get; private set; }

        /// <summary>Keepalive ping interval in seconds (<c>ping</c>), if pushed.</summary>
        public int? Ping { get; private set; }

        /// <summary>Keepalive restart timeout in seconds (<c>ping-restart</c>), if pushed.</summary>
        public int? PingRestart { get; private set; }

        /// <summary>Pushed DNS servers (<c>dhcp-option DNS &lt;ip&gt;</c>).</summary>
        public List<IPAddress> DnsServers { get; } = new();

        /// <summary>Pushed routes as CIDR text (parsed from <c>route &lt;net&gt; &lt;mask&gt;</c>).</summary>
        public List<string> Routes { get; } = new();

        /// <summary>Every option verbatim (including ones not modelled above), in push order.</summary>
        public List<string> Options { get; } = new();

        /// <summary>
        /// Parses a <c>PUSH_REPLY,opt1,opt2,…</c> string. Returns false if the message is not a PUSH_REPLY (e.g.
        /// <c>AUTH_FAILED</c>). Unrecognised options are kept in <see cref="Options"/> and otherwise ignored.
        /// </summary>
        public static bool TryParse(string message, out OpenVpnPushReply reply)
        {
            reply = new OpenVpnPushReply();
            if (string.IsNullOrEmpty(message)) return false;

            string[] parts = message.Split(',');
            if (parts[0].Trim() != Prefix) return false;

            for (int i = 1; i < parts.Length; i++)
            {
                string option = parts[i].Trim();
                if (option.Length == 0) continue;
                reply.Options.Add(option);

                string[] t = option.Split(new[] { ' ' }, StringSplitOptions.RemoveEmptyEntries);
                switch (t[0])
                {
                    case "ifconfig":
                        if (t.Length >= 2) reply.IfconfigLocal = ParseV4(t[1]);
                        if (t.Length >= 3) reply.IfconfigRemoteOrMask = ParseV4(t[2]);
                        break;
                    case "route":
                        string? cidr = RouteToCidr(t);
                        if (cidr != null) reply.Routes.Add(cidr);
                        break;
                    case "route-gateway":
                        if (t.Length >= 2) reply.RouteGateway = ParseV4(t[1]);
                        break;
                    case "dhcp-option":
                        if (t.Length >= 3 && string.Equals(t[1], "DNS", StringComparison.OrdinalIgnoreCase)
                            && ParseV4(t[2]) is IPAddress dns) reply.DnsServers.Add(dns);
                        break;
                    case "peer-id":
                        if (t.Length >= 2 && uint.TryParse(t[1], out uint pid)) reply.PeerId = pid;
                        break;
                    case "cipher":
                        if (t.Length >= 2) reply.Cipher = t[1];
                        break;
                    case "ping":
                        if (t.Length >= 2 && int.TryParse(t[1], out int ping)) reply.Ping = ping;
                        break;
                    case "ping-restart":
                        if (t.Length >= 2 && int.TryParse(t[1], out int pr)) reply.PingRestart = pr;
                        break;
                    case "topology":
                        if (t.Length >= 2) reply.Topology = t[1];
                        break;
                    case "comp-lzo":
                    case "compress":
                        reply.Compression = option; // e.g. "comp-lzo no" / "compress stub-v2" / "compress"
                        break;
                }
            }
            return true;
        }

        /// <summary>Maps the pushed options onto a <see cref="TunnelConfig"/> for the userspace stack.</summary>
        public TunnelConfig ToTunnelConfig()
        {
            var config = new TunnelConfig { AssignedAddress = IfconfigLocal };
            // subnet topology ⇒ the second ifconfig arg is a netmask; net30/p2p (or unset for tun) ⇒ a /30 peer address.
            if (string.Equals(Topology, "subnet", StringComparison.OrdinalIgnoreCase) && IfconfigRemoteOrMask != null)
                config.PrefixLength = MaskToPrefix(IfconfigRemoteOrMask);
            else
                config.PrefixLength = 30;
            config.Gateway = RouteGateway;
            foreach (IPAddress dns in DnsServers) config.DnsServers.Add(dns);
            foreach (string route in Routes) config.Routes.Add(route);
            return config;
        }

        static IPAddress? ParseV4(string s) =>
            IPAddress.TryParse(s, out IPAddress? ip) && ip.AddressFamily == AddressFamily.InterNetwork ? ip : null;

        // "route <net> [<mask>] [<gw>] [<metric>]" → "net/prefix" (mask defaults to /32 when absent).
        static string? RouteToCidr(string[] t)
        {
            if (t.Length < 2) return null;
            IPAddress? net = ParseV4(t[1]);
            if (net == null) return null;
            int prefix = 32;
            if (t.Length >= 3 && ParseV4(t[2]) is IPAddress mask) prefix = MaskToPrefix(mask);
            return $"{net}/{prefix}";
        }

        static int MaskToPrefix(IPAddress mask)
        {
            int bits = 0;
            foreach (byte b in mask.GetAddressBytes())
            {
                byte v = b;
                while (v != 0) { bits += v & 1; v >>= 1; }
            }
            return bits;
        }
    }
}
