using System.Net;
using TqkLibrary.VpnClient.Abstractions.Drivers.Models;

namespace TqkLibrary.VpnClient.OpenConnect.Models
{
    /// <summary>
    /// The tunnel configuration an OpenConnect/ocserv gateway returns in the <c>X-CSTP-*</c> headers of the HTTP
    /// CONNECT response: the assigned address(es), netmask, DNS servers, split-include routes, MTU, and the DPD /
    /// keep-alive / rekey timers. <see cref="ToTunnelConfig"/> maps it onto the shared <see cref="TunnelConfig"/> the
    /// userspace stack consumes (CSTP assigns the IP in-band — <see cref="Enums.CstpPacketType"/> data rides L3 directly,
    /// no PPP).
    /// </summary>
    public sealed class OpenConnectTunnelInfo
    {
        /// <summary>The assigned IPv4 tunnel address (<c>X-CSTP-Address</c>), if any.</summary>
        public IPAddress? Address { get; set; }

        /// <summary>The assigned IPv6 tunnel address (<c>X-CSTP-Address-IP6</c>), if any.</summary>
        public IPAddress? AddressV6 { get; set; }

        /// <summary>The IPv4 netmask (<c>X-CSTP-Netmask</c>), used to derive the prefix length.</summary>
        public IPAddress? Netmask { get; set; }

        /// <summary>The IPv6 prefix length (<c>X-CSTP-Address-IP6</c> CIDR suffix); 64 when unset.</summary>
        public int PrefixLengthV6 { get; set; } = 64;

        /// <summary>Pushed DNS servers (<c>X-CSTP-DNS</c>, repeated).</summary>
        public List<IPAddress> DnsServers { get; } = new();

        /// <summary>Split-include routes as CIDR text (<c>X-CSTP-Split-Include</c>, repeated).</summary>
        public List<string> Routes { get; } = new();

        /// <summary>Tunnel MTU (<c>X-CSTP-MTU</c>, falling back to <c>X-CSTP-Base-MTU</c>); null when unset.</summary>
        public int? Mtu { get; set; }

        /// <summary>Dead-peer-detection interval in seconds (<c>X-CSTP-DPD</c>); null = DPD disabled.</summary>
        public int? Dpd { get; set; }

        /// <summary>Keep-alive interval in seconds (<c>X-CSTP-Keepalive</c>); null = disabled.</summary>
        public int? Keepalive { get; set; }

        /// <summary>The rekey method the server requested (<c>X-CSTP-Rekey-Method</c>: <c>ssl</c> / <c>new-tunnel</c> / <c>none</c>).</summary>
        public string? RekeyMethod { get; set; }

        /// <summary>The rekey period in seconds (<c>X-CSTP-Rekey-Time</c>); null when unset.</summary>
        public int? RekeyTime { get; set; }

        /// <summary>The session cookie echoed by the server (<c>Set-Cookie: webvpn=…</c>), if present on the CONNECT response.</summary>
        public string? SessionCookie { get; set; }

        /// <summary>Maps the parsed headers onto a <see cref="TunnelConfig"/> for the userspace stack.</summary>
        public TunnelConfig ToTunnelConfig()
        {
            var config = new TunnelConfig
            {
                AssignedAddress = Address,
                AssignedAddressV6 = AddressV6,
                PrefixLengthV6 = PrefixLengthV6,
            };
            if (Netmask != null) config.PrefixLength = MaskToPrefix(Netmask);
            if (Mtu.HasValue) config.Mtu = Mtu.Value;
            foreach (IPAddress dns in DnsServers) config.DnsServers.Add(dns);
            foreach (string route in Routes) config.Routes.Add(route);
            return config;
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
