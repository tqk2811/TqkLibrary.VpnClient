namespace Vpn2ProxyDemo.CommandModules.Enums
{
    /// <summary>Giao thức VPN demo hỗ trợ — map từ scheme/giá trị của option <c>--vpn</c>.</summary>
    internal enum VpnProtocol
    {
        /// <summary>MS-SSTP qua TLS/443 (scheme <c>sstp</c>).</summary>
        Sstp,

        /// <summary>L2TP/IPsec (IKEv1 PSK "vpn", NAT-T) (scheme <c>l2tp</c>).</summary>
        L2tp,

        /// <summary>IKEv2-native (RFC 7296 PSK/EAP over NAT-T, CP virtual IP, ESP tunnel mode — no PPP) (scheme <c>ikev2</c>).</summary>
        Ikev2,

        /// <summary>SoftEther SSL-VPN (Ethernet-over-TLS, DHCP SecureNAT, auth SHA-0) (scheme <c>softether</c>/<c>ssl</c>).</summary>
        SoftEther,

        /// <summary>OpenVPN (community-server compatible) cấu hình từ một file <c>.ovpn</c> (<c>--vpn</c> trỏ thẳng tới đường dẫn file).</summary>
        OpenVpn,

        /// <summary>WireGuard (Noise_IKpsk2, UDP) cấu hình từ một file <c>.conf</c> wg-quick (<c>--vpn</c> trỏ thẳng tới đường dẫn file).</summary>
        WireGuard,

        /// <summary>OpenConnect (Cisco AnyConnect/ocserv): HTTPS config-auth → CSTP-over-TLS (+DTLS data path), bare IP — no PPP (scheme <c>openconnect</c>/<c>anyconnect</c>) (V.5).</summary>
        OpenConnect,

        /// <summary>PPTP (RFC 2637): control TCP/1723 + GRE proto-47 (raw socket) carrying PPP/MS-CHAPv2/MPPE (scheme <c>pptp</c>) — needs CAP_NET_RAW/Administrator (V.6).</summary>
        Pptp,

        /// <summary>Plain IP-in-IP / GRE encapsulation (no control plane): standard GRE proto-47 (scheme <c>gre</c>), IPIP proto-4 (scheme <c>ipip</c>) or SIT/6in4 proto-41 (scheme <c>sit</c>) over a raw IP socket — needs CAP_NET_RAW/Administrator; the tunnel address is static (?addr=/?peer=) since there is no IPCP/DHCP (V.8).</summary>
        IpEncap,
    }
}
