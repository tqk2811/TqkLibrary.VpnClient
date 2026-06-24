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

        /// <summary>Cisco IPsec / EzVPN (IKEv1 Aggressive Mode group PSK + XAUTH + Mode-Config over NAT-T, ESP tunnel mode — no PPP) (scheme <c>cisco</c>) (V.12).</summary>
        CiscoIpsec,

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

        /// <summary>Nebula (Slack mesh VPN, Noise_IX/AES-256-GCM, UDP) cấu hình từ một file <c>.nebula</c> (ini trỏ tới ca/cert/key PEM + peer endpoint + overlay) (<c>--vpn</c> trỏ thẳng tới file) (V.7.1).</summary>
        Nebula,

        /// <summary>tinc 1.1 (SPTPS: Curve25519/Ed25519/ChaCha-Poly1305) cấu hình từ một file <c>.tinc</c> (ini trỏ tới seed Ed25519 của ta + host file của peer + endpoint + overlay); TCP meta-connection + UDP data plane (<c>--vpn</c> trỏ thẳng tới file) (V.7.2).</summary>
        Tinc,

        /// <summary>n2n v3 (ntop) L2 mesh (UDP, REGISTER_SUPER tới supernode + PACKET Ethernet-frame NULL/AES-CBC) cấu hình từ một file <c>.n2n</c> (ini trỏ tới community + supernode endpoint + static overlay + transform); supernode-relay (<c>--vpn</c> trỏ thẳng tới file) (V.7.4).</summary>
        N2n,

        /// <summary>ZeroTier (VL1 Curve25519/Salsa20-12/Poly1305 + VL2 EXT_FRAME L2-over-UDP) cấu hình từ một file <c>.zerotier</c> (ini trỏ tới identity.secret ta + identity.public của node/controller + endpoint + network id + overlay); HELLO ⇄ OK + NETWORK_CONFIG_REQUEST (<c>--vpn</c> trỏ thẳng tới file) (V.7.3).</summary>
        ZeroTier,

        /// <summary>vtun (legacy tunnel daemon): TCP control+data, challenge-response (MD5+Blowfish-ECB) → length-prefix frame → bare IP (type tun, encrypt no, compress no). Scheme <c>vtun://pass@host[:port]/hostName?addr=&lt;ip&gt;/&lt;prefix&gt;&amp;peer=&lt;ip&gt;</c> (V.11).</summary>
        Vtun,
    }
}
