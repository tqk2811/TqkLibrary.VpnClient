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
    }
}
