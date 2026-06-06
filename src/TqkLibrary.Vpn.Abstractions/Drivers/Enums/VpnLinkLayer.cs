namespace TqkLibrary.Vpn.Abstractions.Drivers.Enums
{
    /// <summary>The link layer a driver outputs.</summary>
    public enum VpnLinkLayer
    {
        /// <summary>Bare IP packets (L2TP/SSTP/OpenVPN-tun/WireGuard...).</summary>
        L3Ip = 0,

        /// <summary>Ethernet frames (SoftEther/OpenVPN-tap/VXLAN...).</summary>
        L2Ethernet = 1,

        /// <summary>Configurable either way (OpenVPN, GRE, tinc).</summary>
        Both = 2,
    }
}
