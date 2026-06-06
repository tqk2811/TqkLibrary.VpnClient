namespace TqkLibrary.Vpn.Abstractions.Drivers.Enums
{
    /// <summary>How the client learns its tunnel IP / DNS / routes.</summary>
    public enum AddressAssignment
    {
        /// <summary>PPP IPCP negotiation (L2TP, SSTP, PPTP, Fortinet, F5).</summary>
        Ipcp = 0,

        /// <summary>In-band config push (OpenVPN PUSH_REPLY, IKEv2 CFG payload, CSTP headers, GlobalProtect XML).</summary>
        ConfigPush = 1,

        /// <summary>Configured out of band (WireGuard, Nebula static/cert-asserted addresses).</summary>
        OutOfBand = 2,

        /// <summary>DHCP over an L2 segment (SoftEther SecureNAT, OpenVPN-tap).</summary>
        Dhcp = 3,
    }
}
