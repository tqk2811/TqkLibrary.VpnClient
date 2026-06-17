namespace TqkLibrary.VpnClient.Ppp.Framing.Enums
{
    /// <summary>PPP protocol field values (RFC 1661 / IANA), identifying the encapsulated payload.</summary>
    public enum PppProtocol : ushort
    {
        /// <summary>Padding protocol.</summary>
        Padding = 0x0001,

        /// <summary>Internet Protocol version 4.</summary>
        Ip = 0x0021,

        /// <summary>Internet Protocol version 6.</summary>
        Ipv6 = 0x0057,

        /// <summary>Compressed/encrypted datagram (MPPC/MPPE payload, RFC 1962/3078). PPTP data plane (V.6).</summary>
        Compressed = 0x00FD,

        /// <summary>Link Control Protocol.</summary>
        Lcp = 0xC021,

        /// <summary>Compression Control Protocol (RFC 1962). Carries the MPPE option for PPTP (V.6).</summary>
        Ccp = 0x80FD,

        /// <summary>Password Authentication Protocol.</summary>
        Pap = 0xC023,

        /// <summary>Challenge Handshake Authentication Protocol (incl. MS-CHAPv2).</summary>
        Chap = 0xC223,

        /// <summary>IP Control Protocol.</summary>
        Ipcp = 0x8021,

        /// <summary>IPv6 Control Protocol.</summary>
        Ipv6cp = 0x8057,
    }
}
