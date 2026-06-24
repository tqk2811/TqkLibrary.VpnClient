namespace TqkLibrary.VpnClient.Vtun.Wire.Enums
{
    /// <summary>
    /// The vtun host flag bits (<c>vtun.h</c>) carried in the <c>OK FLAGS: &lt;...&gt;</c> line — the tunnel parameters the
    /// <b>server</b> dictates: link type (tun/tap/...), transport protocol (tcp/udp), and the feature toggles
    /// (compression, encryption, keepalive, traffic shaping). The numeric values match the C macros so a parsed flag set
    /// round-trips bit-for-bit.
    /// </summary>
    [System.Flags]
    public enum VtunHostFlags
    {
        /// <summary>No flags.</summary>
        None = 0,

        // ---- feature toggles (low nibble) ----

        /// <summary>zlib compression (<c>VTUN_ZLIB</c>).</summary>
        Zlib = 0x0001,

        /// <summary>LZO compression (<c>VTUN_LZO</c>).</summary>
        Lzo = 0x0002,

        /// <summary>Traffic shaping (<c>VTUN_SHAPE</c>).</summary>
        Shape = 0x0004,

        /// <summary>Data-plane encryption (<c>VTUN_ENCRYPT</c>).</summary>
        Encrypt = 0x0008,

        // ---- transport protocol ----

        /// <summary>TCP transport (<c>VTUN_TCP</c>).</summary>
        Tcp = 0x0010,

        /// <summary>UDP transport (<c>VTUN_UDP</c>).</summary>
        Udp = 0x0020,

        /// <summary>Keepalive echo enabled (<c>VTUN_KEEP_ALIVE</c>).</summary>
        KeepAlive = 0x0040,

        // ---- link type (type nibble) ----

        /// <summary>Serial/tty link (<c>VTUN_TTY</c>).</summary>
        Tty = 0x0100,

        /// <summary>Pipe link (<c>VTUN_PIPE</c>).</summary>
        Pipe = 0x0200,

        /// <summary>Ethernet (tap) link (<c>VTUN_ETHER</c>).</summary>
        Ether = 0x0400,

        /// <summary>IP (tun) link (<c>VTUN_TUN</c>).</summary>
        Tun = 0x0800,

        /// <summary>Mask isolating the transport protocol bits (<c>VTUN_PROT_MASK</c>).</summary>
        ProtocolMask = Tcp | Udp,

        /// <summary>Mask isolating the link-type bits (<c>VTUN_TYPE_MASK</c>).</summary>
        TypeMask = Tty | Pipe | Ether | Tun,
    }
}
