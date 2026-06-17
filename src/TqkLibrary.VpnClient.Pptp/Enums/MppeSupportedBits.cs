namespace TqkLibrary.VpnClient.Pptp.Enums
{
    /// <summary>
    /// The 32-bit MPPE/MPPC "supported bits" field carried in the CCP MPPE option (RFC 3078 §3.1), expressed
    /// as a host <see cref="uint"/> (the wire form is this value in big-endian). Only the encryption bits and
    /// the stateless flag matter for our use; MPPC compression is advertised but not implemented.
    /// <para>Bit layout (RFC 3078 §3.1), shown as the assembled 32-bit value:</para>
    /// <code>
    /// 0x01000000  H? (Stateless / "S" historically) — encryption is stateless (per-packet re-key)
    /// 0x00000040  H  — 128-bit session keys
    /// 0x00000080  M  — 56-bit session keys
    /// 0x00000020  L  — 40-bit session keys
    /// 0x00000010  D  — obsolete (must be zero)
    /// 0x00000001  C  — MPPC compression
    /// </code>
    /// Note: the historical RFC 3078 letters are confusing; the numeric constants below are the de-facto
    /// interoperable values used by Microsoft RAS, poptop and accel-ppp.
    /// </summary>
    [System.Flags]
    public enum MppeSupportedBits : uint
    {
        /// <summary>No bits set.</summary>
        None = 0,

        /// <summary>MPPC compression supported (C). Advertised but not implemented here.</summary>
        Mppc = 0x00000001,

        /// <summary>Obsolete bit D — must be zero.</summary>
        Obsolete = 0x00000010,

        /// <summary>40-bit session keys (L).</summary>
        Encrypt40Bit = 0x00000020,

        /// <summary>128-bit session keys (H).</summary>
        Encrypt128Bit = 0x00000040,

        /// <summary>56-bit session keys (M).</summary>
        Encrypt56Bit = 0x00000080,

        /// <summary>Stateless mode — re-key before every packet (S/H historical flag).</summary>
        Stateless = 0x01000000,
    }
}
