namespace TqkLibrary.VpnClient.Pptp.Enums
{
    /// <summary>
    /// CCP (Compression Control Protocol, RFC 1962) configuration-option types. Only the Microsoft
    /// Point-to-Point Encryption / Compression option (type 18, RFC 2118 §3 / RFC 3078 §3.1) is negotiated
    /// here — it carries the 4-byte MPPE/MPPC "supported bits" field.
    /// </summary>
    public enum CcpOptionType : byte
    {
        /// <summary>OUI (proprietary compression, RFC 1962) — not used here.</summary>
        Oui = 0,

        /// <summary>Microsoft Point-to-Point Encryption/Compression (MPPE/MPPC), RFC 2118 §3 / RFC 3078 §3.1.</summary>
        MppeMppc = 18,
    }
}
