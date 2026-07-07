namespace TqkLibrary.VpnClient.Drivers.EoGre.Enums
{
    /// <summary>
    /// Which flavour of Ethernet-over-GRE a connection puts on the wire. Both carry a full Ethernet frame behind a standard
    /// GRE header with Protocol Type 0x6558 (Transparent Ethernet Bridging) inside a UDP payload (RFC 8086); they differ
    /// only in how the GRE Key and the Checksum/Sequence fields are used.
    /// </summary>
    public enum EoGreMode
    {
        /// <summary>
        /// Plain EoGRE / GRETAP (RFC 2784/2890 + RFC 8086): the 24-bit VSID is <b>optional</b> — when
        /// <c>EoGreConfig.Vsid</c> is set it is packed into the RFC 2890 Key (with the FlowID), otherwise no Key is emitted.
        /// The RFC 2784 Checksum and RFC 2890 Sequence Number are optional (per the config flags). Driver key <c>"eogre"</c>.
        /// </summary>
        EoGre = 0,

        /// <summary>
        /// NVGRE (RFC 7637): a <b>mandatory</b> 24-bit Virtual Subnet ID (VSID) plus an 8-bit FlowID is packed into the GRE
        /// Key (<c>VSID &lt;&lt; 8 | FlowID</c>, K bit set), and the Checksum (C) and Sequence Number (S) bits MUST be zero
        /// — so those config flags are forced off in this mode. Driver key <c>"nvgre"</c>.
        /// </summary>
        Nvgre = 1,
    }
}
