namespace TqkLibrary.VpnClient.Crypto.Mppe.Enums
{
    /// <summary>
    /// MPPE session-key strength negotiated via CCP (RFC 3078 §3.1 / RFC 3079 §2): the bit flags map to the
    /// 8-byte (40/56-bit) or 16-byte (128-bit) RC4 session key, the weaker variants applying the well-known
    /// fixed-prefix strength reduction.
    /// </summary>
    public enum MppeKeyStrength
    {
        /// <summary>40-bit session key (8-byte RC4 key, first 3 octets forced to 0xD1 0x26 0x9E). CCP option bit <c>L</c>.</summary>
        Bits40,

        /// <summary>56-bit session key (8-byte RC4 key, first octet forced to 0xD1). CCP option bit <c>S</c>.</summary>
        Bits56,

        /// <summary>128-bit session key (full 16-byte RC4 key, no reduction). CCP option bit <c>H</c> (strongest).</summary>
        Bits128,
    }
}
