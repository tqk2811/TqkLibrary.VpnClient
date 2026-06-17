namespace TqkLibrary.VpnClient.Pptp.Enums
{
    /// <summary>
    /// Bearer Capabilities bitmask (4 bytes) in Start-Control-Connection-Request/Reply (RFC 2637 §2.1/§2.2):
    /// the bearer-channel types the peer can provide.
    /// </summary>
    [System.Flags]
    public enum PptpBearerCapability : uint
    {
        /// <summary>No bearer capabilities advertised.</summary>
        None = 0,

        /// <summary>Analog access supported (bit 0).</summary>
        Analog = 0x00000001,

        /// <summary>Digital access supported (bit 1).</summary>
        Digital = 0x00000002,
    }
}
