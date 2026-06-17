namespace TqkLibrary.VpnClient.Pptp.Enums
{
    /// <summary>
    /// Framing Capabilities bitmask (4 bytes) in Start-Control-Connection-Request/Reply (RFC 2637 §2.1/§2.2):
    /// the types of framing the peer can provide.
    /// </summary>
    [System.Flags]
    public enum PptpFramingCapability : uint
    {
        /// <summary>No framing capabilities advertised.</summary>
        None = 0,

        /// <summary>Asynchronous Framing supported (bit 0).</summary>
        Asynchronous = 0x00000001,

        /// <summary>Synchronous Framing supported (bit 1).</summary>
        Synchronous = 0x00000002,
    }
}
