namespace TqkLibrary.VpnClient.Pptp.Enums
{
    /// <summary>
    /// The PPTP Message Type field (2 bytes) that follows the 2-byte length in every PPTP packet header
    /// (RFC 2637 §2.1). Only control messages travel over the TCP/1723 control connection.
    /// </summary>
    public enum PptpMessageType : ushort
    {
        /// <summary>Control Message.</summary>
        Control = 1,

        /// <summary>Management Message (reserved, not used by this implementation).</summary>
        Management = 2,
    }
}
