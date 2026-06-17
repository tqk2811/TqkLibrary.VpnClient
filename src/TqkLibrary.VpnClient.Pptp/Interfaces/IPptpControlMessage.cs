using TqkLibrary.VpnClient.Pptp.Enums;

namespace TqkLibrary.VpnClient.Pptp.Interfaces
{
    /// <summary>
    /// A typed PPTP control message body. Each concrete message knows its own
    /// <see cref="ControlMessageType"/>; <see cref="PptpControlCodec"/> uses it to write the 8-byte common
    /// header before the body bytes the message supplies.
    /// </summary>
    public interface IPptpControlMessage
    {
        /// <summary>The Control Message Type this message represents (RFC 2637 §2.1).</summary>
        PptpControlMessageType ControlMessageType { get; }
    }
}
