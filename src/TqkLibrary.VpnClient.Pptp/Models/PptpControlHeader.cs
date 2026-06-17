using TqkLibrary.VpnClient.Pptp.Enums;

namespace TqkLibrary.VpnClient.Pptp.Models
{
    /// <summary>
    /// The fixed 8-byte header common to every PPTP control message (RFC 2637 §2.1):
    /// <code>
    /// Length (2)  | PPTP Message Type (2) | Magic Cookie (4 = 0x1A2B3C4D)
    /// </code>
    /// followed by Control Message Type (2) + Reserved0 (2), then the message body. <see cref="Length"/> covers
    /// the whole packet (header + body). This model is what <see cref="PptpControlCodec"/> exposes after parsing
    /// the generic header; the typed body is parsed separately.
    /// </summary>
    public sealed class PptpControlHeader
    {
        /// <summary>The magic cookie that must appear in every control packet (RFC 2637 §2.1).</summary>
        public const uint MagicCookie = 0x1A2B3C4D;

        /// <summary>Total packet length in bytes (header + body), as carried in the first 2 bytes.</summary>
        public ushort Length { get; set; }

        /// <summary>PPTP Message Type — Control (1) or Management (2).</summary>
        public PptpMessageType MessageType { get; set; }

        /// <summary>Control Message Type (the specific control message).</summary>
        public PptpControlMessageType ControlMessageType { get; set; }
    }
}
