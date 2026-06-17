using TqkLibrary.VpnClient.Pptp.Enums;
using TqkLibrary.VpnClient.Pptp.Interfaces;

namespace TqkLibrary.VpnClient.Pptp.Models
{
    /// <summary>
    /// Echo-Reply (RFC 2637 §2.6) — the answer to an <see cref="EchoRequest"/>. Body: Identifier(4),
    /// ResultCode(1), ErrorCode(1), Reserved1(2). The <see cref="Identifier"/> must match the request.
    /// </summary>
    public sealed class EchoReply : IPptpControlMessage
    {
        /// <inheritdoc/>
        public PptpControlMessageType ControlMessageType => PptpControlMessageType.EchoReply;

        /// <summary>Identifier copied from the matching <see cref="EchoRequest"/>.</summary>
        public uint Identifier { get; set; }

        /// <summary>Result code (1 = OK).</summary>
        public PptpResultCode ResultCode { get; set; } = PptpResultCode.Successful;

        /// <summary>Error code (valid on a general error result).</summary>
        public byte ErrorCode { get; set; }
    }
}
