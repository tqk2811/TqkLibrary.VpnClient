using TqkLibrary.VpnClient.Pptp.Enums;
using TqkLibrary.VpnClient.Pptp.Interfaces;

namespace TqkLibrary.VpnClient.Pptp.Models
{
    /// <summary>
    /// Stop-Control-Connection-Reply (RFC 2637 §2.4) — answer to a <see cref="StopControlConnectionRequest"/>.
    /// Body: ResultCode(1), ErrorCode(1), Reserved1(2).
    /// </summary>
    public sealed class StopControlConnectionReply : IPptpControlMessage
    {
        /// <inheritdoc/>
        public PptpControlMessageType ControlMessageType => PptpControlMessageType.StopControlConnectionReply;

        /// <summary>Result code (1 = OK, the connection is closed).</summary>
        public PptpResultCode ResultCode { get; set; } = PptpResultCode.Successful;

        /// <summary>Error code (valid on a general error result).</summary>
        public byte ErrorCode { get; set; }
    }
}
