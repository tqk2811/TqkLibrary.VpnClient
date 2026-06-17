using TqkLibrary.VpnClient.Pptp.Enums;
using TqkLibrary.VpnClient.Pptp.Interfaces;

namespace TqkLibrary.VpnClient.Pptp.Models
{
    /// <summary>
    /// Call-Disconnect-Notify (RFC 2637 §2.13) — the PAC tells the PNS that a call has been disconnected (either
    /// in response to a <see cref="CallClearRequest"/> or unsolicited). Body: CallID(2), ResultCode(1), ErrorCode(1),
    /// CauseCode(2), Reserved1(2), CallStatistics(128, ASCII NUL-padded).
    /// </summary>
    public sealed class CallDisconnectNotify : IPptpControlMessage
    {
        /// <summary>The fixed size of the Call Statistics field (RFC 2637 §2.13).</summary>
        public const int CallStatisticsLength = 128;

        /// <inheritdoc/>
        public PptpControlMessageType ControlMessageType => PptpControlMessageType.CallDisconnectNotify;

        /// <summary>The Call ID (assigned by the PAC) of the disconnected call.</summary>
        public ushort CallId { get; set; }

        /// <summary>Reason the call was disconnected (1 = lost carrier, 2 = general error, 3 = admin shutdown, 4 = request).</summary>
        public PptpResultCode ResultCode { get; set; }

        /// <summary>Error code (valid on a general error result).</summary>
        public byte ErrorCode { get; set; }

        /// <summary>Cause code — protocol/hardware-specific disconnect reason.</summary>
        public ushort CauseCode { get; set; }

        /// <summary>Vendor-specific call statistics — ASCII, NUL-padded to 128 bytes.</summary>
        public string CallStatistics { get; set; } = string.Empty;
    }
}
