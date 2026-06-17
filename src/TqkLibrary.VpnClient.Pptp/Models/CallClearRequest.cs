using TqkLibrary.VpnClient.Pptp.Enums;
using TqkLibrary.VpnClient.Pptp.Interfaces;

namespace TqkLibrary.VpnClient.Pptp.Models
{
    /// <summary>
    /// Call-Clear-Request (RFC 2637 §2.12) — the PNS asks the PAC to disconnect a call. Body: CallID(2),
    /// Reserved1(2). The PAC answers with a <see cref="CallDisconnectNotify"/>.
    /// </summary>
    public sealed class CallClearRequest : IPptpControlMessage
    {
        /// <inheritdoc/>
        public PptpControlMessageType ControlMessageType => PptpControlMessageType.CallClearRequest;

        /// <summary>The Call ID (assigned by the PNS) of the call to clear.</summary>
        public ushort CallId { get; set; }
    }
}
