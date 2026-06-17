using TqkLibrary.VpnClient.Pptp.Enums;
using TqkLibrary.VpnClient.Pptp.Interfaces;

namespace TqkLibrary.VpnClient.Pptp.Models
{
    /// <summary>
    /// Set-Link-Info (RFC 2637 §2.15) — carries PPP-negotiated link options (the ACCM async control-character
    /// maps) from the PNS to the PAC so the PAC can frame async PPP correctly. Body: PeerCallID(2), Reserved1(2),
    /// SendACCM(4), ReceiveACCM(4). For a synchronous VPN link the ACCMs are typically 0xFFFFFFFF (escape nothing
    /// is not applicable) — the default 0xFFFFFFFF means "the link uses no async control-character mapping".
    /// </summary>
    public sealed class SetLinkInfo : IPptpControlMessage
    {
        /// <inheritdoc/>
        public PptpControlMessageType ControlMessageType => PptpControlMessageType.SetLinkInfo;

        /// <summary>The Call ID assigned by the peer (the receiver of this message).</summary>
        public ushort PeerCallId { get; set; }

        /// <summary>Send ACCM — the async control-character map for the send direction.</summary>
        public uint SendAccm { get; set; } = 0xFFFFFFFF;

        /// <summary>Receive ACCM — the async control-character map for the receive direction.</summary>
        public uint ReceiveAccm { get; set; } = 0xFFFFFFFF;
    }
}
