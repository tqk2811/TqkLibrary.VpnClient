namespace TqkLibrary.VpnClient.Pptp.Enums
{
    /// <summary>
    /// PPTP control-message types carried in the 2-byte Control Message Type field of a control packet
    /// whose PPTP Message Type is <see cref="PptpMessageType.Control"/> (RFC 2637 §2.1, table in §2.13).
    /// </summary>
    public enum PptpControlMessageType : ushort
    {
        // ----- Control Connection Management -----
        /// <summary>Start-Control-Connection-Request (RFC 2637 §2.1).</summary>
        StartControlConnectionRequest = 1,

        /// <summary>Start-Control-Connection-Reply (RFC 2637 §2.2).</summary>
        StartControlConnectionReply = 2,

        /// <summary>Stop-Control-Connection-Request (RFC 2637 §2.3).</summary>
        StopControlConnectionRequest = 3,

        /// <summary>Stop-Control-Connection-Reply (RFC 2637 §2.4).</summary>
        StopControlConnectionReply = 4,

        /// <summary>Echo-Request (RFC 2637 §2.5).</summary>
        EchoRequest = 5,

        /// <summary>Echo-Reply (RFC 2637 §2.6).</summary>
        EchoReply = 6,

        // ----- Call Management -----
        /// <summary>Outgoing-Call-Request (RFC 2637 §2.7).</summary>
        OutgoingCallRequest = 7,

        /// <summary>Outgoing-Call-Reply (RFC 2637 §2.8).</summary>
        OutgoingCallReply = 8,

        /// <summary>Incoming-Call-Request (RFC 2637 §2.9).</summary>
        IncomingCallRequest = 9,

        /// <summary>Incoming-Call-Reply (RFC 2637 §2.10).</summary>
        IncomingCallReply = 10,

        /// <summary>Incoming-Call-Connected (RFC 2637 §2.11).</summary>
        IncomingCallConnected = 11,

        /// <summary>Call-Clear-Request (RFC 2637 §2.12).</summary>
        CallClearRequest = 12,

        /// <summary>Call-Disconnect-Notify (RFC 2637 §2.13).</summary>
        CallDisconnectNotify = 13,

        // ----- Error Reporting -----
        /// <summary>WAN-Error-Notify (RFC 2637 §2.14).</summary>
        WanErrorNotify = 14,

        // ----- PPP Session Control -----
        /// <summary>Set-Link-Info (RFC 2637 §2.15).</summary>
        SetLinkInfo = 15,
    }
}
