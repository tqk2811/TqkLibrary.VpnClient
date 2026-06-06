namespace TqkLibrary.Vpn.L2tp.Enums
{
    /// <summary>L2TPv2 control message types, carried in the first (Message Type) AVP (RFC 2661 §4.4).</summary>
    public enum L2tpMessageType : ushort
    {
        /// <summary>Start-Control-Connection-Request (tunnel setup, initiator → peer).</summary>
        StartControlConnectionRequest = 1,

        /// <summary>Start-Control-Connection-Reply.</summary>
        StartControlConnectionReply = 2,

        /// <summary>Start-Control-Connection-Connected.</summary>
        StartControlConnectionConnected = 3,

        /// <summary>Stop-Control-Connection-Notification (tunnel teardown).</summary>
        StopControlConnectionNotification = 4,

        /// <summary>Hello (keepalive).</summary>
        Hello = 6,

        /// <summary>Incoming-Call-Request (session setup, initiator → peer).</summary>
        IncomingCallRequest = 10,

        /// <summary>Incoming-Call-Reply.</summary>
        IncomingCallReply = 11,

        /// <summary>Incoming-Call-Connected.</summary>
        IncomingCallConnected = 12,

        /// <summary>Call-Disconnect-Notify (session teardown).</summary>
        CallDisconnectNotify = 14,

        /// <summary>Set-Link-Info (PPP link parameters).</summary>
        SetLinkInfo = 16,
    }
}
