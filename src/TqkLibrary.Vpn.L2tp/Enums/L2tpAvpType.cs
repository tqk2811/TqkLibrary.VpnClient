namespace TqkLibrary.Vpn.L2tp.Enums
{
    /// <summary>L2TPv2 AVP attribute types used by this client (RFC 2661 §4.4).</summary>
    public enum L2tpAvpType : ushort
    {
        /// <summary>Message Type (must be the first AVP).</summary>
        MessageType = 0,

        /// <summary>Result Code (in StopCCN / CDN).</summary>
        ResultCode = 1,

        /// <summary>Protocol Version (e.g. 0x0100 = 1.0).</summary>
        ProtocolVersion = 2,

        /// <summary>Framing Capabilities (async/sync bitmask).</summary>
        FramingCapabilities = 3,

        /// <summary>Bearer Capabilities.</summary>
        BearerCapabilities = 4,

        /// <summary>Firmware Revision.</summary>
        FirmwareRevision = 6,

        /// <summary>Host Name.</summary>
        HostName = 7,

        /// <summary>Vendor Name.</summary>
        VendorName = 8,

        /// <summary>Assigned Tunnel ID (the sender's tunnel id the peer should address).</summary>
        AssignedTunnelId = 9,

        /// <summary>Receive Window Size (control-channel window).</summary>
        ReceiveWindowSize = 10,

        /// <summary>Challenge (tunnel CHAP).</summary>
        Challenge = 11,

        /// <summary>Challenge Response (tunnel CHAP).</summary>
        ChallengeResponse = 13,

        /// <summary>Assigned Session ID (the sender's session id the peer should address).</summary>
        AssignedSessionId = 14,

        /// <summary>Call Serial Number.</summary>
        CallSerialNumber = 15,

        /// <summary>Bearer Type.</summary>
        BearerType = 18,

        /// <summary>Framing Type.</summary>
        FramingType = 19,

        /// <summary>Called Number.</summary>
        CalledNumber = 21,

        /// <summary>Calling Number.</summary>
        CallingNumber = 22,

        /// <summary>(Tx) Connect Speed.</summary>
        TxConnectSpeed = 24,
    }
}
