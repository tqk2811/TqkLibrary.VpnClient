namespace TqkLibrary.VpnClient.Vtun.Wire.Enums
{
    /// <summary>What an inbound vtun frame header decodes to: a data frame (carrying a payload) or one of the control
    /// frames (zero-length, identified by the flag bits of the 2-byte header word).</summary>
    public enum VtunFrameType
    {
        /// <summary>A normal data frame — the header's top nibble is zero; <see cref="VtunFrameHeader.Length"/> bytes of payload follow.</summary>
        Data,

        /// <summary>A keepalive echo request (<c>VTUN_ECHO_REQ</c>) — the peer expects an echo reply.</summary>
        EchoRequest,

        /// <summary>A keepalive echo reply (<c>VTUN_ECHO_REP</c>).</summary>
        EchoReply,

        /// <summary>A connection-close control frame (<c>VTUN_CONN_CLOSE</c>).</summary>
        ConnClose,

        /// <summary>A bad/oversized frame the reader flagged (<c>VTUN_BAD_FRAME</c>) — drop it.</summary>
        BadFrame,
    }
}
