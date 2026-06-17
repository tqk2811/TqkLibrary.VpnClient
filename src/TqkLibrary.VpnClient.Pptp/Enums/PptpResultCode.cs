namespace TqkLibrary.VpnClient.Pptp.Enums
{
    /// <summary>
    /// General Result Code values that appear in several PPTP replies (RFC 2637). Each reply carries its own
    /// 1-byte Result Code; the values below cover Start-Control-Connection-Reply (§2.2), Stop-Control-Connection-Reply
    /// (§2.4), Outgoing-Call-Reply (§2.8) and Call-Disconnect-Notify (§2.13). A reply is successful only when its
    /// Result Code is <see cref="Successful"/> (1); any other value means the peer refused the request.
    /// </summary>
    public enum PptpResultCode : byte
    {
        /// <summary>Connection / call established successfully.</summary>
        Successful = 1,

        /// <summary>General error — Error Code (in the same message) gives the reason.</summary>
        GeneralError = 2,

        /// <summary>Command channel already exists (Start-Control-Connection-Reply only).</summary>
        ChannelAlreadyExists = 3,

        /// <summary>Requester is not authorised to establish a command channel.</summary>
        NotAuthorized = 4,

        /// <summary>The protocol version of the requester is not supported.</summary>
        UnsupportedProtocolVersion = 5,
    }
}
