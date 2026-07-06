namespace TqkLibrary.VpnClient.Drivers.L2tpv3Eth.Enums
{
    /// <summary>
    /// Why <see cref="L2tpv3DataHeader.TryDecodeData"/> accepted or dropped a datagram. <see cref="None"/> is the only
    /// success value; every other value names a distinct drop reason so the connection can log it and the offline tests can
    /// assert the exact rejection path (RFC 3931 §4.1 data message + RFC 4719 Ethernet pseudowire).
    /// </summary>
    public enum L2tpv3DecodeError
    {
        /// <summary>The datagram decoded to a valid data message for the expected session.</summary>
        None = 0,

        /// <summary>Fewer bytes than a Session ID (4) — too short to be an L2TPv3 data message.</summary>
        Runt,

        /// <summary>The T (control) bit is set in the first octet — this is a control message, not data; drop.</summary>
        ControlMessage,

        /// <summary>The Session ID is zero — reserved for the control channel (RFC 3931 §4.1); drop.</summary>
        ZeroSessionId,

        /// <summary>The Session ID does not match the locally configured session — the datagram is for another session; drop.</summary>
        SessionIdMismatch,

        /// <summary>The Cookie does not match the configured value — anti-spoofing check failed (RFC 3931 §4.1); drop.</summary>
        CookieMismatch,

        /// <summary>The datagram is too short to hold the declared Cookie / L2-Specific Sublayer — truncated header; drop.</summary>
        Truncated,
    }
}
