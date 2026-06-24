namespace TqkLibrary.VpnClient.Vtun.Wire
{
    /// <summary>
    /// Fixed sizes, flag bits and protocol constants of the vtun wire protocol (matching the C constants in
    /// <c>vtun.h</c> / <c>linkfd.h</c> of vtun 3.0.x). Pure data — no behavior.
    /// </summary>
    public static class VtunConstants
    {
        /// <summary>Default control/data port (<c>VTUN_PORT</c>).</summary>
        public const int DefaultPort = 5000;

        /// <summary>The fixed length of every authentication message block on the wire (<c>VTUN_MESG_SIZE</c>), NUL-padded.</summary>
        public const int MessageSize = 50;

        /// <summary>The authentication challenge length in bytes (<c>VTUN_CHAL_SIZE</c>).</summary>
        public const int ChallengeSize = 16;

        // ---- data-plane frame: the 2-byte big-endian header is (flags | length). Top 4 bits = flags, low 12 = length. ----

        /// <summary>Mask isolating the frame length from the header word (<c>VTUN_FSIZE_MASK</c>).</summary>
        public const ushort FrameSizeMask = 0x0fff;

        /// <summary>Maximum payload a single frame may carry (<c>VTUN_FRAME_SIZE</c>).</summary>
        public const int FrameSize = 2048;

        /// <summary>Allowance added to <see cref="FrameSize"/> when validating an inbound length (<c>VTUN_FRAME_OVERHEAD</c>).</summary>
        public const int FrameOverhead = 100;

        // ---- control-frame flags: a header word equal to one of these (length bits zero) is a control frame ----

        /// <summary>Connection-close control frame (<c>VTUN_CONN_CLOSE</c>).</summary>
        public const ushort ConnClose = 0x1000;

        /// <summary>Keepalive echo request (<c>VTUN_ECHO_REQ</c>) — answered with <see cref="EchoReply"/>.</summary>
        public const ushort EchoRequest = 0x2000;

        /// <summary>Keepalive echo reply (<c>VTUN_ECHO_REP</c>).</summary>
        public const ushort EchoReply = 0x4000;

        /// <summary>Bad/oversized frame marker returned by the reader (<c>VTUN_BAD_FRAME</c>).</summary>
        public const ushort BadFrame = 0x8000;
    }
}
