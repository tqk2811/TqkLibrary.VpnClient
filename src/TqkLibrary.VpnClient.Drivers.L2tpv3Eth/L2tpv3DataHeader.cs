using System;
using TqkLibrary.VpnClient.Drivers.L2tpv3Eth.Enums;

namespace TqkLibrary.VpnClient.Drivers.L2tpv3Eth
{
    /// <summary>
    /// The L2TPv3 (RFC 3931 §4.1) data-message codec for the static/unmanaged Ethernet pseudowire (RFC 4719) — pure,
    /// stateless. This driver runs the L2TPv3 <b>data</b> header directly in a UDP payload (the same header L2TPv3-over-IP
    /// carries as IP proto-115, but over an ordinary UDP socket so no raw socket / elevation is needed — the no-admin variant
    /// of roadmap V.8c). There is <b>no control plane</b>: the Session IDs and Cookie are configured statically on both peers
    /// (like a VXLAN static unicast tunnel), so only data messages ever cross the wire. The header is:
    /// <code>
    /// bytes 0-3 = Session ID (32-bit, big-endian; MUST be non-zero — 0 is the control channel; the top bit is the T/control
    ///             flag, so a data Session ID is 1..0x7FFFFFFF)
    /// bytes ..  = Cookie (0, 4 or 8 bytes, per session config — matched on both ends; anti-spoofing)
    /// bytes ..  = Default L2-Specific Sublayer (4 bytes) ONLY when sequencing is enabled (RFC 3931 §4.6): byte0 bit1 = S
    ///             (sequence present), bits 8-31 = 24-bit Sequence Number; big-endian
    /// bytes ..  = payload = a full Ethernet frame (RFC 4719 Ethernet pseudowire)
    /// </code>
    /// Everything after the header is the encapsulated Ethernet frame verbatim, which plugs into the userspace Ethernet
    /// fabric. This differs from Linux <c>ip l2tp ... encap udp</c>, which prepends an extra 4-byte version header before the
    /// Session ID; this driver matches the L2TPv3-over-IP data header placed directly in UDP (see the driver README).
    /// </summary>
    public static class L2tpv3DataHeader
    {
        /// <summary>The default L2TP UDP port (shared with L2TPv2; data vs control is told apart by the Session ID / T-bit).</summary>
        public const int DefaultPort = 1701;

        /// <summary>The Session ID field length in bytes (a 32-bit big-endian value at the start of every data message).</summary>
        public const int SessionIdLength = 4;

        /// <summary>The T (control) flag: the top bit of the first octet. Set on control messages; clear on data.</summary>
        public const byte ControlMessageBit = 0x80;

        /// <summary>The largest value a data Session ID may hold: 0x7FFFFFFF (the top bit is reserved as the T/control flag).</summary>
        public const uint MaxSessionId = 0x7FFFFFFF;

        /// <summary>The Default L2-Specific Sublayer length in bytes (RFC 3931 §4.6), present only when sequencing is on.</summary>
        public const int L2SpecificSublayerLength = 4;

        /// <summary>The S (Sequence-number present) bit in the first octet of the Default L2-Specific Sublayer (bit 1).</summary>
        public const byte SublayerSequenceBit = 0x40;

        /// <summary>The largest value the 24-bit Sequence Number in the Default L2-Specific Sublayer can hold (2^24 − 1).</summary>
        public const uint MaxSequenceNumber = 0xFFFFFF;

        /// <summary>Returns true when <paramref name="cookieLength"/> is a valid L2TPv3 Cookie length (0, 4 or 8 bytes).</summary>
        public static bool IsValidCookieLength(int cookieLength) => cookieLength == 0 || cookieLength == 4 || cookieLength == 8;

        /// <summary>Returns true when <paramref name="sessionId"/> is a valid data Session ID (non-zero, top bit clear).</summary>
        public static bool IsValidDataSessionId(uint sessionId) => sessionId != 0 && sessionId <= MaxSessionId;

        /// <summary>
        /// Encapsulates <paramref name="ethernetFrame"/> in an L2TPv3 data message: the 32-bit <paramref name="sessionId"/>
        /// (big-endian), the <paramref name="cookie"/> (0/4/8 bytes verbatim), an optional 4-byte Default L2-Specific
        /// Sublayer carrying <paramref name="sequenceNumber"/> when <paramref name="sequencing"/> is true, then the frame.
        /// On egress the caller passes the <b>remote</b> Session ID (the id the peer expects for its inbound session) and the
        /// shared Cookie.
        /// </summary>
        /// <exception cref="ArgumentOutOfRangeException"><paramref name="sessionId"/> is not a valid data Session ID, the
        /// cookie length is not 0/4/8, or the sequence number exceeds 24 bits.</exception>
        public static byte[] EncodeData(uint sessionId, ReadOnlySpan<byte> cookie, bool sequencing, uint sequenceNumber, ReadOnlySpan<byte> ethernetFrame)
        {
            if (!IsValidDataSessionId(sessionId))
                throw new ArgumentOutOfRangeException(nameof(sessionId), sessionId, "An L2TPv3 data Session ID must be non-zero and ≤ 0x7FFFFFFF (the top bit is the T/control flag).");
            if (!IsValidCookieLength(cookie.Length))
                throw new ArgumentOutOfRangeException(nameof(cookie), cookie.Length, "An L2TPv3 Cookie is 0, 4 or 8 bytes.");
            if (sequencing && sequenceNumber > MaxSequenceNumber)
                throw new ArgumentOutOfRangeException(nameof(sequenceNumber), sequenceNumber, "The L2TPv3 Sequence Number is a 24-bit value (0..0xFFFFFF).");

            int sublayerLength = sequencing ? L2SpecificSublayerLength : 0;
            int headerLength = SessionIdLength + cookie.Length + sublayerLength;
            byte[] datagram = new byte[headerLength + ethernetFrame.Length];

            datagram[0] = (byte)(sessionId >> 24);       // Session ID[31:24] (top bit clear ⇒ T = 0, data)
            datagram[1] = (byte)(sessionId >> 16);       // Session ID[23:16]
            datagram[2] = (byte)(sessionId >> 8);        // Session ID[15:8]
            datagram[3] = (byte)sessionId;               // Session ID[7:0]

            int offset = SessionIdLength;
            cookie.CopyTo(datagram.AsSpan(offset, cookie.Length));
            offset += cookie.Length;

            if (sequencing)
            {
                datagram[offset] = SublayerSequenceBit;              // S bit set, other flags 0
                datagram[offset + 1] = (byte)(sequenceNumber >> 16); // Sequence Number[23:16]
                datagram[offset + 2] = (byte)(sequenceNumber >> 8);  // [15:8]
                datagram[offset + 3] = (byte)sequenceNumber;         // [7:0]
                offset += L2SpecificSublayerLength;
            }

            ethernetFrame.CopyTo(datagram.AsSpan(offset));
            return datagram;
        }

        /// <summary>
        /// Decodes an L2TPv3 data message: rejects a runt / a control message (T-bit set) / the control-channel Session ID 0 /
        /// a Session ID that is not <paramref name="expectedSessionId"/> (the <b>local</b> session id) / a Cookie that does not
        /// match <paramref name="expectedCookie"/> / a header truncated before its Cookie + Sublayer end. On success it slices
        /// out the encapsulated Ethernet <paramref name="ethernetFrame"/> and, when <paramref name="sequencing"/> is set,
        /// reports the 24-bit <paramref name="sequenceNumber"/> from the Default L2-Specific Sublayer. The precise outcome is
        /// returned in <paramref name="error"/> (<see cref="L2tpv3DecodeError.None"/> on success).
        /// </summary>
        public static bool TryDecodeData(ReadOnlySpan<byte> datagram, uint expectedSessionId, ReadOnlySpan<byte> expectedCookie,
            bool sequencing, out uint sequenceNumber, out ReadOnlyMemory<byte> ethernetFrame, out L2tpv3DecodeError error)
        {
            sequenceNumber = 0;
            ethernetFrame = default;

            if (datagram.Length < SessionIdLength)
            {
                error = L2tpv3DecodeError.Runt;
                return false;
            }
            if ((datagram[0] & ControlMessageBit) != 0)
            {
                error = L2tpv3DecodeError.ControlMessage;     // T-bit set ⇒ control message, not data
                return false;
            }

            uint sessionId = ((uint)datagram[0] << 24) | ((uint)datagram[1] << 16) | ((uint)datagram[2] << 8) | datagram[3];
            if (sessionId == 0)
            {
                error = L2tpv3DecodeError.ZeroSessionId;       // Session ID 0 is the control channel
                return false;
            }
            if (sessionId != expectedSessionId)
            {
                error = L2tpv3DecodeError.SessionIdMismatch;
                return false;
            }

            int cookieLength = expectedCookie.Length;
            int sublayerLength = sequencing ? L2SpecificSublayerLength : 0;
            int headerLength = SessionIdLength + cookieLength + sublayerLength;
            if (datagram.Length < headerLength)
            {
                error = L2tpv3DecodeError.Truncated;
                return false;
            }

            if (cookieLength > 0 && !datagram.Slice(SessionIdLength, cookieLength).SequenceEqual(expectedCookie))
            {
                error = L2tpv3DecodeError.CookieMismatch;
                return false;
            }

            if (sequencing)
            {
                int s = SessionIdLength + cookieLength;
                sequenceNumber = ((uint)datagram[s + 1] << 16) | ((uint)datagram[s + 2] << 8) | datagram[s + 3];
            }

            ethernetFrame = datagram.Slice(headerLength).ToArray();
            error = L2tpv3DecodeError.None;
            return true;
        }
    }
}
