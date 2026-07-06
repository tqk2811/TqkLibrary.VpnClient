using System;

namespace TqkLibrary.VpnClient.Drivers.GtpU
{
    /// <summary>
    /// Stateless codec + parse result for the GTP-U (GPRS Tunnelling Protocol, User plane) header
    /// (3GPP TS 29.281). A pure encode/decode pair holding no tunnel state — the mandatory 8-byte header, the optional
    /// 4-byte block (Sequence Number / N-PDU Number / Next-Extension-Header-Type, present when any of the E/S/PN flags is
    /// set) and any chain of extension headers (each: <c>Length(1)</c> in 4-octet units ‖ content ‖ next-type(1), repeated
    /// until next-type 0). Layout of the mandatory header:
    /// <list type="bullet">
    ///   <item>Byte 0 = <c>Version(3) | PT(1) | spare(1) | E(1) | S(1) | PN(1)</c> — Version is <b>1</b> for GTPv1,
    ///   PT is 1 for GTP (not GTP'), and E/S/PN say whether the optional block + extension headers are present.</item>
    ///   <item>Byte 1 = <c>Message Type</c> — <b>255 = G-PDU</b> (user data); 1/2 = Echo Request/Response, 26 = Error
    ///   Indication (control/management).</item>
    ///   <item>Bytes 2-3 = <c>Length</c> (big-endian) — the number of octets <i>after</i> the 8-byte mandatory header
    ///   (optional block + extension headers + payload); it does NOT count the 8 mandatory bytes.</item>
    ///   <item>Bytes 4-7 = <c>TEID</c> (32-bit big-endian) — the tunnel endpoint identifier.</item>
    /// </list>
    /// The encoder always emits a minimal G-PDU (Version 1, PT 1, E=PN=0, and S only when a sequence number is supplied).
    /// The decoder validates Version==1 and the Length field, reads the TEID + message type, walks the optional block and
    /// (when E is set) the extension-header chain <b>without interpreting unknown extensions</b> (they are skipped by
    /// length, per the spec's forward-compatibility rule), and reports the inner-packet offset/length.
    /// </summary>
    public readonly struct GtpUHeader
    {
        /// <summary>The fixed length of the mandatory GTP-U header, before the optional block or any payload.</summary>
        public const int BaseLength = 8;

        /// <summary>The length of the optional block (Sequence Number 2B + N-PDU Number 1B + Next-Ext-Header-Type 1B), present when any of E/S/PN is set.</summary>
        public const int OptionalBlockLength = 4;

        /// <summary>The GTP version carried in the top 3 bits of byte 0. Always 1 for GTPv1 (GTP-U).</summary>
        public const byte Version1 = 1;

        /// <summary>Message Type 1 — Echo Request (path-management control message, not user data).</summary>
        public const byte MessageTypeEchoRequest = 1;

        /// <summary>Message Type 2 — Echo Response (path-management control message, not user data).</summary>
        public const byte MessageTypeEchoResponse = 2;

        /// <summary>Message Type 26 — Error Indication (signals an unknown TEID; not user data).</summary>
        public const byte MessageTypeErrorIndication = 26;

        /// <summary>Message Type 255 — G-PDU: the user-plane message that carries an inner IP packet.</summary>
        public const byte MessageTypeGPdu = 255;

        const int VersionShift = 5;      // byte 0, bits 0-2: Version (top 3 bits)
        const byte VersionMask = 0x07;
        const byte ProtocolTypeBit = 0x10; // byte 0, bit 3: PT (1 = GTP, 0 = GTP')
        const byte ExtensionFlag = 0x04;   // byte 0, bit 5: E (extension header present)
        const byte SequenceFlag = 0x02;    // byte 0, bit 6: S (sequence number present)
        const byte NpduFlag = 0x01;        // byte 0, bit 7: PN (N-PDU number present)

        /// <summary>Creates a parsed header result.</summary>
        public GtpUHeader(byte messageType, uint teid, bool hasSequence, ushort sequenceNumber, int payloadOffset, int payloadLength)
        {
            MessageType = messageType;
            Teid = teid;
            HasSequence = hasSequence;
            SequenceNumber = sequenceNumber;
            PayloadOffset = payloadOffset;
            PayloadLength = payloadLength;
        }

        /// <summary>The GTP-U message type (byte 1); <see cref="MessageTypeGPdu"/> = 255 for user data.</summary>
        public byte MessageType { get; }

        /// <summary>The 32-bit Tunnel Endpoint Identifier (bytes 4-7).</summary>
        public uint Teid { get; }

        /// <summary>Whether the S (Sequence Number present) flag was set.</summary>
        public bool HasSequence { get; }

        /// <summary>The 16-bit Sequence Number from the optional block (meaningful only when <see cref="HasSequence"/>).</summary>
        public ushort SequenceNumber { get; }

        /// <summary>The index at which the inner payload begins (after the mandatory header, optional block and any extension headers).</summary>
        public int PayloadOffset { get; }

        /// <summary>The length of the inner payload (the G-PDU inner IP packet); may be 0 for a header-only datagram.</summary>
        public int PayloadLength { get; }

        /// <summary>True when this is a G-PDU (message type 255) — the user-plane message that carries an inner IP packet.</summary>
        public bool IsGPdu => MessageType == MessageTypeGPdu;

        /// <summary>
        /// Encodes a minimal GTP-U <b>G-PDU</b> (message type 255) carrying <paramref name="payload"/> (an inner IP packet)
        /// under the given <paramref name="teid"/>. When <paramref name="sequenceNumber"/> is supplied the S flag is set and
        /// the 4-byte optional block is emitted (Sequence Number + N-PDU 0 + Next-Ext-Header-Type 0); otherwise no optional
        /// block is emitted (E=S=PN=0). The Length field is set to the number of octets after the mandatory 8-byte header.
        /// </summary>
        public static byte[] Encode(uint teid, ReadOnlySpan<byte> payload, ushort? sequenceNumber = null)
        {
            bool withSequence = sequenceNumber.HasValue;
            int optional = withSequence ? OptionalBlockLength : 0;
            byte[] buffer = new byte[BaseLength + optional + payload.Length];

            byte flags = (byte)((Version1 << VersionShift) | ProtocolTypeBit);
            if (withSequence) flags |= SequenceFlag;
            buffer[0] = flags;
            buffer[1] = MessageTypeGPdu;

            int lengthAfterHeader = optional + payload.Length;
            buffer[2] = (byte)(lengthAfterHeader >> 8);
            buffer[3] = (byte)lengthAfterHeader;

            buffer[4] = (byte)(teid >> 24);
            buffer[5] = (byte)(teid >> 16);
            buffer[6] = (byte)(teid >> 8);
            buffer[7] = (byte)teid;

            int offset = BaseLength;
            if (withSequence)
            {
                ushort sequence = sequenceNumber!.Value;
                buffer[offset] = (byte)(sequence >> 8);
                buffer[offset + 1] = (byte)sequence;
                buffer[offset + 2] = 0; // N-PDU Number (unused)
                buffer[offset + 3] = 0; // Next Extension Header Type (none)
                offset += OptionalBlockLength;
            }

            payload.CopyTo(buffer.AsSpan(offset));
            return buffer;
        }

        /// <summary>
        /// Decodes one GTP-U datagram. Returns <c>false</c> (with <paramref name="header"/> defaulted) on any input that is
        /// not a well-formed GTPv1 message: shorter than the 8-byte mandatory header, a Version other than 1, a Length field
        /// that claims more octets than are present, a truncated optional block, or an extension-header chain that runs past
        /// the declared message end (or an extension whose length is 0). On success <paramref name="header"/> carries the
        /// message type, TEID, sequence flag/number and the inner payload's offset + length. Extension headers are skipped
        /// by length without interpreting them (unknown extensions are tolerated, per TS 29.281).
        /// </summary>
        public static bool TryDecode(ReadOnlySpan<byte> datagram, out GtpUHeader header)
        {
            header = default;
            if (datagram.Length < BaseLength) return false; // runt

            byte flags = datagram[0];
            if (((flags >> VersionShift) & VersionMask) != Version1) return false; // GTPv1 only

            bool hasExtension = (flags & ExtensionFlag) != 0;
            bool hasSequence = (flags & SequenceFlag) != 0;
            bool hasNpdu = (flags & NpduFlag) != 0;

            byte messageType = datagram[1];
            int declaredLength = (datagram[2] << 8) | datagram[3];
            int messageEnd = BaseLength + declaredLength;
            if (messageEnd > datagram.Length) return false; // Length field claims more than is present

            uint teid = ((uint)datagram[4] << 24) | ((uint)datagram[5] << 16) | ((uint)datagram[6] << 8) | datagram[7];

            int offset = BaseLength;
            ushort sequenceNumber = 0;
            byte nextExtensionType = 0;
            if (hasExtension || hasSequence || hasNpdu)
            {
                if (offset + OptionalBlockLength > messageEnd) return false; // optional block truncated
                sequenceNumber = (ushort)((datagram[offset] << 8) | datagram[offset + 1]);
                // datagram[offset + 2] = N-PDU Number (ignored)
                nextExtensionType = datagram[offset + 3];
                offset += OptionalBlockLength;
            }

            if (hasExtension)
            {
                // Each extension header: Length(1, in 4-octet units, covering the length byte, content and next-type byte)
                // ‖ content ‖ Next-Extension-Header-Type(1). Walk the chain until next-type is 0, skipping unknown ones.
                while (nextExtensionType != 0)
                {
                    if (offset >= messageEnd) return false;
                    int units = datagram[offset];
                    if (units == 0) return false; // malformed (a 0-length extension would never terminate)
                    int extensionLength = units * 4;
                    if (offset + extensionLength > messageEnd) return false; // extension header truncated
                    nextExtensionType = datagram[offset + extensionLength - 1];
                    offset += extensionLength;
                }
            }

            int payloadLength = messageEnd - offset;
            if (payloadLength < 0) return false;

            header = new GtpUHeader(messageType, teid, hasSequence, sequenceNumber, offset, payloadLength);
            return true;
        }
    }
}
