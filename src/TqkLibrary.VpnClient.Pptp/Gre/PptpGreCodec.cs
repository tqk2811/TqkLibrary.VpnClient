using System;
using System.Buffers.Binary;

namespace TqkLibrary.VpnClient.Pptp.Gre
{
    /// <summary>
    /// Stateless codec for the PPTP Enhanced GRE header (RFC 2637 §4.1). A pure encode/decode pair: it does not
    /// own sequence/ack state — the caller (the data-plane channel) supplies those per RFC 2637 §4.4.
    /// <para>
    /// Header layout (PPTP fixes C=0, R=0, K=1, s=0, Recur=0, Flags=0, Ver=1, ProtocolType=0x880B):
    /// </para>
    /// <list type="bullet">
    ///   <item>Byte 0 = <c>C R K S s Recur(3)</c> → 0x30 when a payload is present (K=1,S=1), 0x20 ack-only (K=1,S=0).</item>
    ///   <item>Byte 1 = <c>A Flags(4) Ver(3)</c> → 0x01 (no ack) or 0x81 (A=1).</item>
    ///   <item>Bytes 2-3 = Protocol Type 0x880B.</item>
    ///   <item>Bytes 4-5 = Key high word = payload length; bytes 6-7 = Key low word = Call ID.</item>
    ///   <item>If S=1: 4-byte Sequence Number (big-endian). If A=1: 4-byte Acknowledgment Number (big-endian). Then payload.</item>
    /// </list>
    /// </summary>
    public static class PptpGreCodec
    {
        const byte BitS = 0x10;            // byte0: Sequence Number present
        const byte BitK = 0x20;            // byte0: Key present (always set by PPTP)
        const byte BitA = 0x80;            // byte1: Acknowledgment Number present
        const byte VersionMask = 0x07;     // byte1: low 3 bits = GRE version
        const byte EnhancedVersion = 1;    // PPTP uses GRE version 1 (enhanced)

        /// <summary>The Enhanced GRE protocol type for PPP payloads (RFC 2637 §4.1).</summary>
        public const ushort ProtocolType = 0x880B;

        /// <summary>Encodes <paramref name="packet"/> into a fresh GRE datagram (the IP payload for proto-47).</summary>
        public static byte[] Encode(PptpGrePacket packet)
        {
            if (packet is null) throw new ArgumentNullException(nameof(packet));

            ReadOnlySpan<byte> payload = packet.Payload.Span;
            bool hasSeq = packet.SequenceNumber.HasValue;
            bool hasAck = packet.AckNumber.HasValue;

            int length = 8 + (hasSeq ? 4 : 0) + (hasAck ? 4 : 0) + payload.Length;
            byte[] buffer = new byte[length];

            buffer[0] = (byte)(BitK | (hasSeq ? BitS : 0));
            buffer[1] = (byte)((hasAck ? BitA : 0) | EnhancedVersion);
            BinaryPrimitives.WriteUInt16BigEndian(buffer.AsSpan(2), ProtocolType);
            BinaryPrimitives.WriteUInt16BigEndian(buffer.AsSpan(4), (ushort)payload.Length); // Key high word
            BinaryPrimitives.WriteUInt16BigEndian(buffer.AsSpan(6), packet.CallId);           // Key low word

            int offset = 8;
            if (hasSeq)
            {
                BinaryPrimitives.WriteUInt32BigEndian(buffer.AsSpan(offset), packet.SequenceNumber!.Value);
                offset += 4;
            }
            if (hasAck)
            {
                BinaryPrimitives.WriteUInt32BigEndian(buffer.AsSpan(offset), packet.AckNumber!.Value);
                offset += 4;
            }
            payload.CopyTo(buffer.AsSpan(offset));
            return buffer;
        }

        /// <summary>
        /// Decodes one GRE datagram. Returns <c>false</c> (and a null <paramref name="packet"/>) on any malformed
        /// input: wrong version, wrong protocol type, missing Key bit, or a truncated/over-long buffer.
        /// </summary>
        public static bool TryDecode(ReadOnlySpan<byte> datagram, out PptpGrePacket? packet)
        {
            packet = null;
            if (datagram.Length < 8) return false;

            byte byte0 = datagram[0];
            byte byte1 = datagram[1];

            if ((byte0 & BitK) == 0) return false;                          // PPTP always sets the Key bit
            if ((byte1 & VersionMask) != EnhancedVersion) return false;     // enhanced GRE only
            if (BinaryPrimitives.ReadUInt16BigEndian(datagram.Slice(2)) != ProtocolType) return false;

            ushort payloadLength = BinaryPrimitives.ReadUInt16BigEndian(datagram.Slice(4)); // Key high word
            ushort callId = BinaryPrimitives.ReadUInt16BigEndian(datagram.Slice(6));        // Key low word

            bool hasSeq = (byte0 & BitS) != 0;
            bool hasAck = (byte1 & BitA) != 0;

            int offset = 8;
            uint? sequence = null;
            uint? ack = null;
            if (hasSeq)
            {
                if (datagram.Length < offset + 4) return false;
                sequence = BinaryPrimitives.ReadUInt32BigEndian(datagram.Slice(offset));
                offset += 4;
            }
            if (hasAck)
            {
                if (datagram.Length < offset + 4) return false;
                ack = BinaryPrimitives.ReadUInt32BigEndian(datagram.Slice(offset));
                offset += 4;
            }

            // Remaining bytes are the payload; the declared length must match what is actually present.
            int remaining = datagram.Length - offset;
            if (remaining < 0) return false;
            if (hasSeq)
            {
                if (payloadLength != remaining) return false; // a payload packet declares its exact length
            }
            else if (remaining != 0)
            {
                return false; // ack-only packet must carry no payload
            }

            byte[] payload = remaining > 0 ? datagram.Slice(offset, remaining).ToArray() : Array.Empty<byte>();
            packet = new PptpGrePacket
            {
                CallId = callId,
                SequenceNumber = sequence,
                AckNumber = ack,
                Payload = payload,
            };
            return true;
        }
    }
}
