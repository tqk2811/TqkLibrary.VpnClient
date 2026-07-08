using System.Buffers.Binary;

namespace TqkLibrary.VpnClient.Transport.WebSocket
{
    /// <summary>
    /// Stateless wire codec for the RFC 6455 §5 frame format. Re-implemented from the published RFC — not copied from any
    /// GPL/AGPL implementation, and deliberately independent of <c>System.Net.WebSockets</c> so the exact same byte layout
    /// is produced on both <c>netstandard2.0</c> and <c>net8.0</c> over any transport.
    /// <para>
    /// Frame layout (§5.2): byte 0 = <c>FIN(1)‖RSV(3)=0‖opcode(4)</c>; byte 1 = <c>MASK(1)‖payload-len(7)</c>. A 7-bit
    /// length of <c>126</c> means the next 2 bytes are a 16-bit big-endian length, <c>127</c> means the next 8 bytes are a
    /// 64-bit big-endian length. <b>Client→server frames MUST be masked (§5.3):</b> a 4-byte masking key follows the
    /// length and every payload byte is XORed as <c>transformed[i] = original[i] XOR maskKey[i % 4]</c>. Server→client
    /// frames are never masked. Control frames (§5.5, opcode bit <c>0x08</c>) MUST carry ≤ 125 payload bytes and FIN = 1.
    /// </para>
    /// </summary>
    public static class Rfc6455Frame
    {
        /// <summary>The RFC 6455 §5.3 masking-key length: four octets.</summary>
        public const int MaskingKeyLength = 4;

        /// <summary>The RFC 6455 §5.5 maximum payload of a control frame: 125 octets.</summary>
        public const int MaxControlPayloadLength = 125;

        /// <summary>
        /// Encodes one <b>masked client→server</b> frame (§5.3): FIN = 1, RSV = 0, the given <paramref name="opcode"/>,
        /// mask bit set, the 4-byte <paramref name="maskKey"/>, then the XOR-masked <paramref name="payload"/>. Throws
        /// <see cref="ArgumentException"/> when <paramref name="maskKey"/> is not exactly <see cref="MaskingKeyLength"/>
        /// bytes, or when a control-frame payload exceeds <see cref="MaxControlPayloadLength"/>.
        /// </summary>
        public static byte[] EncodeClientFrame(Rfc6455Opcode opcode, ReadOnlySpan<byte> payload, ReadOnlySpan<byte> maskKey)
        {
            if (maskKey.Length != MaskingKeyLength)
                throw new ArgumentException($"RFC 6455 masking key must be exactly {MaskingKeyLength} bytes.", nameof(maskKey));
            return Encode(opcode, payload, fin: true, masked: true, maskKey);
        }

        /// <summary>
        /// Encodes one <b>unmasked server→client</b> frame (§5.1): the mask bit is clear and the payload is copied
        /// verbatim. <paramref name="fin"/> defaults to <c>true</c>; pass <c>false</c> to emit the non-final frames of a
        /// fragmented data message (§5.4). Provided for completeness / test servers — a client only ever calls
        /// <see cref="EncodeClientFrame"/>.
        /// </summary>
        public static byte[] EncodeServerFrame(Rfc6455Opcode opcode, ReadOnlySpan<byte> payload, bool fin = true)
            => Encode(opcode, payload, fin, masked: false, default);

        static byte[] Encode(Rfc6455Opcode opcode, ReadOnlySpan<byte> payload, bool fin, bool masked, ReadOnlySpan<byte> maskKey)
        {
            bool isControl = ((byte)opcode & 0x08) != 0;
            if (isControl)
            {
                if (payload.Length > MaxControlPayloadLength)
                    throw new ArgumentException($"RFC 6455 control frame payload must be ≤ {MaxControlPayloadLength} bytes.", nameof(payload));
                if (!fin)
                    throw new ArgumentException("RFC 6455 control frames must not be fragmented (FIN = 1).", nameof(fin));
            }

            int extendedLenBytes = payload.Length <= 125 ? 0 : payload.Length <= ushort.MaxValue ? 2 : 8;
            int maskBytes = masked ? MaskingKeyLength : 0;
            int headerLength = 2 + extendedLenBytes + maskBytes;
            byte[] frame = new byte[headerLength + payload.Length];

            frame[0] = (byte)((fin ? 0x80 : 0x00) | ((byte)opcode & 0x0F)); // FIN‖RSV=0‖opcode

            int offset;
            if (payload.Length <= 125)
            {
                frame[1] = (byte)payload.Length;
                offset = 2;
            }
            else if (payload.Length <= ushort.MaxValue)
            {
                frame[1] = 126;
                BinaryPrimitives.WriteUInt16BigEndian(frame.AsSpan(2, 2), (ushort)payload.Length);
                offset = 4;
            }
            else
            {
                frame[1] = 127;
                BinaryPrimitives.WriteUInt64BigEndian(frame.AsSpan(2, 8), (ulong)payload.Length);
                offset = 10;
            }

            if (masked)
            {
                frame[1] |= 0x80; // MASK bit
                maskKey.CopyTo(frame.AsSpan(offset, MaskingKeyLength));
                int payloadStart = offset + MaskingKeyLength;
                for (int i = 0; i < payload.Length; i++)
                    frame[payloadStart + i] = (byte)(payload[i] ^ maskKey[i & 3]); // transformed[i] = original[i] XOR maskKey[i%4]
            }
            else
            {
                payload.CopyTo(frame.AsSpan(offset));
            }

            return frame;
        }

        /// <summary>
        /// Decodes the first whole frame at the front of <paramref name="buffer"/>. Returns <c>false</c> (leaving
        /// <paramref name="consumed"/> = 0) while the buffer holds only a partial frame — feed more bytes and retry. On
        /// success <paramref name="payload"/> is the decoded application bytes (already un-masked when the frame carried
        /// the mask bit) and <paramref name="consumed"/> is the total frame length to drop from the buffer. Throws
        /// <see cref="FormatException"/> only when a 64-bit declared length exceeds the addressable maximum
        /// (<see cref="int.MaxValue"/>), which cannot be satisfied.
        /// </summary>
        public static bool TryDecodeFrame(ReadOnlySpan<byte> buffer, out bool fin, out Rfc6455Opcode opcode, out byte[] payload, out int consumed)
        {
            fin = false;
            opcode = default;
            payload = Array.Empty<byte>();
            consumed = 0;

            if (buffer.Length < 2) return false;

            byte b0 = buffer[0];
            byte b1 = buffer[1];
            bool finBit = (b0 & 0x80) != 0;
            var op = (Rfc6455Opcode)(b0 & 0x0F);
            bool masked = (b1 & 0x80) != 0;
            int len7 = b1 & 0x7F;

            int offset;
            long payloadLength;
            if (len7 < 126)
            {
                payloadLength = len7;
                offset = 2;
            }
            else if (len7 == 126)
            {
                if (buffer.Length < 4) return false;
                payloadLength = BinaryPrimitives.ReadUInt16BigEndian(buffer.Slice(2, 2));
                offset = 4;
            }
            else // len7 == 127
            {
                if (buffer.Length < 10) return false;
                ulong len64 = BinaryPrimitives.ReadUInt64BigEndian(buffer.Slice(2, 8));
                if (len64 > int.MaxValue)
                    throw new FormatException($"RFC 6455 frame payload length {len64} exceeds the addressable maximum.");
                payloadLength = (long)len64;
                offset = 10;
            }

            ReadOnlySpan<byte> maskKey = default;
            if (masked)
            {
                if (buffer.Length < offset + MaskingKeyLength) return false;
                maskKey = buffer.Slice(offset, MaskingKeyLength);
                offset += MaskingKeyLength;
            }

            if (buffer.Length < offset + payloadLength) return false;

            int length = (int)payloadLength;
            ReadOnlySpan<byte> raw = buffer.Slice(offset, length);
            byte[] result = new byte[length];
            if (masked)
            {
                for (int i = 0; i < length; i++)
                    result[i] = (byte)(raw[i] ^ maskKey[i & 3]); // un-mask (XOR is its own inverse)
            }
            else
            {
                raw.CopyTo(result);
            }

            fin = finBit;
            opcode = op;
            payload = result;
            consumed = offset + length;
            return true;
        }
    }
}
