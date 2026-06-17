using System.Buffers.Binary;
using System.Collections.Generic;
using TqkLibrary.VpnClient.OpenConnect.Enums;
using TqkLibrary.VpnClient.OpenConnect.Models;

namespace TqkLibrary.VpnClient.OpenConnect
{
    /// <summary>
    /// CSTP (Cisco AnyConnect SSL transport) packet framing — the OpenConnect realisation of the F.2
    /// <c>IPacketEncapsulator</c> seam (cf. SSTP's 4-byte framing and OpenVPN's 2-byte TCP length prefix). On the
    /// CSTP-over-TLS byte stream every packet is prefixed with an 8-byte header:
    /// <code>
    /// 0x53 'S' | 0x54 'T' | 0x46 'F' | 0x01 | length(2, big-endian) | type(1) | 0x00
    /// </code>
    /// <see cref="Encode"/> frames one outgoing packet; the instance decoder (<see cref="Append"/> +
    /// <see cref="TryReadPacket"/>) reassembles whole packets across arbitrary TLS read boundaries. Re-implemented
    /// from the published wire behaviour (draft-mavrogiannopoulos-openconnect) — not copied from the GPL source.
    /// </summary>
    public sealed class CstpFraming
    {
        /// <summary>The fixed 8-byte CSTP header size.</summary>
        public const int HeaderSize = 8;

        /// <summary>The largest payload the 16-bit length field can carry.</summary>
        public const int MaxPayloadLength = 0xFFFF;

        // Magic / fixed bytes of the header. Bytes 0-2 spell "STF"; byte 3 is a fixed 0x01; byte 7 is a fixed 0x00.
        const byte Magic0 = 0x53; // 'S'
        const byte Magic1 = 0x54; // 'T'
        const byte Magic2 = 0x46; // 'F'
        const byte Fixed3 = 0x01;
        const byte Fixed7 = 0x00;

        readonly List<byte> _buffer = new();

        /// <summary>
        /// Frames one outgoing packet as the 8-byte header followed by <paramref name="payload"/>. Control packets
        /// (DPD/keep-alive/disconnect/terminate) pass an empty payload.
        /// </summary>
        public static byte[] Encode(CstpPacketType type, ReadOnlySpan<byte> payload)
        {
            if (payload.Length > MaxPayloadLength)
                throw new ArgumentOutOfRangeException(nameof(payload), "CSTP payload exceeds 65535 bytes.");

            byte[] framed = new byte[HeaderSize + payload.Length];
            framed[0] = Magic0;
            framed[1] = Magic1;
            framed[2] = Magic2;
            framed[3] = Fixed3;
            BinaryPrimitives.WriteUInt16BigEndian(framed.AsSpan(4, 2), (ushort)payload.Length);
            framed[6] = (byte)type;
            framed[7] = Fixed7;
            payload.CopyTo(framed.AsSpan(HeaderSize));
            return framed;
        }

        /// <summary>Frames a <see cref="CstpPacket"/> (convenience over the type/payload overload).</summary>
        public static byte[] Encode(CstpPacket packet)
        {
            if (packet is null) throw new ArgumentNullException(nameof(packet));
            return Encode(packet.Type, packet.Payload);
        }

        /// <summary>
        /// Decodes exactly one complete CSTP packet from <paramref name="frame"/> (header + full payload). Throws
        /// <see cref="FormatException"/> on a bad magic, a truncated header, or a length that does not match the buffer.
        /// Use the streaming decoder (<see cref="Append"/>/<see cref="TryReadPacket"/>) when reading off a byte stream.
        /// </summary>
        public static CstpPacket Decode(ReadOnlySpan<byte> frame)
        {
            if (frame.Length < HeaderSize)
                throw new FormatException("CSTP frame shorter than the 8-byte header.");
            ValidateHeader(frame);
            int length = BinaryPrimitives.ReadUInt16BigEndian(frame.Slice(4, 2));
            if (frame.Length != HeaderSize + length)
                throw new FormatException($"CSTP frame length {frame.Length} does not match declared payload {length} (+8 header).");
            return new CstpPacket((CstpPacketType)frame[6], frame.Slice(HeaderSize, length).ToArray());
        }

        /// <summary>Feeds a chunk of received stream bytes into the reassembly buffer.</summary>
        public void Append(ReadOnlySpan<byte> chunk)
        {
            // List<byte>.AddRange(ReadOnlySpan<byte>) isn't on netstandard2.0; reads are MTU-sized so a per-byte
            // append is acceptable (zero-alloc reassembly is a Q.4 concern, not a correctness one).
            foreach (byte b in chunk) _buffer.Add(b);
        }

        /// <summary>
        /// Pulls the next fully-received packet if one is buffered; call in a loop after each <see cref="Append"/>.
        /// Returns false (leaving the partial bytes buffered) until a complete header+payload has arrived. Throws
        /// <see cref="FormatException"/> if the buffered header magic is invalid (the stream is corrupt/desynced).
        /// </summary>
        public bool TryReadPacket(out CstpPacket packet)
        {
            packet = null!;
            if (_buffer.Count < HeaderSize) return false;

            Span<byte> header = stackalloc byte[HeaderSize];
            for (int i = 0; i < HeaderSize; i++) header[i] = _buffer[i];
            ValidateHeader(header);

            int length = (_buffer[4] << 8) | _buffer[5];
            if (_buffer.Count < HeaderSize + length) return false;

            byte[] payload = new byte[length];
            for (int i = 0; i < length; i++) payload[i] = _buffer[HeaderSize + i];
            _buffer.RemoveRange(0, HeaderSize + length);
            packet = new CstpPacket((CstpPacketType)header[6], payload);
            return true;
        }

        static void ValidateHeader(ReadOnlySpan<byte> header)
        {
            if (header[0] != Magic0 || header[1] != Magic1 || header[2] != Magic2 || header[3] != Fixed3)
                throw new FormatException("CSTP header magic invalid (expected 'STF' 0x01).");
        }
    }
}
