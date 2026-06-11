using System.Net;
using TqkLibrary.Vpn.IpStack.Tcp.Enums;

namespace TqkLibrary.Vpn.IpStack.Tcp
{
    /// <summary>Builds and reads TCP segments (with the pseudo-header checksum).</summary>
    public static class TcpSegment
    {
        /// <summary>A <paramref name="windowScale"/> value meaning "no Window Scale option" (RFC 7323).</summary>
        public const byte NoWindowScale = 0xFF;

        /// <summary>The SACK-Permitted option kind (RFC 2018), carried on the SYN exchange to enable selective ACKs.</summary>
        public const byte SackPermittedKind = 4;

        /// <summary>The SACK option kind (RFC 2018), carrying selectively-acknowledged blocks on data ACKs.</summary>
        public const byte SackKind = 5;

        /// <summary>
        /// Builds a TCP segment. On a SYN, pass <paramref name="mss"/> &gt; 0 to include the MSS option (RFC 793),
        /// <paramref name="windowScale"/> ≠ <see cref="NoWindowScale"/> for the Window Scale option (RFC 7323), and
        /// <paramref name="sackPermitted"/> for the SACK-Permitted option (RFC 2018). On a data ACK, pass
        /// <paramref name="sackBlocks"/> as consecutive (leftEdge, rightEdge) pairs (at most 4 blocks) to include a
        /// SACK option. The options are padded to a 32-bit boundary with No-Operation bytes.
        /// </summary>
        public static byte[] Build(
            IPAddress sourceIp, IPAddress destinationIp,
            ushort sourcePort, ushort destinationPort,
            uint sequence, uint acknowledgment, TcpFlags flags, ushort window,
            ReadOnlySpan<byte> payload, ushort mss = 0, byte windowScale = NoWindowScale,
            bool sackPermitted = false, ReadOnlySpan<uint> sackBlocks = default)
        {
            // Up to 40 option bytes (the 4-bit data offset caps the header at 60 bytes). SYN-time options
            // (MSS/SACK-Permitted/Window Scale) and a data-time SACK block list are never combined by callers, so
            // they never collide within that ceiling.
            Span<byte> options = stackalloc byte[40];
            int optLen = 0;
            if (mss > 0)
            {
                options[optLen++] = 2; options[optLen++] = 4;               // MSS: kind 2, length 4
                options[optLen++] = (byte)(mss >> 8); options[optLen++] = (byte)mss;
            }
            if (sackPermitted)
            {
                options[optLen++] = SackPermittedKind; options[optLen++] = 2; // SACK-Permitted (RFC 2018): kind 4, length 2
            }
            if (windowScale != NoWindowScale)
            {
                options[optLen++] = 3; options[optLen++] = 3; options[optLen++] = windowScale; // Window Scale: kind 3, length 3
            }
            if (sackBlocks.Length >= 2)
            {
                int pairs = Math.Min(sackBlocks.Length / 2, 4);             // RFC 2018: at most 4 SACK blocks
                options[optLen++] = 1; options[optLen++] = 1;               // 2 NOPs to align the 8-byte block edges (RFC 2018 §3)
                options[optLen++] = SackKind; options[optLen++] = (byte)(2 + pairs * 8); // SACK: kind 5, length 2 + 8·blocks
                for (int b = 0; b < pairs; b++)
                {
                    PutU32(options, ref optLen, sackBlocks[b * 2]);         // left edge
                    PutU32(options, ref optLen, sackBlocks[b * 2 + 1]);     // right edge
                }
            }
            while ((optLen & 3) != 0) options[optLen++] = 1;                // pad to a 32-bit boundary with NOPs

            int headerLength = 20 + optLen;
            byte[] segment = new byte[headerLength + payload.Length];
            WriteU16(segment, 0, sourcePort);
            WriteU16(segment, 2, destinationPort);
            WriteU32(segment, 4, sequence);
            WriteU32(segment, 8, acknowledgment);
            segment[12] = (byte)((headerLength / 4) << 4); // data offset
            segment[13] = (byte)flags;
            WriteU16(segment, 14, window);
            // checksum (16..18) and urgent (18..20) left zero
            options.Slice(0, optLen).CopyTo(segment.AsSpan(20));
            payload.CopyTo(segment.AsSpan(headerLength));

            ushort checksum = Checksum(sourceIp, destinationIp, segment);
            WriteU16(segment, 16, checksum);
            return segment;
        }

        static ushort Checksum(IPAddress sourceIp, IPAddress destinationIp, ReadOnlySpan<byte> segment)
        {
            // Pseudo-header drives the address-family difference (4-byte IPv4 vs 16-byte IPv6 addresses); the rest is identical.
            uint sum = InternetChecksum.PseudoHeaderSum(sourceIp, destinationIp, 6 /* TCP */, segment.Length);
            for (int i = 0; i + 1 < segment.Length; i += 2)
                sum += (uint)((segment[i] << 8) | segment[i + 1]);
            if ((segment.Length & 1) != 0)
                sum += (uint)(segment[segment.Length - 1] << 8);
            return InternetChecksum.Finish(sum);
        }

        /// <summary>Source port.</summary>
        public static ushort SourcePort(ReadOnlySpan<byte> s) => (ushort)((s[0] << 8) | s[1]);

        /// <summary>Destination port.</summary>
        public static ushort DestinationPort(ReadOnlySpan<byte> s) => (ushort)((s[2] << 8) | s[3]);

        /// <summary>Sequence number.</summary>
        public static uint Sequence(ReadOnlySpan<byte> s) => ReadU32(s, 4);

        /// <summary>Acknowledgment number.</summary>
        public static uint Acknowledgment(ReadOnlySpan<byte> s) => ReadU32(s, 8);

        /// <summary>Header length in bytes (data offset * 4).</summary>
        public static int DataOffset(ReadOnlySpan<byte> s) => (s[12] >> 4) * 4;

        /// <summary>Control flags.</summary>
        public static TcpFlags Flags(ReadOnlySpan<byte> s) => (TcpFlags)s[13];

        /// <summary>Advertised window.</summary>
        public static ushort Window(ReadOnlySpan<byte> s) => (ushort)((s[14] << 8) | s[15]);

        /// <summary>The data payload after the TCP header.</summary>
        public static ReadOnlyMemory<byte> Payload(ReadOnlyMemory<byte> segment) => segment.Slice(DataOffset(segment.Span));

        /// <summary>Reads the Maximum Segment Size option (kind 2) from the TCP options, or 0 if no MSS option is present.</summary>
        public static ushort MaxSegmentSize(ReadOnlySpan<byte> segment)
        {
            int v = FindOption(segment, kind: 2, out int valueLength);
            return v >= 0 && valueLength == 2 ? (ushort)((segment[v] << 8) | segment[v + 1]) : (ushort)0;
        }

        /// <summary>Reads the Window Scale option (kind 3) shift count (RFC 7323), or <see cref="NoWindowScale"/> if absent.</summary>
        public static byte WindowScale(ReadOnlySpan<byte> segment)
        {
            int v = FindOption(segment, kind: 3, out int valueLength);
            return v >= 0 && valueLength == 1 ? segment[v] : NoWindowScale;
        }

        /// <summary>True if the segment carries the SACK-Permitted option (RFC 2018), offered on the SYN exchange.</summary>
        public static bool SackPermitted(ReadOnlySpan<byte> segment)
            => FindOption(segment, SackPermittedKind, out int valueLength) >= 0 && valueLength == 0;

        /// <summary>
        /// Reads the SACK option (kind 5) blocks into <paramref name="blocks"/> as consecutive (leftEdge, rightEdge)
        /// pairs and returns the block count (0 if no SACK option), capped by the destination span's capacity.
        /// </summary>
        public static int ReadSackBlocks(ReadOnlySpan<byte> segment, Span<uint> blocks)
        {
            int v = FindOption(segment, SackKind, out int valueLength);
            if (v < 0) return 0;
            int count = Math.Min(valueLength / 8, blocks.Length / 2);
            for (int b = 0; b < count; b++)
            {
                blocks[b * 2] = ReadU32(segment, v + b * 8);
                blocks[b * 2 + 1] = ReadU32(segment, v + b * 8 + 4);
            }
            return count;
        }

        // Walks the options between the fixed 20-byte header and the data offset, skipping End-of-List/No-Operation
        // padding and tolerating malformed/truncated options. Returns the value offset (just past kind+length) of the
        // first option matching <paramref name="kind"/> (and its value length), or -1 if not found.
        static int FindOption(ReadOnlySpan<byte> segment, byte kind, out int valueLength)
        {
            valueLength = 0;
            int dataOffset = Math.Min(DataOffset(segment), segment.Length);
            int i = 20;
            while (i < dataOffset)
            {
                byte optKind = segment[i];
                if (optKind == 0) break;              // End of Option List
                if (optKind == 1) { i++; continue; }  // No-Operation: a single byte with no length
                if (i + 1 >= dataOffset) break;        // truncated option header
                byte length = segment[i + 1];
                if (length < 2 || i + length > dataOffset) break; // malformed length
                if (optKind == kind) { valueLength = length - 2; return i + 2; }
                i += length;
            }
            return -1;
        }

        static void WriteU16(byte[] b, int o, ushort v) { b[o] = (byte)(v >> 8); b[o + 1] = (byte)v; }
        static void WriteU32(byte[] b, int o, uint v) { b[o] = (byte)(v >> 24); b[o + 1] = (byte)(v >> 16); b[o + 2] = (byte)(v >> 8); b[o + 3] = (byte)v; }
        static void PutU32(Span<byte> b, ref int o, uint v) { b[o++] = (byte)(v >> 24); b[o++] = (byte)(v >> 16); b[o++] = (byte)(v >> 8); b[o++] = (byte)v; }
        static uint ReadU32(ReadOnlySpan<byte> b, int o) => ((uint)b[o] << 24) | ((uint)b[o + 1] << 16) | ((uint)b[o + 2] << 8) | b[o + 3];
    }
}
