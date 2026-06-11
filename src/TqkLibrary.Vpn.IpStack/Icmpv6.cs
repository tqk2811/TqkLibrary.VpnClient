using System.Net;

namespace TqkLibrary.Vpn.IpStack
{
    /// <summary>
    /// Builds and reads ICMPv6 messages (RFC 4443): Echo Request/Reply, Destination Unreachable and Packet Too Big.
    /// Unlike ICMPv4, the checksum covers an IPv6 pseudo-header (RFC 8200 §8.1, next header 58) in addition to the
    /// ICMPv6 message, so build/verify take the source and destination addresses.
    /// </summary>
    public static class Icmpv6
    {
        /// <summary>Destination Unreachable message type.</summary>
        public const byte TypeDestinationUnreachable = 1;

        /// <summary>Packet Too Big message type (carries the next-hop MTU).</summary>
        public const byte TypePacketTooBig = 2;

        /// <summary>Time Exceeded message type.</summary>
        public const byte TypeTimeExceeded = 3;

        /// <summary>Parameter Problem message type.</summary>
        public const byte TypeParameterProblem = 4;

        /// <summary>Echo Request message type.</summary>
        public const byte TypeEchoRequest = 128;

        /// <summary>Echo Reply message type.</summary>
        public const byte TypeEchoReply = 129;

        /// <summary>Destination Unreachable code: port unreachable (RFC 4443 §3.1).</summary>
        public const byte CodePortUnreachable = 4;

        /// <summary>ICMPv6 next-header / protocol number used in the pseudo-header.</summary>
        public const byte ProtocolNumber = 58;

        /// <summary>Fixed ICMPv6 header size in bytes: type(1) + code(1) + checksum(2) + message-body(4).</summary>
        public const int HeaderSize = 8;

        // RFC 4443: an error message includes as much of the invoking packet as fits without exceeding the IPv6
        // minimum MTU (1280) — i.e. 1280 − outer IPv6 header (40) − ICMPv6 header (8).
        const int MaxErrorQuote = 1280 - Ipv6.HeaderLength - HeaderSize;

        /// <summary>Builds an Echo Request/Reply message (8-byte header + data) with a computed pseudo-header checksum.</summary>
        public static byte[] BuildEcho(byte type, ushort identifier, ushort sequence, ReadOnlySpan<byte> data, IPAddress source, IPAddress destination)
        {
            byte[] msg = new byte[HeaderSize + data.Length];
            msg[0] = type;
            msg[1] = 0; // code is always 0 for echo
            // checksum (2..4) left zero for the computation
            msg[4] = (byte)(identifier >> 8); msg[5] = (byte)identifier;
            msg[6] = (byte)(sequence >> 8); msg[7] = (byte)sequence;
            data.CopyTo(msg.AsSpan(HeaderSize));
            WriteChecksum(msg, source, destination);
            return msg;
        }

        /// <summary>
        /// Builds a Destination Unreachable message quoting as much of the offending packet as fits within the IPv6
        /// minimum MTU (RFC 4443 §3.1). The 4 bytes after the header are unused (zero).
        /// </summary>
        public static byte[] BuildDestinationUnreachable(byte code, ReadOnlySpan<byte> offendingIpPacket, IPAddress source, IPAddress destination)
        {
            int quote = Math.Min(offendingIpPacket.Length, MaxErrorQuote);
            byte[] msg = new byte[HeaderSize + quote];
            msg[0] = TypeDestinationUnreachable;
            msg[1] = code;
            // checksum (2..4) + unused (4..8) left zero
            offendingIpPacket.Slice(0, quote).CopyTo(msg.AsSpan(HeaderSize));
            WriteChecksum(msg, source, destination);
            return msg;
        }

        /// <summary>
        /// Builds a Packet Too Big message (RFC 4443 §3.2) carrying the next-hop link's <paramref name="mtu"/> in the
        /// 32-bit word after the checksum, quoting as much of the offending packet as fits within the IPv6 minimum MTU.
        /// Drives Path MTU Discovery (RFC 8201).
        /// </summary>
        public static byte[] BuildPacketTooBig(uint mtu, ReadOnlySpan<byte> offendingIpPacket, IPAddress source, IPAddress destination)
        {
            int quote = Math.Min(offendingIpPacket.Length, MaxErrorQuote);
            byte[] msg = new byte[HeaderSize + quote];
            msg[0] = TypePacketTooBig;
            msg[1] = 0; // code is always 0
            // checksum (2..4) left zero; bytes 4..8 carry the next-hop MTU (RFC 4443 §3.2).
            msg[4] = (byte)(mtu >> 24); msg[5] = (byte)(mtu >> 16); msg[6] = (byte)(mtu >> 8); msg[7] = (byte)mtu;
            offendingIpPacket.Slice(0, quote).CopyTo(msg.AsSpan(HeaderSize));
            WriteChecksum(msg, source, destination);
            return msg;
        }

        /// <summary>Message type.</summary>
        public static byte Type(ReadOnlySpan<byte> msg) => msg[0];

        /// <summary>Message code.</summary>
        public static byte Code(ReadOnlySpan<byte> msg) => msg[1];

        /// <summary>Echo identifier (Echo Request/Reply).</summary>
        public static ushort Identifier(ReadOnlySpan<byte> msg) => (ushort)((msg[4] << 8) | msg[5]);

        /// <summary>Echo sequence number (Echo Request/Reply).</summary>
        public static ushort Sequence(ReadOnlySpan<byte> msg) => (ushort)((msg[6] << 8) | msg[7]);

        /// <summary>Next-hop MTU carried by a Packet Too Big message (RFC 4443 §3.2).</summary>
        public static uint NextHopMtu(ReadOnlySpan<byte> msg) =>
            ((uint)msg[4] << 24) | ((uint)msg[5] << 16) | ((uint)msg[6] << 8) | msg[7];

        /// <summary>The data after the 8-byte ICMPv6 header (echo payload, or the quoted packet for errors).</summary>
        public static ReadOnlyMemory<byte> Payload(ReadOnlyMemory<byte> msg) => msg.Slice(HeaderSize);

        /// <summary>True if the pseudo-header checksum over the whole message verifies (sum folds to 0).</summary>
        public static bool VerifyChecksum(ReadOnlySpan<byte> msg, IPAddress source, IPAddress destination)
        {
            uint sum = InternetChecksum.PseudoHeaderSum(source, destination, ProtocolNumber, msg.Length);
            for (int i = 0; i + 1 < msg.Length; i += 2) sum += (uint)((msg[i] << 8) | msg[i + 1]);
            if ((msg.Length & 1) != 0) sum += (uint)(msg[msg.Length - 1] << 8);
            return InternetChecksum.Finish(sum) == 0;
        }

        static void WriteChecksum(byte[] msg, IPAddress source, IPAddress destination)
        {
            uint sum = InternetChecksum.PseudoHeaderSum(source, destination, ProtocolNumber, msg.Length);
            for (int i = 0; i + 1 < msg.Length; i += 2) sum += (uint)((msg[i] << 8) | msg[i + 1]);
            if ((msg.Length & 1) != 0) sum += (uint)(msg[msg.Length - 1] << 8);
            ushort checksum = InternetChecksum.Finish(sum);
            msg[2] = (byte)(checksum >> 8);
            msg[3] = (byte)checksum;
        }
    }
}
