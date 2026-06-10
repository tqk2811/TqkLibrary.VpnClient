namespace TqkLibrary.Vpn.IpStack
{
    /// <summary>
    /// Builds and reads ICMPv4 messages (RFC 792): Echo Request/Reply and Destination Unreachable.
    /// The checksum is the ones-complement sum over the whole ICMP message (no pseudo-header, unlike TCP/UDP).
    /// </summary>
    public static class Icmpv4
    {
        /// <summary>Echo Reply message type.</summary>
        public const byte TypeEchoReply = 0;

        /// <summary>Destination Unreachable message type.</summary>
        public const byte TypeDestinationUnreachable = 3;

        /// <summary>Echo Request message type.</summary>
        public const byte TypeEchoRequest = 8;

        /// <summary>Destination Unreachable code: port unreachable (RFC 792 §3.1).</summary>
        public const byte CodePortUnreachable = 3;

        /// <summary>Fixed ICMP header size in bytes: type(1) + code(1) + checksum(2) + rest-of-header(4).</summary>
        public const int HeaderSize = 8;

        /// <summary>Builds an Echo Request/Reply message (8-byte header + data) with a computed checksum.</summary>
        public static byte[] BuildEcho(byte type, ushort identifier, ushort sequence, ReadOnlySpan<byte> data)
        {
            byte[] msg = new byte[HeaderSize + data.Length];
            msg[0] = type;
            msg[1] = 0; // code is always 0 for echo
            // checksum (2..4) left zero for the computation
            msg[4] = (byte)(identifier >> 8); msg[5] = (byte)identifier;
            msg[6] = (byte)(sequence >> 8); msg[7] = (byte)sequence;
            data.CopyTo(msg.AsSpan(HeaderSize));
            WriteChecksum(msg);
            return msg;
        }

        /// <summary>
        /// Builds a Destination Unreachable message that quotes the offending datagram (its IP header plus the
        /// first 8 bytes of payload, per RFC 792).
        /// </summary>
        public static byte[] BuildDestinationUnreachable(byte code, ReadOnlySpan<byte> offendingIpPacket)
        {
            int quote = Math.Min(offendingIpPacket.Length, QuoteLength(offendingIpPacket));
            byte[] msg = new byte[HeaderSize + quote];
            msg[0] = TypeDestinationUnreachable;
            msg[1] = code;
            // checksum (2..4) + unused (4..8) left zero
            offendingIpPacket.Slice(0, quote).CopyTo(msg.AsSpan(HeaderSize));
            WriteChecksum(msg);
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

        /// <summary>The data after the 8-byte ICMP header (echo payload, or the quoted datagram for errors).</summary>
        public static ReadOnlyMemory<byte> Payload(ReadOnlyMemory<byte> msg) => msg.Slice(HeaderSize);

        /// <summary>True if the 16-bit ones-complement checksum over the whole message verifies (sum folds to 0).</summary>
        public static bool VerifyChecksum(ReadOnlySpan<byte> msg) => InternetChecksum.Compute(msg) == 0;

        // RFC 792: an error message quotes the original IP header + the first 8 bytes of its payload.
        static int QuoteLength(ReadOnlySpan<byte> ipPacket)
        {
            int ihl = ipPacket.Length > 0 ? (ipPacket[0] & 0x0F) * 4 : 20;
            if (ihl < 20) ihl = 20;
            return ihl + 8;
        }

        static void WriteChecksum(byte[] msg)
        {
            ushort checksum = InternetChecksum.Compute(msg);
            msg[2] = (byte)(checksum >> 8);
            msg[3] = (byte)checksum;
        }
    }
}
