using System.Net;

namespace TqkLibrary.Vpn.IpStack
{
    /// <summary>Builds and reads minimal IPv4 packets (no options) for the userspace stack.</summary>
    public static class Ipv4
    {
        /// <summary>IP protocol numbers used by the stack.</summary>
        public const byte ProtocolTcp = 6;

        /// <summary>UDP protocol number.</summary>
        public const byte ProtocolUdp = 17;

        /// <summary>ICMP protocol number.</summary>
        public const byte ProtocolIcmp = 1;

        /// <summary>Builds an IPv4 packet (20-byte header, DF set) wrapping <paramref name="payload"/>.</summary>
        public static byte[] Build(IPAddress source, IPAddress destination, byte protocol, ReadOnlySpan<byte> payload, ushort identification)
        {
            byte[] packet = new byte[20 + payload.Length];
            packet[0] = 0x45;       // Version 4, IHL 5
            packet[1] = 0x00;       // DSCP/ECN
            int total = packet.Length;
            packet[2] = (byte)(total >> 8);
            packet[3] = (byte)total;
            packet[4] = (byte)(identification >> 8);
            packet[5] = (byte)identification;
            packet[6] = 0x40;       // Flags: Don't Fragment
            packet[7] = 0x00;       // Fragment offset
            packet[8] = 64;         // TTL
            packet[9] = protocol;
            // checksum (10..12) left zero for the computation
            source.GetAddressBytes().CopyTo(packet, 12);
            destination.GetAddressBytes().CopyTo(packet, 16);

            ushort checksum = InternetChecksum.Compute(packet.AsSpan(0, 20));
            packet[10] = (byte)(checksum >> 8);
            packet[11] = (byte)checksum;

            payload.CopyTo(packet.AsSpan(20));
            return packet;
        }

        /// <summary>
        /// Builds one fragment of an IPv4 datagram (20-byte header, no options). <paramref name="fragmentOffset"/>
        /// is the byte offset of <paramref name="payloadFragment"/> within the reassembled payload (must be a
        /// multiple of 8 except for the last fragment). Set <paramref name="moreFragments"/> on every fragment
        /// except the last. All fragments of one datagram must share <paramref name="identification"/>.
        /// </summary>
        public static byte[] BuildFragment(IPAddress source, IPAddress destination, byte protocol, ReadOnlySpan<byte> payloadFragment, ushort identification, int fragmentOffset, bool moreFragments)
        {
            byte[] packet = new byte[20 + payloadFragment.Length];
            packet[0] = 0x45;       // Version 4, IHL 5
            packet[1] = 0x00;       // DSCP/ECN
            int total = packet.Length;
            packet[2] = (byte)(total >> 8);
            packet[3] = (byte)total;
            packet[4] = (byte)(identification >> 8);
            packet[5] = (byte)identification;
            int units = fragmentOffset / 8;                 // fragment offset field counts 8-byte units
            byte flags = moreFragments ? (byte)0x20 : (byte)0x00; // MF bit (DF cleared on fragments)
            packet[6] = (byte)(flags | ((units >> 8) & 0x1F));
            packet[7] = (byte)units;
            packet[8] = 64;         // TTL
            packet[9] = protocol;
            // checksum (10..12) left zero for the computation
            source.GetAddressBytes().CopyTo(packet, 12);
            destination.GetAddressBytes().CopyTo(packet, 16);

            ushort checksum = InternetChecksum.Compute(packet.AsSpan(0, 20));
            packet[10] = (byte)(checksum >> 8);
            packet[11] = (byte)checksum;

            payloadFragment.CopyTo(packet.AsSpan(20));
            return packet;
        }

        /// <summary>Header length in bytes (IHL * 4).</summary>
        public static int HeaderLength(ReadOnlySpan<byte> packet) => (packet[0] & 0x0F) * 4;

        /// <summary>Total length of the datagram in bytes (header + payload) from the IPv4 length field.</summary>
        public static int TotalLength(ReadOnlySpan<byte> packet) => (packet[2] << 8) | packet[3];

        /// <summary>The 16-bit identification field (shared by all fragments of one datagram).</summary>
        public static ushort Identification(ReadOnlySpan<byte> packet) => (ushort)((packet[4] << 8) | packet[5]);

        /// <summary>True if the Don't-Fragment flag is set.</summary>
        public static bool DontFragment(ReadOnlySpan<byte> packet) => (packet[6] & 0x40) != 0;

        /// <summary>True if the More-Fragments flag is set (this is not the last fragment).</summary>
        public static bool MoreFragments(ReadOnlySpan<byte> packet) => (packet[6] & 0x20) != 0;

        /// <summary>Fragment offset in bytes (the 13-bit field value × 8).</summary>
        public static int FragmentOffset(ReadOnlySpan<byte> packet) => (((packet[6] & 0x1F) << 8) | packet[7]) * 8;

        /// <summary>The protocol field.</summary>
        public static byte Protocol(ReadOnlySpan<byte> packet) => packet[9];

        /// <summary>The source address.</summary>
        public static IPAddress Source(ReadOnlySpan<byte> packet) => new IPAddress(packet.Slice(12, 4).ToArray());

        /// <summary>The destination address.</summary>
        public static IPAddress Destination(ReadOnlySpan<byte> packet) => new IPAddress(packet.Slice(16, 4).ToArray());

        /// <summary>The payload (after the IP header).</summary>
        public static ReadOnlyMemory<byte> Payload(ReadOnlyMemory<byte> packet) => packet.Slice(HeaderLength(packet.Span));
    }
}
