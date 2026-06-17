using System;
using System.Net;

namespace TqkLibrary.VpnClient.Ethernet
{
    /// <summary>
    /// Builds and reads the DHCPv6 client/server message (RFC 8415 §8): a 4-byte fixed header
    /// <c>(msg-type: 1 byte, transaction-id: 3 bytes)</c> followed by the option field (see <see cref="Dhcpv6Options"/>).
    /// It also wraps a built message in a UDP/IPv6 packet (client port 546 → server port 547, destination the
    /// All_DHCP_Relay_Agents_and_Servers link-scoped multicast <c>ff02::1:2</c>) and reads one back, so the configurator
    /// can pump it through an <see cref="IEthernetChannel"/> exactly like DHCPv4 rides on top of UDP/IPv4 — the L2 layer
    /// never references the L3 <c>IpStack</c> project (it builds the IPv6 + UDP bytes itself, like <see cref="Icmpv6Ndisc"/>).
    /// <para>Mirrors the static, allocation-light codec style of <see cref="DhcpV4Packet"/> / <see cref="Icmpv6Ndisc"/>.</para>
    /// </summary>
    public static class Dhcpv6Packet
    {
        /// <summary>SOLICIT (1) — a client locates servers (RFC 8415 §7.3).</summary>
        public const byte MessageSolicit = 1;

        /// <summary>ADVERTISE (2) — a server offers itself in response to a SOLICIT.</summary>
        public const byte MessageAdvertise = 2;

        /// <summary>REQUEST (3) — a client requests addresses/config from a chosen server.</summary>
        public const byte MessageRequest = 3;

        /// <summary>REPLY (7) — a server's response to a REQUEST/RENEW/INFORMATION-REQUEST.</summary>
        public const byte MessageReply = 7;

        /// <summary>UDP port a DHCPv6 client receives on (RFC 8415 §7.2) — also the source port of client messages.</summary>
        public const ushort ClientPort = 546;

        /// <summary>UDP port DHCPv6 servers/relays listen on (RFC 8415 §7.2) — the destination port of client messages.</summary>
        public const ushort ServerPort = 547;

        /// <summary>The All_DHCP_Relay_Agents_and_Servers link-scoped multicast (ff02::1:2), RFC 8415 §7.1.</summary>
        public static readonly IPAddress AllRelayAgentsAndServers = IPAddress.Parse("ff02::1:2");

        const int Ipv6HeaderLength = 40;
        const int UdpHeaderLength = 8;
        const int MessageHeaderLength = 4;   // msg-type(1) + transaction-id(3)
        const byte UdpProtocol = 17;

        /// <summary>
        /// Builds a DHCPv6 message: the 1-byte <paramref name="messageType"/> + 3-byte <paramref name="transactionId"/>
        /// (low 24 bits) + the option field <paramref name="options"/>.
        /// </summary>
        public static byte[] Build(byte messageType, uint transactionId, ReadOnlySpan<byte> options)
        {
            byte[] message = new byte[MessageHeaderLength + options.Length];
            message[0] = messageType;
            message[1] = (byte)(transactionId >> 16);
            message[2] = (byte)(transactionId >> 8);
            message[3] = (byte)transactionId;
            options.CopyTo(message.AsSpan(MessageHeaderLength));
            return message;
        }

        /// <summary>The 1-byte message type (RFC 8415 §8).</summary>
        public static byte MessageType(ReadOnlySpan<byte> message) => message[0];

        /// <summary>The 24-bit transaction id (bytes 1..4).</summary>
        public static uint TransactionId(ReadOnlySpan<byte> message)
            => ((uint)message[1] << 16) | ((uint)message[2] << 8) | message[3];

        /// <summary>The option field (after the 4-byte header).</summary>
        public static ReadOnlyMemory<byte> OptionField(ReadOnlyMemory<byte> message) => message.Slice(MessageHeaderLength);

        // ---- UDP/IPv6 framing (so DHCPv6 can ride an IEthernetChannel without referencing the IpStack project) ----

        /// <summary>
        /// Wraps a built DHCPv6 <paramref name="dhcpMessage"/> in a UDP/IPv6 packet from <paramref name="source"/>:546 to
        /// <paramref name="destination"/>:547 (RFC 8415 §7.2). The UDP checksum (mandatory for IPv6, RFC 8200 §8.1) is
        /// computed here over the IPv6 pseudo-header.
        /// </summary>
        public static byte[] BuildUdpIpv6(IPAddress source, IPAddress destination, ushort sourcePort, ushort destinationPort, ReadOnlySpan<byte> dhcpMessage)
        {
            int udpLength = UdpHeaderLength + dhcpMessage.Length;
            byte[] packet = new byte[Ipv6HeaderLength + udpLength];

            // IPv6 header (RFC 8200 §3)
            packet[0] = 0x60;                       // version 6, traffic class / flow label 0
            packet[4] = (byte)(udpLength >> 8);     // payload length
            packet[5] = (byte)udpLength;
            packet[6] = UdpProtocol;                // next header = UDP
            packet[7] = 1;                          // hop limit 1 (link-scoped multicast stays on-link)
            source.GetAddressBytes().CopyTo(packet, 8);
            destination.GetAddressBytes().CopyTo(packet, 24);

            // UDP header (RFC 768)
            int udp = Ipv6HeaderLength;
            packet[udp] = (byte)(sourcePort >> 8);
            packet[udp + 1] = (byte)sourcePort;
            packet[udp + 2] = (byte)(destinationPort >> 8);
            packet[udp + 3] = (byte)destinationPort;
            packet[udp + 4] = (byte)(udpLength >> 8);
            packet[udp + 5] = (byte)udpLength;
            dhcpMessage.CopyTo(packet.AsSpan(udp + UdpHeaderLength));
            ushort udpChecksum = UdpChecksum(source, destination, packet.AsSpan(udp, udpLength));
            packet[udp + 6] = (byte)(udpChecksum >> 8);
            packet[udp + 7] = (byte)udpChecksum;
            return packet;
        }

        /// <summary>
        /// Extracts the DHCPv6 message from a UDP/IPv6 packet if it is a well-formed IPv6/UDP datagram destined for the
        /// DHCPv6 client port (546); returns <c>false</c> otherwise (slices without copying). Like the DHCPv4 reader, it
        /// does not verify the checksum (the server is trusted on this point-to-point/in-memory fabric).
        /// </summary>
        public static bool TryReadUdpIpv6(ReadOnlyMemory<byte> packet, out ReadOnlyMemory<byte> dhcpMessage)
        {
            dhcpMessage = default;
            ReadOnlySpan<byte> span = packet.Span;
            if (span.Length < Ipv6HeaderLength + UdpHeaderLength)
                return false;
            if ((byte)(span[0] >> 4) != 6)
                return false;                       // not IPv6
            if (span[6] != UdpProtocol)
                return false;                       // next header is not UDP (no extension-header walk needed here)
            int udp = Ipv6HeaderLength;
            int destPort = (span[udp + 2] << 8) | span[udp + 3];
            if (destPort != ClientPort)
                return false;                       // not addressed to the DHCPv6 client port
            int udpLength = (span[udp + 4] << 8) | span[udp + 5];
            if (udpLength < UdpHeaderLength || udp + udpLength > span.Length)
                return false;
            if (udpLength - UdpHeaderLength < MessageHeaderLength)
                return false;                       // smaller than a DHCPv6 header
            dhcpMessage = packet.Slice(udp + UdpHeaderLength, udpLength - UdpHeaderLength);
            return true;
        }

        // ---- Internals ----

        static ushort UdpChecksum(IPAddress source, IPAddress destination, ReadOnlySpan<byte> udpDatagram)
        {
            // IPv6 pseudo-header (RFC 8200 §8.1): src(16) + dst(16) + upper-layer length(4) + zero(3) + next-header(1).
            uint sum = 0;
            byte[] s = source.GetAddressBytes();
            byte[] d = destination.GetAddressBytes();
            for (int i = 0; i + 1 < s.Length; i += 2) sum += (uint)((s[i] << 8) | s[i + 1]);
            for (int i = 0; i + 1 < d.Length; i += 2) sum += (uint)((d[i] << 8) | d[i + 1]);
            sum += (uint)((udpDatagram.Length >> 16) & 0xFFFF);
            sum += (uint)(udpDatagram.Length & 0xFFFF);
            sum += UdpProtocol;
            sum += SumWords(udpDatagram);
            ushort folded = Fold(sum);
            return folded == 0 ? (ushort)0xFFFF : folded;   // RFC 8200: a computed 0 is transmitted as all-ones
        }

        static uint SumWords(ReadOnlySpan<byte> data)
        {
            uint sum = 0;
            int i = 0;
            for (; i + 1 < data.Length; i += 2) sum += (uint)((data[i] << 8) | data[i + 1]);
            if (i < data.Length) sum += (uint)(data[i] << 8);
            return sum;
        }

        static ushort Fold(uint sum)
        {
            while ((sum >> 16) != 0) sum = (sum & 0xFFFF) + (sum >> 16);
            return (ushort)~sum;
        }
    }
}
