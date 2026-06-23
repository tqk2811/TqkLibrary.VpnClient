using System;
using System.Net;
using System.Net.Sockets;

namespace TqkLibrary.VpnClient.Ethernet
{
    /// <summary>
    /// Builds and reads the ICMPv6 Neighbor Discovery messages (RFC 4861) that ride directly inside an IPv6 packet
    /// inside an Ethernet frame (EtherType <see cref="EthernetFrame.EtherTypeIpv6"/>, IPv6 Next Header = 58): Router
    /// Solicitation/Advertisement (RS/RA) and Neighbor Solicitation/Advertisement (NS/NA), plus the options they carry
    /// (Source/Target Link-Layer Address, Prefix Information).
    /// <para>
    /// This codec lives in the Ethernet (L2) project on purpose. NDISC sits at the same layer as ARP and is consumed by
    /// <see cref="NdiscResolver"/> exactly where ARP's codec serves <see cref="ArpResolver"/>; putting it here keeps the
    /// L2 neighbor layer self-contained and avoids a horizontal dependency on the L3 <c>IpStack</c> project (which owns
    /// the generic <c>Icmpv6</c>/<c>Ipv6</c> codecs). Like <see cref="VirtualHost"/> reading IP header offsets directly,
    /// it builds/reads the IPv6 + ICMPv6 bytes itself — including the pseudo-header checksum (RFC 8200 §8.1).
    /// </para>
    /// Mirrors the static, allocation-light codec style of <see cref="ArpPacket"/> and <see cref="EthernetFrame"/>.
    /// </summary>
    public static class Icmpv6Ndisc
    {
        /// <summary>ICMPv6 next-header / protocol number (RFC 4443), used in the IPv6 pseudo-header.</summary>
        public const byte ProtocolNumber = 58;

        /// <summary>Router Solicitation message type (RFC 4861 §4.1).</summary>
        public const byte TypeRouterSolicitation = 133;

        /// <summary>Router Advertisement message type (RFC 4861 §4.2).</summary>
        public const byte TypeRouterAdvertisement = 134;

        /// <summary>Neighbor Solicitation message type (RFC 4861 §4.3).</summary>
        public const byte TypeNeighborSolicitation = 135;

        /// <summary>Neighbor Advertisement message type (RFC 4861 §4.4).</summary>
        public const byte TypeNeighborAdvertisement = 136;

        /// <summary>NDISC option type: Source Link-Layer Address (RFC 4861 §4.6.1).</summary>
        public const byte OptionSourceLinkLayerAddress = 1;

        /// <summary>NDISC option type: Target Link-Layer Address (RFC 4861 §4.6.1).</summary>
        public const byte OptionTargetLinkLayerAddress = 2;

        /// <summary>NDISC option type: Prefix Information (RFC 4861 §4.6.2).</summary>
        public const byte OptionPrefixInformation = 3;

        /// <summary>Neighbor Advertisement flag (in the first flag byte): Router (R).</summary>
        public const byte FlagRouter = 0x80;

        /// <summary>Neighbor Advertisement flag (in the first flag byte): Solicited (S).</summary>
        public const byte FlagSolicited = 0x40;

        /// <summary>Neighbor Advertisement flag (in the first flag byte): Override (O).</summary>
        public const byte FlagOverride = 0x20;

        /// <summary>Router Advertisement flag: Managed address configuration (M) — use stateful DHCPv6.</summary>
        public const byte RaFlagManaged = 0x80;

        /// <summary>Router Advertisement flag: Other configuration (O) — other config via DHCPv6.</summary>
        public const byte RaFlagOther = 0x40;

        /// <summary>Prefix Information flag: On-Link (L).</summary>
        public const byte PrefixFlagOnLink = 0x80;

        /// <summary>Prefix Information flag: Autonomous address-configuration (A) — usable for SLAAC.</summary>
        public const byte PrefixFlagAutonomous = 0x40;

        /// <summary>Hop limit for all NDISC messages (RFC 4861 §4 — must be 255 so off-link spoofing is rejected).</summary>
        public const byte NdiscHopLimit = 255;

        // ICMPv6 header: type(1) + code(1) + checksum(2) + body(4). The body layout differs per message.
        const int Icmpv6HeaderSize = 8;
        const int Ipv6HeaderLength = 40;

        /// <summary>The all-nodes link-local multicast address (ff02::1), destination of an unsolicited NA / RA.</summary>
        public static readonly IPAddress AllNodes = IPAddress.Parse("ff02::1");

        /// <summary>The all-routers link-local multicast address (ff02::2), destination of a Router Solicitation.</summary>
        public static readonly IPAddress AllRouters = IPAddress.Parse("ff02::2");

        /// <summary>The unspecified address (::), source of a Neighbor Solicitation sent for Duplicate Address Detection.</summary>
        public static readonly IPAddress Unspecified = IPAddress.IPv6Any;

        /// <summary>
        /// Computes the solicited-node multicast address for <paramref name="target"/> (RFC 4291 §2.7.1):
        /// <c>ff02::1:ff</c> followed by the low 24 bits of the target address. NS for address resolution and DAD is
        /// sent here so only hosts whose address shares those 24 bits need process it.
        /// </summary>
        public static IPAddress SolicitedNodeMulticast(IPAddress target)
        {
            if (target is null)
                throw new ArgumentNullException(nameof(target));
            if (target.AddressFamily != AddressFamily.InterNetworkV6)
                throw new ArgumentException("Solicited-node multicast is computed from an IPv6 address.", nameof(target));
            byte[] t = target.GetAddressBytes();
            byte[] m = new byte[16];
            m[0] = 0xFF; m[1] = 0x02;           // ff02::
            m[11] = 0x01; m[12] = 0xFF;         // ::1:ff
            m[13] = t[13]; m[14] = t[14]; m[15] = t[15];   // low 24 bits of the target
            return new IPAddress(m);
        }

        /// <summary>
        /// Maps an IPv6 multicast address to its Ethernet destination MAC (RFC 2464 §7): <c>33:33</c> followed by the
        /// last four bytes of the address. Used for NS (solicited-node multicast), RS (all-routers) and unsolicited
        /// NA/RA (all-nodes).
        /// </summary>
        public static MacAddress MulticastMac(IPAddress multicast)
        {
            if (multicast is null)
                throw new ArgumentNullException(nameof(multicast));
            byte[] a = multicast.GetAddressBytes();
            Span<byte> mac = stackalloc byte[MacAddress.Size];
            mac[0] = 0x33; mac[1] = 0x33;
            mac[2] = a[12]; mac[3] = a[13]; mac[4] = a[14]; mac[5] = a[15];
            return MacAddress.FromBytes(mac);
        }

        // ---- Builders ----

        /// <summary>
        /// Builds a Neighbor Solicitation (RFC 4861 §4.3) for <paramref name="target"/>. When <paramref name="source"/>
        /// is the unspecified address (::), this is a DAD probe and the Source Link-Layer Address option is omitted
        /// (RFC 4861 §4.3); otherwise the option carries <paramref name="sourceMac"/>.
        /// </summary>
        public static byte[] BuildNeighborSolicitation(IPAddress source, IPAddress destination, IPAddress target, MacAddress sourceMac)
        {
            bool dad = source.Equals(Unspecified);
            int optionLength = dad ? 0 : 8;          // Source LLA option: type(1)+len(1)+MAC(6)
            byte[] msg = new byte[Icmpv6HeaderSize + 16 + optionLength];
            msg[0] = TypeNeighborSolicitation;
            // code(1) + checksum(2) + reserved(4) left zero
            target.GetAddressBytes().CopyTo(msg, Icmpv6HeaderSize);
            if (!dad)
                WriteLinkLayerOption(msg, Icmpv6HeaderSize + 16, OptionSourceLinkLayerAddress, sourceMac);
            WriteIcmpv6Checksum(msg, source, destination);
            return msg;
        }

        /// <summary>
        /// Builds a Neighbor Advertisement (RFC 4861 §4.4) announcing that <paramref name="target"/> is at
        /// <paramref name="targetMac"/>, with the given R/S/O <paramref name="flags"/> and a Target Link-Layer Address
        /// option.
        /// </summary>
        public static byte[] BuildNeighborAdvertisement(IPAddress source, IPAddress destination, IPAddress target, MacAddress targetMac, byte flags)
        {
            byte[] msg = new byte[Icmpv6HeaderSize + 16 + 8];
            msg[0] = TypeNeighborAdvertisement;
            msg[4] = flags;                          // R/S/O in the high bits of the first reserved byte
            target.GetAddressBytes().CopyTo(msg, Icmpv6HeaderSize);
            WriteLinkLayerOption(msg, Icmpv6HeaderSize + 16, OptionTargetLinkLayerAddress, targetMac);
            WriteIcmpv6Checksum(msg, source, destination);
            return msg;
        }

        /// <summary>Builds a Router Solicitation (RFC 4861 §4.1) carrying a Source Link-Layer Address option.</summary>
        public static byte[] BuildRouterSolicitation(IPAddress source, IPAddress destination, MacAddress sourceMac)
        {
            byte[] msg = new byte[Icmpv6HeaderSize + 8];
            msg[0] = TypeRouterSolicitation;
            // code(1) + checksum(2) + reserved(4) left zero
            WriteLinkLayerOption(msg, Icmpv6HeaderSize, OptionSourceLinkLayerAddress, sourceMac);
            WriteIcmpv6Checksum(msg, source, destination);
            return msg;
        }

        /// <summary>
        /// Builds a Router Advertisement (RFC 4861 §4.2) advertising one on-link/autonomous prefix and the router's
        /// link-layer address — enough for the offline tests that exercise RA parsing into gateway + prefix.
        /// </summary>
        public static byte[] BuildRouterAdvertisement(IPAddress source, IPAddress destination, MacAddress routerMac, byte curHopLimit, ushort routerLifetimeSeconds, IPAddress prefix, byte prefixLength, byte prefixFlags, uint validLifetime, uint preferredLifetime)
        {
            // RA fixed body (RFC 4861 §4.2): curHopLimit(1)+flags(1)+routerLifetime(2) — the 4-byte word counted in
            // Icmpv6HeaderSize(8) — then reachable(4)+retrans(4), then options: Source LLA (8) + Prefix Information (32).
            // Options begin at byte 16 (must match OptionsOffsetFor(RA) and real-host RAs from radvd/Linux).
            const int raBodyAfterHeader = 8;        // ReachableTime(4) + RetransTimer(4): bytes 8..16
            byte[] msg = new byte[Icmpv6HeaderSize + raBodyAfterHeader + 8 + 32];
            msg[0] = TypeRouterAdvertisement;
            msg[4] = curHopLimit;
            // msg[5] = M/O flags left zero (no DHCPv6 in this advertisement)
            msg[6] = (byte)(routerLifetimeSeconds >> 8);
            msg[7] = (byte)routerLifetimeSeconds;
            // reachable time (8..12) + retrans timer (12..16) left zero
            int pos = Icmpv6HeaderSize + raBodyAfterHeader;
            WriteLinkLayerOption(msg, pos, OptionSourceLinkLayerAddress, routerMac);
            pos += 8;
            WritePrefixOption(msg, pos, prefix, prefixLength, prefixFlags, validLifetime, preferredLifetime);
            WriteIcmpv6Checksum(msg, source, destination);
            return msg;
        }

        /// <summary>Builds the IPv6 packet (40-byte header, hop limit 255) carrying an NDISC <paramref name="icmpv6Message"/>.</summary>
        public static byte[] BuildIpv6(IPAddress source, IPAddress destination, ReadOnlySpan<byte> icmpv6Message)
        {
            byte[] packet = new byte[Ipv6HeaderLength + icmpv6Message.Length];
            packet[0] = 0x60;                        // version 6, traffic class/flow label 0
            packet[4] = (byte)(icmpv6Message.Length >> 8);
            packet[5] = (byte)icmpv6Message.Length;
            packet[6] = ProtocolNumber;
            packet[7] = NdiscHopLimit;               // 255 — RFC 4861 §4
            source.GetAddressBytes().CopyTo(packet, 8);
            destination.GetAddressBytes().CopyTo(packet, 24);
            icmpv6Message.CopyTo(packet.AsSpan(Ipv6HeaderLength));
            return packet;
        }

        // ---- Readers ----

        /// <summary>ICMPv6 message type (first byte of the NDISC message).</summary>
        public static byte Type(ReadOnlySpan<byte> message) => message[0];

        /// <summary>True if <paramref name="message"/> is an ICMPv6 type this NDISC codec handles (RS/RA/NS/NA).</summary>
        public static bool IsNdisc(ReadOnlySpan<byte> message)
        {
            if (message.Length < Icmpv6HeaderSize) return false;
            byte type = message[0];
            return type == TypeRouterSolicitation || type == TypeRouterAdvertisement
                || type == TypeNeighborSolicitation || type == TypeNeighborAdvertisement;
        }

        /// <summary>The Target Address of an NS or NA message (the 16 bytes after the 8-byte ICMPv6 header).</summary>
        public static IPAddress TargetAddress(ReadOnlySpan<byte> message)
            => new IPAddress(message.Slice(Icmpv6HeaderSize, 16).ToArray());

        /// <summary>The R/S/O flag byte of a Neighbor Advertisement (byte 4 of the message).</summary>
        public static byte NaFlags(ReadOnlySpan<byte> message) => message[4];

        /// <summary>The Router Lifetime (seconds) of a Router Advertisement (a zero lifetime means "not a default router").</summary>
        public static ushort RouterLifetime(ReadOnlySpan<byte> raMessage) => (ushort)((raMessage[6] << 8) | raMessage[7]);

        /// <summary>The M/O flag byte of a Router Advertisement (byte 5 of the message).</summary>
        public static byte RaFlags(ReadOnlySpan<byte> raMessage) => raMessage[5];

        /// <summary>
        /// Reads the link-layer address carried by a Source/Target Link-Layer Address option (type 1 or 2) if present.
        /// <paramref name="optionsOffset"/> is where the options begin for the message: <see cref="OptionsOffsetFor"/>.
        /// </summary>
        public static bool TryGetLinkLayerAddress(ReadOnlySpan<byte> message, int optionsOffset, byte optionType, out MacAddress mac)
        {
            mac = default;
            int pos = optionsOffset;
            while (pos + 2 <= message.Length)
            {
                byte type = message[pos];
                int lenUnits = message[pos + 1];       // length in 8-byte units, including the 2-byte option header
                if (lenUnits == 0) return false;        // malformed: a zero-length option would loop forever
                int optLen = lenUnits * 8;
                if (pos + optLen > message.Length) return false;
                if (type == optionType && optLen >= 8)
                {
                    mac = MacAddress.FromBytes(message.Slice(pos + 2, MacAddress.Size));
                    return true;
                }
                pos += optLen;
            }
            return false;
        }

        /// <summary>
        /// Reads the first Prefix Information option (type 3) of a Router Advertisement if present (RFC 4861 §4.6.2).
        /// </summary>
        public static bool TryGetPrefixInformation(ReadOnlySpan<byte> raMessage, out IPAddress prefix, out byte prefixLength, out byte flags, out uint validLifetime, out uint preferredLifetime)
        {
            prefix = IPAddress.IPv6Any;
            prefixLength = 0;
            flags = 0;
            validLifetime = 0;
            preferredLifetime = 0;

            int pos = OptionsOffsetFor(TypeRouterAdvertisement);
            while (pos + 2 <= raMessage.Length)
            {
                byte type = raMessage[pos];
                int lenUnits = raMessage[pos + 1];
                if (lenUnits == 0) return false;
                int optLen = lenUnits * 8;
                if (pos + optLen > raMessage.Length) return false;
                if (type == OptionPrefixInformation && optLen >= 32)
                {
                    prefixLength = raMessage[pos + 2];
                    flags = raMessage[pos + 3];
                    validLifetime = ReadUInt32(raMessage, pos + 4);
                    preferredLifetime = ReadUInt32(raMessage, pos + 8);
                    // bytes 12..16 reserved; prefix is the 16-byte address at offset 16 of the option.
                    prefix = new IPAddress(raMessage.Slice(pos + 16, 16).ToArray());
                    return true;
                }
                pos += optLen;
            }
            return false;
        }

        /// <summary>The byte offset where the options begin for a given NDISC message type.</summary>
        public static int OptionsOffsetFor(byte messageType)
        {
            switch (messageType)
            {
                case TypeNeighborSolicitation:
                case TypeNeighborAdvertisement:
                    return Icmpv6HeaderSize + 16;       // 4-byte header word + 4-byte reserved/flags + 16-byte target
                case TypeRouterSolicitation:
                    return Icmpv6HeaderSize;            // 4-byte header word + 4-byte reserved
                case TypeRouterAdvertisement:
                    // RA header is 16 bytes before options (RFC 4861 §4.2): 4-byte ICMPv6 header + CurHopLimit/flags/
                    // RouterLifetime (the 4-byte word counted in Icmpv6HeaderSize=8) + ReachableTime(4) + RetransTimer(4).
                    return Icmpv6HeaderSize + 8;
                default:
                    return Icmpv6HeaderSize;
            }
        }

        /// <summary>True if the pseudo-header checksum over <paramref name="message"/> verifies (folds to 0).</summary>
        public static bool VerifyChecksum(ReadOnlySpan<byte> message, IPAddress source, IPAddress destination)
            => FinishChecksum(PseudoHeaderSum(source, destination, message.Length) + ChecksumBody(message)) == 0;

        // ---- Internals ----

        static void WriteLinkLayerOption(byte[] message, int offset, byte optionType, MacAddress mac)
        {
            message[offset] = optionType;
            message[offset + 1] = 1;                  // length = 1 × 8 bytes
            Span<byte> macBytes = stackalloc byte[MacAddress.Size];
            mac.CopyTo(macBytes);
            macBytes.CopyTo(message.AsSpan(offset + 2, MacAddress.Size));
        }

        static void WritePrefixOption(byte[] message, int offset, IPAddress prefix, byte prefixLength, byte flags, uint validLifetime, uint preferredLifetime)
        {
            message[offset] = OptionPrefixInformation;
            message[offset + 1] = 4;                  // length = 4 × 8 = 32 bytes
            message[offset + 2] = prefixLength;
            message[offset + 3] = flags;
            WriteUInt32(message, offset + 4, validLifetime);
            WriteUInt32(message, offset + 8, preferredLifetime);
            // bytes 12..16 reserved (zero)
            prefix.GetAddressBytes().CopyTo(message, offset + 16);
        }

        static void WriteIcmpv6Checksum(byte[] message, IPAddress source, IPAddress destination)
        {
            // The checksum field (bytes 2..4) must be zero while summing.
            message[2] = 0; message[3] = 0;
            ushort checksum = FinishChecksum(PseudoHeaderSum(source, destination, message.Length) + ChecksumBody(message));
            message[2] = (byte)(checksum >> 8);
            message[3] = (byte)checksum;
        }

        // IPv6 pseudo-header for the upper-layer checksum (RFC 8200 §8.1): 16-byte src + 16-byte dst + 32-bit
        // upper-layer length + 24 zero bits + next-header. Computed here instead of referencing the IpStack project
        // to keep the L2 codec free of a horizontal dependency.
        static uint PseudoHeaderSum(IPAddress source, IPAddress destination, int upperLayerLength)
        {
            uint sum = 0;
            byte[] s = source.GetAddressBytes();
            byte[] d = destination.GetAddressBytes();
            for (int i = 0; i + 1 < s.Length; i += 2) sum += (uint)((s[i] << 8) | s[i + 1]);
            for (int i = 0; i + 1 < d.Length; i += 2) sum += (uint)((d[i] << 8) | d[i + 1]);
            sum += (uint)((upperLayerLength >> 16) & 0xFFFF);
            sum += (uint)(upperLayerLength & 0xFFFF);
            sum += ProtocolNumber;
            return sum;
        }

        static uint ChecksumBody(ReadOnlySpan<byte> message)
        {
            uint sum = 0;
            int i = 0;
            for (; i + 1 < message.Length; i += 2) sum += (uint)((message[i] << 8) | message[i + 1]);
            if (i < message.Length) sum += (uint)(message[i] << 8);
            return sum;
        }

        static ushort FinishChecksum(uint sum)
        {
            while ((sum >> 16) != 0) sum = (sum & 0xFFFF) + (sum >> 16);
            return (ushort)~sum;
        }

        static uint ReadUInt32(ReadOnlySpan<byte> b, int offset)
            => ((uint)b[offset] << 24) | ((uint)b[offset + 1] << 16) | ((uint)b[offset + 2] << 8) | b[offset + 3];

        static void WriteUInt32(byte[] b, int offset, uint value)
        {
            b[offset] = (byte)(value >> 24);
            b[offset + 1] = (byte)(value >> 16);
            b[offset + 2] = (byte)(value >> 8);
            b[offset + 3] = (byte)value;
        }
    }
}
