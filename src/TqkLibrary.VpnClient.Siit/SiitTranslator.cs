using System.Net;
using TqkLibrary.VpnClient.Abstractions.Net;
using TqkLibrary.VpnClient.IpStack;
using TqkLibrary.VpnClient.Siit.Enums;
using TqkLibrary.VpnClient.Siit.Helpers;
using TqkLibrary.VpnClient.Siit.Interfaces;

namespace TqkLibrary.VpnClient.Siit;

/// <summary>
/// Stateless SIIT header translator (RFC 7915): rewrites an IPv4 packet as an IPv6 packet and vice-versa without
/// keeping per-flow state. Addresses are mapped through an <see cref="IAddressTranslator"/> (typically EAM →
/// RFC 6052). Handles TCP/UDP (with checksum fix-up), ICMP↔ICMPv6 (echo + the common errors, with the embedded
/// offending packet translated too), and single Fragment headers. Anything it cannot safely translate returns
/// <c>null</c> and sets <see cref="LastDropReason"/>. Not thread-safe because of that diagnostic field — use one
/// instance per translating thread/flow.
/// </summary>
public sealed class SiitTranslator
{
    // RFC 4443 §3: an ICMPv6 error quotes as much of the invoking packet as fits within the IPv6 minimum MTU.
    const int Icmpv6MaxErrorQuote = 1280 - Ipv6.HeaderLength - Icmpv6.HeaderSize;

    readonly IAddressTranslator _addr;
    readonly Action<SiitDropReason>? _onDrop;

    /// <summary>Creates a translator using <paramref name="addressTranslator"/> for address mapping and an optional drop callback.</summary>
    public SiitTranslator(IAddressTranslator addressTranslator, Action<SiitDropReason>? onDrop = null)
    {
        _addr = addressTranslator ?? throw new ArgumentNullException(nameof(addressTranslator));
        _onDrop = onDrop;
    }

    /// <summary>Reason the most recent translation returned <c>null</c> (or <see cref="SiitDropReason.None"/> on success).</summary>
    public SiitDropReason LastDropReason { get; private set; }

    byte[]? Drop(SiitDropReason reason)
    {
        LastDropReason = reason;
        _onDrop?.Invoke(reason);
        return null;
    }

    static bool IsMulticastV4(IPAddress a) => (a.GetAddressBytes()[0] & 0xF0) == 0xE0;   // 224.0.0.0/4
    static bool IsMulticastV6(IPAddress a) => a.GetAddressBytes()[0] == 0xFF;            // ff00::/8

    static bool IsExtensionHeader(byte nextHeader) =>
        nextHeader == Ipv6.NextHeaderHopByHop || nextHeader == Ipv6.NextHeaderRouting ||
        nextHeader == Ipv6.NextHeaderDestOptions || nextHeader == Ipv6.NextHeaderFragment ||
        nextHeader == Ipv6.NextHeaderNone;

    // ---------------------------------------------------------------------------------------------------------
    // IPv4 -> IPv6 (RFC 7915 §4)
    // ---------------------------------------------------------------------------------------------------------

    /// <summary>Translates an IPv4 packet to an IPv6 packet (RFC 7915 §4). Returns <c>null</c> on a safe drop; see <see cref="LastDropReason"/>.</summary>
    public byte[]? Translate4to6(ReadOnlySpan<byte> packet)
    {
        LastDropReason = SiitDropReason.None;

        if (packet.Length < 20 || (packet[0] >> 4) != 4) return Drop(SiitDropReason.Malformed);
        int ihl = Ipv4.HeaderLength(packet);
        if (ihl < 20 || ihl > packet.Length) return Drop(SiitDropReason.Malformed);

        int ttl = packet[8];
        if (ttl <= 1) return Drop(SiitDropReason.HopLimitExceeded);
        byte hopLimit = (byte)(ttl - 1);
        byte tos = packet[1];
        byte protocol = Ipv4.Protocol(packet);

        IPAddress src4 = Ipv4.Source(packet), dst4 = Ipv4.Destination(packet);
        if (IsMulticastV4(src4) || IsMulticastV4(dst4)) return Drop(SiitDropReason.Multicast);
        if (!_addr.TryTranslate4to6(src4, out var src6)) return Drop(SiitDropReason.AddressNotMapped);
        if (!_addr.TryTranslate4to6(dst4, out var dst6)) return Drop(SiitDropReason.AddressNotMapped);

        bool moreFrag = Ipv4.MoreFragments(packet);
        int fragOffset = Ipv4.FragmentOffset(packet);
        bool df = Ipv4.DontFragment(packet);
        uint ident = Ipv4.Identification(packet);
        bool fragmented = moreFrag || fragOffset > 0;
        bool needFragmentHeader = fragmented || !df;   // RFC 7915 §4: add a Fragment header when DF=0 or already a fragment
        bool wholeDatagram = !fragmented;

        ReadOnlySpan<byte> l4 = packet.Slice(ihl);
        byte nextHeader;
        byte[]? newL4;

        if (fragOffset == 0)
        {
            switch (protocol)
            {
                case Ipv4.ProtocolIcmp:
                    if (fragmented) return Drop(SiitDropReason.FragmentedIcmp);
                    nextHeader = Ipv6.NextHeaderIcmpv6;
                    newL4 = TranslateIcmp4to6(l4, src6, dst6);
                    break;
                case Ipv4.ProtocolTcp:
                case Ipv4.ProtocolUdp:
                    nextHeader = protocol;
                    newL4 = TranslateTcpUdp4to6(protocol, l4, src4, dst4, src6, dst6, wholeDatagram);
                    break;
                default:
                    return Drop(SiitDropReason.UnsupportedProtocol);
            }
            if (newL4 is null) return null; // reason already set
        }
        else
        {
            switch (protocol)   // non-first fragment: no upper-layer header to fix, just carry the bytes
            {
                case Ipv4.ProtocolIcmp: return Drop(SiitDropReason.FragmentedIcmp);
                case Ipv4.ProtocolTcp: case Ipv4.ProtocolUdp: nextHeader = protocol; break;
                default: return Drop(SiitDropReason.UnsupportedProtocol);
            }
            newL4 = l4.ToArray();
        }

        byte[] result = needFragmentHeader
            ? Ipv6.BuildFragment(src6, dst6, nextHeader, newL4, ident, fragOffset, moreFrag, hopLimit)
            : Ipv6.Build(src6, dst6, nextHeader, newL4, hopLimit);

        ApplyTrafficClass(result, tos);
        return result;
    }

    byte[]? TranslateTcpUdp4to6(byte protocol, ReadOnlySpan<byte> segment, IPAddress src4, IPAddress dst4, IPAddress src6, IPAddress dst6, bool wholeDatagram)
    {
        int csumOffset = protocol == Ipv4.ProtocolUdp ? 6 : 16;
        if (segment.Length < csumOffset + 2) return Drop(SiitDropReason.Malformed);

        byte[] seg = segment.ToArray();
        ushort oldCsum = (ushort)((seg[csumOffset] << 8) | seg[csumOffset + 1]);

        if (protocol == Ipv4.ProtocolUdp && oldCsum == 0)
        {
            // IPv4 lets UDP skip the checksum; IPv6 requires one, so it must be computed (RFC 7915 §4.5).
            if (!wholeDatagram) return Drop(SiitDropReason.UdpZeroChecksumFragment);
            return WriteTransportChecksum(seg, csumOffset, ComputeUdpNonZero(src6, dst6, seg));
        }

        ushort newCsum;
        if (wholeDatagram)
        {
            seg[csumOffset] = 0; seg[csumOffset + 1] = 0;
            newCsum = SiitChecksum.ComputeTransport(src6, dst6, protocol, seg);
            if (protocol == Ipv4.ProtocolUdp && newCsum == 0) newCsum = 0xFFFF;
        }
        else
        {
            Span<byte> oldAddr = stackalloc byte[8];
            src4.GetAddressBytes().CopyTo(oldAddr); dst4.GetAddressBytes().CopyTo(oldAddr.Slice(4));
            Span<byte> newAddr = stackalloc byte[32];
            src6.GetAddressBytes().CopyTo(newAddr); dst6.GetAddressBytes().CopyTo(newAddr.Slice(16));
            newCsum = SiitChecksum.AdjustForAddressChange(oldCsum, oldAddr, newAddr);
            if (protocol == Ipv4.ProtocolUdp && newCsum == 0) newCsum = 0xFFFF;
        }
        return WriteTransportChecksum(seg, csumOffset, newCsum);
    }

    static ushort ComputeUdpNonZero(IPAddress src, IPAddress dst, byte[] seg)
    {
        seg[6] = 0; seg[7] = 0;
        ushort c = SiitChecksum.ComputeTransport(src, dst, Ipv4.ProtocolUdp, seg);
        return c == 0 ? (ushort)0xFFFF : c;
    }

    byte[]? TranslateIcmp4to6(ReadOnlySpan<byte> icmp, IPAddress src6, IPAddress dst6)
    {
        if (icmp.Length < Icmpv4.HeaderSize) return Drop(SiitDropReason.Malformed);
        byte type = Icmpv4.Type(icmp), code = Icmpv4.Code(icmp);

        switch (type)
        {
            case Icmpv4.TypeEchoRequest:
            case Icmpv4.TypeEchoReply:
            {
                byte newType = type == Icmpv4.TypeEchoRequest ? Icmpv6.TypeEchoRequest : Icmpv6.TypeEchoReply;
                return Icmpv6.BuildEcho(newType, Icmpv4.Identifier(icmp), Icmpv4.Sequence(icmp), icmp.Slice(Icmpv4.HeaderSize), src6, dst6);
            }
            case Icmpv4.TypeDestinationUnreachable:
            {
                if (code == Icmpv4.CodeFragmentationNeeded)
                {
                    ushort v4Mtu = Icmpv4.NextHopMtu(icmp);
                    uint mtu = v4Mtu == 0 ? 1280u : (uint)(v4Mtu + 20);   // IPv6 header is 20 bytes larger
                    if (mtu < 1280) mtu = 1280;
                    byte[]? emb = TranslateEmbedded4to6(icmp.Slice(Icmpv4.HeaderSize));
                    if (emb is null) return null;
                    return Icmpv6.BuildPacketTooBig(mtu, emb, src6, dst6);
                }
                else
                {
                    int v6Code = MapUnreachableCode4to6(code);
                    if (v6Code < 0) return Drop(SiitDropReason.UnsupportedIcmp);
                    byte[]? emb = TranslateEmbedded4to6(icmp.Slice(Icmpv4.HeaderSize));
                    if (emb is null) return null;
                    return Icmpv6.BuildDestinationUnreachable((byte)v6Code, emb, src6, dst6);
                }
            }
            case 11: // Time Exceeded -> ICMPv6 Time Exceeded (type 3), code preserved
            {
                byte[]? emb = TranslateEmbedded4to6(icmp.Slice(Icmpv4.HeaderSize));
                if (emb is null) return null;
                return BuildIcmpv6Error(Icmpv6.TypeTimeExceeded, code, emb, src6, dst6);
            }
            default:
                return Drop(SiitDropReason.UnsupportedIcmp);
        }
    }

    // Translate the offending IPv4 packet quoted inside an ICMP error: header only, keep hop count, tolerate a
    // truncated (header + 8 bytes) quote, and do not recompute the upper-layer checksum (RFC 7915 §4.2).
    byte[]? TranslateEmbedded4to6(ReadOnlySpan<byte> emb)
    {
        if (emb.Length < 20 || (emb[0] >> 4) != 4) return Drop(SiitDropReason.Malformed);
        int ihl = Ipv4.HeaderLength(emb);
        if (ihl < 20 || ihl > emb.Length) return Drop(SiitDropReason.Malformed);

        byte protocol = Ipv4.Protocol(emb);
        byte tos = emb[1], hop = emb[8];
        if (!_addr.TryTranslate4to6(Ipv4.Source(emb), out var s6)) return Drop(SiitDropReason.AddressNotMapped);
        if (!_addr.TryTranslate4to6(Ipv4.Destination(emb), out var d6)) return Drop(SiitDropReason.AddressNotMapped);

        byte nh;
        switch (protocol)
        {
            case Ipv4.ProtocolIcmp: nh = Ipv6.NextHeaderIcmpv6; break;
            case Ipv4.ProtocolTcp: nh = Ipv6.NextHeaderTcp; break;
            case Ipv4.ProtocolUdp: nh = Ipv6.NextHeaderUdp; break;
            default: return Drop(SiitDropReason.UnsupportedProtocol);
        }

        byte[] result = Ipv6.Build(s6, d6, nh, emb.Slice(ihl), hop);
        ApplyTrafficClass(result, tos);
        return result;
    }

    // ---------------------------------------------------------------------------------------------------------
    // IPv6 -> IPv4 (RFC 7915 §5)
    // ---------------------------------------------------------------------------------------------------------

    /// <summary>Translates an IPv6 packet to an IPv4 packet (RFC 7915 §5). Returns <c>null</c> on a safe drop; see <see cref="LastDropReason"/>.</summary>
    public byte[]? Translate6to4(ReadOnlySpan<byte> packet)
    {
        LastDropReason = SiitDropReason.None;

        if (packet.Length < Ipv6.HeaderLength || Ipv6.Version(packet) != 6) return Drop(SiitDropReason.Malformed);

        int hop = Ipv6.HopLimit(packet);
        if (hop <= 1) return Drop(SiitDropReason.HopLimitExceeded);
        byte ttl = (byte)(hop - 1);
        byte tos = (byte)(((packet[0] & 0x0F) << 4) | (packet[1] >> 4));   // IPv6 traffic class -> IPv4 TOS

        IPAddress src6 = Ipv6.Source(packet), dst6 = Ipv6.Destination(packet);
        if (IsMulticastV6(src6) || IsMulticastV6(dst6)) return Drop(SiitDropReason.Multicast);
        if (!_addr.TryTranslate6to4(src6, out var src4)) return Drop(SiitDropReason.AddressNotMapped);
        if (!_addr.TryTranslate6to4(dst6, out var dst4)) return Drop(SiitDropReason.AddressNotMapped);

        byte upperProtocol;
        int payloadOffset;
        bool hasFragment;
        int fragOffset = 0; bool moreFrag = false; ushort ident = 0;

        if (Ipv6.TryGetFragment(packet, out int unfragLen, out _, out byte fragNext, out int fOff, out bool mf, out uint id))
        {
            if (unfragLen != Ipv6.HeaderLength) return Drop(SiitDropReason.UnsupportedExtensionHeader); // other ext headers before Fragment
            hasFragment = true;
            upperProtocol = fragNext;
            payloadOffset = unfragLen + Ipv6.FragmentHeaderLength;
            fragOffset = fOff; moreFrag = mf; ident = (ushort)id;   // RFC 7915 §5.1: low 16 bits of the 32-bit id
        }
        else
        {
            byte nh = Ipv6.NextHeader(packet);
            if (IsExtensionHeader(nh)) return Drop(SiitDropReason.UnsupportedExtensionHeader);
            hasFragment = false;
            upperProtocol = nh;
            payloadOffset = Ipv6.HeaderLength;
        }

        byte v4Protocol;
        switch (upperProtocol)
        {
            case Ipv6.NextHeaderIcmpv6: v4Protocol = Ipv4.ProtocolIcmp; break;
            case Ipv6.NextHeaderTcp: v4Protocol = Ipv4.ProtocolTcp; break;
            case Ipv6.NextHeaderUdp: v4Protocol = Ipv4.ProtocolUdp; break;
            default: return Drop(SiitDropReason.UnsupportedProtocol);
        }

        if (payloadOffset > packet.Length) return Drop(SiitDropReason.Malformed);
        ReadOnlySpan<byte> l4 = packet.Slice(payloadOffset);
        bool wholeDatagram = !hasFragment || (!moreFrag && fragOffset == 0);

        byte[]? newL4;
        if (fragOffset == 0)
        {
            switch (v4Protocol)
            {
                case Ipv4.ProtocolIcmp:
                    if (hasFragment) return Drop(SiitDropReason.FragmentedIcmp);
                    newL4 = TranslateIcmp6to4(l4, src6, dst6);
                    break;
                case Ipv4.ProtocolTcp:
                case Ipv4.ProtocolUdp:
                    newL4 = TranslateTcpUdp6to4(v4Protocol, l4, src6, dst6, src4, dst4, wholeDatagram);
                    break;
                default:
                    return Drop(SiitDropReason.UnsupportedProtocol);
            }
            if (newL4 is null) return null;
        }
        else
        {
            if (v4Protocol == Ipv4.ProtocolIcmp) return Drop(SiitDropReason.FragmentedIcmp);
            newL4 = l4.ToArray();
        }

        byte[] result = hasFragment
            ? Ipv4.BuildFragment(src4, dst4, v4Protocol, newL4, ident, fragOffset, moreFrag)
            : Ipv4.Build(src4, dst4, v4Protocol, newL4, 0);

        result[1] = tos;
        result[8] = ttl;
        RecomputeIpv4HeaderChecksum(result);
        return result;
    }

    byte[]? TranslateTcpUdp6to4(byte protocol, ReadOnlySpan<byte> segment, IPAddress src6, IPAddress dst6, IPAddress src4, IPAddress dst4, bool wholeDatagram)
    {
        int csumOffset = protocol == Ipv4.ProtocolUdp ? 6 : 16;
        if (segment.Length < csumOffset + 2) return Drop(SiitDropReason.Malformed);

        byte[] seg = segment.ToArray();
        ushort oldCsum = (ushort)((seg[csumOffset] << 8) | seg[csumOffset + 1]);

        ushort newCsum;
        if (wholeDatagram)
        {
            seg[csumOffset] = 0; seg[csumOffset + 1] = 0;
            newCsum = SiitChecksum.ComputeTransport(src4, dst4, protocol, seg);
        }
        else
        {
            Span<byte> oldAddr = stackalloc byte[32];
            src6.GetAddressBytes().CopyTo(oldAddr); dst6.GetAddressBytes().CopyTo(oldAddr.Slice(16));
            Span<byte> newAddr = stackalloc byte[8];
            src4.GetAddressBytes().CopyTo(newAddr); dst4.GetAddressBytes().CopyTo(newAddr.Slice(4));
            newCsum = SiitChecksum.AdjustForAddressChange(oldCsum, oldAddr, newAddr);
        }
        return WriteTransportChecksum(seg, csumOffset, newCsum);
    }

    byte[]? TranslateIcmp6to4(ReadOnlySpan<byte> icmp, IPAddress src6, IPAddress dst6)
    {
        if (icmp.Length < Icmpv6.HeaderSize) return Drop(SiitDropReason.Malformed);
        byte type = Icmpv6.Type(icmp), code = Icmpv6.Code(icmp);

        switch (type)
        {
            case Icmpv6.TypeEchoRequest:
            case Icmpv6.TypeEchoReply:
            {
                byte newType = type == Icmpv6.TypeEchoRequest ? Icmpv4.TypeEchoRequest : Icmpv4.TypeEchoReply;
                return Icmpv4.BuildEcho(newType, Icmpv6.Identifier(icmp), Icmpv6.Sequence(icmp), icmp.Slice(Icmpv6.HeaderSize));
            }
            case Icmpv6.TypeDestinationUnreachable:
            {
                int v4Code = MapUnreachableCode6to4(code);
                if (v4Code < 0) return Drop(SiitDropReason.UnsupportedIcmp);
                byte[]? emb = TranslateEmbedded6to4(icmp.Slice(Icmpv6.HeaderSize));
                if (emb is null) return null;
                return Icmpv4.BuildDestinationUnreachable((byte)v4Code, emb);
            }
            case Icmpv6.TypePacketTooBig:
            {
                uint v6Mtu = Icmpv6.NextHopMtu(icmp);
                uint mtu = v6Mtu > 20 ? v6Mtu - 20 : v6Mtu;   // IPv4 header is 20 bytes smaller
                if (mtu > 0xFFFF) mtu = 0xFFFF;
                byte[]? emb = TranslateEmbedded6to4(icmp.Slice(Icmpv6.HeaderSize));
                if (emb is null) return null;
                return Icmpv4.BuildFragmentationNeeded((ushort)mtu, emb);
            }
            case Icmpv6.TypeTimeExceeded: // -> ICMPv4 Time Exceeded (type 11), code preserved
            {
                byte[]? emb = TranslateEmbedded6to4(icmp.Slice(Icmpv6.HeaderSize));
                if (emb is null) return null;
                return BuildIcmpv4Error(11, code, emb);
            }
            default:
                return Drop(SiitDropReason.UnsupportedIcmp);
        }
    }

    // Translate the offending IPv6 packet quoted inside an ICMPv6 error to IPv4: fixed header only, keep hop count,
    // tolerate truncation, do not recompute the upper-layer checksum (RFC 7915 §5.2).
    byte[]? TranslateEmbedded6to4(ReadOnlySpan<byte> emb)
    {
        if (emb.Length < Ipv6.HeaderLength || Ipv6.Version(emb) != 6) return Drop(SiitDropReason.Malformed);

        byte nh = Ipv6.NextHeader(emb);
        if (IsExtensionHeader(nh)) return Drop(SiitDropReason.UnsupportedExtensionHeader);
        byte tos = (byte)(((emb[0] & 0x0F) << 4) | (emb[1] >> 4));
        byte hop = Ipv6.HopLimit(emb);
        if (!_addr.TryTranslate6to4(Ipv6.Source(emb), out var s4)) return Drop(SiitDropReason.AddressNotMapped);
        if (!_addr.TryTranslate6to4(Ipv6.Destination(emb), out var d4)) return Drop(SiitDropReason.AddressNotMapped);

        byte proto;
        switch (nh)
        {
            case Ipv6.NextHeaderIcmpv6: proto = Ipv4.ProtocolIcmp; break;
            case Ipv6.NextHeaderTcp: proto = Ipv4.ProtocolTcp; break;
            case Ipv6.NextHeaderUdp: proto = Ipv4.ProtocolUdp; break;
            default: return Drop(SiitDropReason.UnsupportedProtocol);
        }

        byte[] result = Ipv4.Build(s4, d4, proto, emb.Slice(Ipv6.HeaderLength), 0);
        result[1] = tos;
        result[8] = hop;                       // preserve the quoted hop count (embedded packet is not forwarded)
        RecomputeIpv4HeaderChecksum(result);
        return result;
    }

    // ---------------------------------------------------------------------------------------------------------
    // Shared helpers
    // ---------------------------------------------------------------------------------------------------------

    static byte[] WriteTransportChecksum(byte[] seg, int csumOffset, ushort checksum)
    {
        seg[csumOffset] = (byte)(checksum >> 8);
        seg[csumOffset + 1] = (byte)checksum;
        return seg;
    }

    // Set the IPv6 traffic class from an IPv4 TOS octet; flow label stays zero (RFC 7915 §4).
    static void ApplyTrafficClass(byte[] ipv6Packet, byte tos)
    {
        ipv6Packet[0] = (byte)(0x60 | (tos >> 4));
        ipv6Packet[1] = (byte)((ipv6Packet[1] & 0x0F) | ((tos & 0x0F) << 4));
    }

    static void RecomputeIpv4HeaderChecksum(byte[] ipv4Packet)
    {
        ipv4Packet[10] = 0; ipv4Packet[11] = 0;
        ushort hc = InternetChecksum.Compute(ipv4Packet.AsSpan(0, 20));
        ipv4Packet[10] = (byte)(hc >> 8);
        ipv4Packet[11] = (byte)hc;
    }

    // RFC 7915 §4.2: ICMPv4 Destination Unreachable code -> ICMPv6 Destination Unreachable code. -1 = not translated.
    static int MapUnreachableCode4to6(byte code) => code switch
    {
        0 or 1 => 0,        // net/host unreachable -> no route to destination
        3 => Icmpv6.CodePortUnreachable, // 4
        9 or 10 or 13 => 1, // communication administratively prohibited
        5 or 6 or 7 or 8 or 11 or 12 => 0,
        _ => -1,            // e.g. code 2 (protocol unreachable) needs a Parameter Problem — not emitted here
    };

    // RFC 7915 §5.2: ICMPv6 Destination Unreachable code -> ICMPv4 code. -1 = not translated.
    static int MapUnreachableCode6to4(byte code) => code switch
    {
        0 => 1,                              // no route -> host unreachable
        1 => 10,                             // admin prohibited -> communication administratively prohibited
        2 or 3 => 1,                         // beyond scope / address unreachable -> host unreachable
        4 => Icmpv4.CodePortUnreachable,     // 3
        _ => -1,
    };

    byte[] BuildIcmpv6Error(byte type, byte code, ReadOnlySpan<byte> quote, IPAddress src, IPAddress dst)
    {
        int q = Math.Min(quote.Length, Icmpv6MaxErrorQuote);
        byte[] msg = new byte[Icmpv6.HeaderSize + q];
        msg[0] = type; msg[1] = code;   // bytes 4..8 unused (zero) for Time Exceeded / Destination Unreachable
        quote.Slice(0, q).CopyTo(msg.AsSpan(Icmpv6.HeaderSize));

        uint sum = InternetChecksum.PseudoHeaderSum(src, dst, Icmpv6.ProtocolNumber, msg.Length);
        sum = InternetChecksum.AddData(sum, msg);
        ushort c = InternetChecksum.Finish(sum);
        msg[2] = (byte)(c >> 8); msg[3] = (byte)c;
        return msg;
    }

    static byte[] BuildIcmpv4Error(byte type, byte code, ReadOnlySpan<byte> offendingIpPacket)
    {
        // Quote the offending IPv4 header + 8 bytes (RFC 792), like Icmpv4.BuildDestinationUnreachable.
        int ihl = offendingIpPacket.Length > 0 ? (offendingIpPacket[0] & 0x0F) * 4 : 20;
        if (ihl < 20) ihl = 20;
        int quote = Math.Min(offendingIpPacket.Length, ihl + 8);
        byte[] msg = new byte[Icmpv4.HeaderSize + quote];
        msg[0] = type; msg[1] = code;   // bytes 4..8 unused (zero)
        offendingIpPacket.Slice(0, quote).CopyTo(msg.AsSpan(Icmpv4.HeaderSize));

        ushort c = InternetChecksum.Compute(msg);
        msg[2] = (byte)(c >> 8); msg[3] = (byte)c;
        return msg;
    }
}
