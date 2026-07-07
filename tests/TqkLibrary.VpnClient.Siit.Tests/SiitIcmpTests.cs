using System.Net;
using TqkLibrary.VpnClient.IpStack;
using TqkLibrary.VpnClient.Siit.Enums;
using TqkLibrary.VpnClient.Siit.Models;
using Xunit;
using static TqkLibrary.VpnClient.Siit.Tests.TestPackets;

namespace TqkLibrary.VpnClient.Siit.Tests;

public class SiitIcmpTests
{
    static readonly IPAddress Src4 = V4("192.0.2.1");
    static readonly IPAddress Dst4 = V4("198.51.100.2");
    static readonly IPAddress Src6 = V6("64:ff9b::c000:201");
    static readonly IPAddress Dst6 = V6("64:ff9b::c633:6402");

    static SiitTranslator Nat64() => new SiitTranslator(new Rfc6052AddressMapper());

    [Fact]
    public void EchoRequest_4to6_BecomesType128()
    {
        byte[] echo = Icmpv4.BuildEcho(Icmpv4.TypeEchoRequest, 0x1111, 0x2222, new byte[] { 1, 2, 3, 4 });
        byte[] packet = Ipv4Packet(Src4, Dst4, Ipv4.ProtocolIcmp, echo, 0, 64);

        byte[]? v6 = Nat64().Translate4to6(packet);
        Assert.NotNull(v6);
        Assert.Equal(Ipv6.NextHeaderIcmpv6, Ipv6.NextHeader(v6));
        var msg = v6.AsSpan(Ipv6.HeaderLength);
        Assert.Equal(Icmpv6.TypeEchoRequest, Icmpv6.Type(msg));
        Assert.Equal(0x1111, Icmpv6.Identifier(msg));
        Assert.Equal(0x2222, Icmpv6.Sequence(msg));
        Assert.True(Icmpv6.VerifyChecksum(msg, Src6, Dst6));
    }

    [Fact]
    public void EchoReply_4to6_BecomesType129()
    {
        byte[] echo = Icmpv4.BuildEcho(Icmpv4.TypeEchoReply, 1, 2, new byte[] { 9 });
        byte[] packet = Ipv4Packet(Src4, Dst4, Ipv4.ProtocolIcmp, echo, 0, 64);

        byte[]? v6 = Nat64().Translate4to6(packet);
        Assert.NotNull(v6);
        Assert.Equal(Icmpv6.TypeEchoReply, Icmpv6.Type(v6.AsSpan(Ipv6.HeaderLength)));
    }

    [Fact]
    public void Echo_RoundTrip_ByteExactExceptTtl()
    {
        byte[] echo = Icmpv4.BuildEcho(Icmpv4.TypeEchoRequest, 0xABCD, 0x0007, new byte[] { 5, 6, 7, 8 });
        byte[] packet = Ipv4Packet(Src4, Dst4, Ipv4.ProtocolIcmp, echo, 0, 64);

        var t = Nat64();
        byte[]? back = t.Translate6to4(t.Translate4to6(packet)!);
        Assert.NotNull(back);
        byte[] expected = (byte[])packet.Clone();
        expected[8] = 62;
        RewriteIpv4Checksum(expected);
        Assert.Equal(expected, back);
    }

    [Fact]
    public void DestinationUnreachablePort_4to6_TranslatesEmbedded()
    {
        byte[] offSeg = UdpSegment(Src4, Dst4, 4000, 53, new byte[] { 1, 2, 3, 4 });
        byte[] offending = Ipv4Packet(Src4, Dst4, Ipv4.ProtocolUdp, offSeg, 0, 64);
        byte[] icmp = Icmpv4.BuildDestinationUnreachable(Icmpv4.CodePortUnreachable, offending);
        byte[] outer = Ipv4Packet(Src4, Dst4, Ipv4.ProtocolIcmp, icmp, 0, 64);

        byte[]? v6 = Nat64().Translate4to6(outer);
        Assert.NotNull(v6);
        var msg = v6.AsSpan(Ipv6.HeaderLength);
        Assert.Equal(Icmpv6.TypeDestinationUnreachable, Icmpv6.Type(msg));
        Assert.Equal(Icmpv6.CodePortUnreachable, Icmpv6.Code(msg));
        Assert.True(Icmpv6.VerifyChecksum(msg, Src6, Dst6));

        var embedded = msg.Slice(Icmpv6.HeaderSize);
        Assert.Equal(6, Ipv6.Version(embedded));
        Assert.Equal(Src6, Ipv6.Source(embedded));
        Assert.Equal(Dst6, Ipv6.Destination(embedded));
        Assert.Equal(Ipv6.NextHeaderUdp, Ipv6.NextHeader(embedded));
    }

    [Fact]
    public void FragmentationNeeded_4to6_BecomesPacketTooBig()
    {
        byte[] offSeg = UdpSegment(Src4, Dst4, 4000, 53, new byte[] { 1, 2 });
        byte[] offending = Ipv4Packet(Src4, Dst4, Ipv4.ProtocolUdp, offSeg, 0, 64);
        byte[] icmp = Icmpv4.BuildFragmentationNeeded(1400, offending);
        byte[] outer = Ipv4Packet(Src4, Dst4, Ipv4.ProtocolIcmp, icmp, 0, 64);

        byte[]? v6 = Nat64().Translate4to6(outer);
        Assert.NotNull(v6);
        var msg = v6.AsSpan(Ipv6.HeaderLength);
        Assert.Equal(Icmpv6.TypePacketTooBig, Icmpv6.Type(msg));
        Assert.Equal(1420u, Icmpv6.NextHopMtu(msg));      // IPv4 MTU + 20
        Assert.True(Icmpv6.VerifyChecksum(msg, Src6, Dst6));
    }

    [Fact]
    public void TimeExceeded_4to6_BecomesType3()
    {
        byte[] offSeg = UdpSegment(Src4, Dst4, 4000, 53, new byte[] { 1, 2 });
        byte[] offending = Ipv4Packet(Src4, Dst4, Ipv4.ProtocolUdp, offSeg, 0, 64);
        byte[] icmp = new byte[Icmpv4.HeaderSize + 28];
        icmp[0] = 11;                                     // Time Exceeded
        offending.AsSpan(0, 28).CopyTo(icmp.AsSpan(Icmpv4.HeaderSize));
        byte[] outer = Ipv4Packet(Src4, Dst4, Ipv4.ProtocolIcmp, icmp, 0, 64);

        byte[]? v6 = Nat64().Translate4to6(outer);
        Assert.NotNull(v6);
        var msg = v6.AsSpan(Ipv6.HeaderLength);
        Assert.Equal(Icmpv6.TypeTimeExceeded, Icmpv6.Type(msg));
        Assert.True(Icmpv6.VerifyChecksum(msg, Src6, Dst6));
    }

    [Fact]
    public void DestinationUnreachable_6to4_TranslatesEmbedded()
    {
        byte[] offSeg = UdpSegment(Src6, Dst6, 4000, 53, new byte[] { 1, 2, 3, 4 });
        byte[] offendingV6 = Ipv6.Build(Src6, Dst6, Ipv6.NextHeaderUdp, offSeg, 64);
        byte[] icmp6 = Icmpv6.BuildDestinationUnreachable(Icmpv6.CodePortUnreachable, offendingV6, Src6, Dst6);
        byte[] outer = Ipv6.Build(Src6, Dst6, Ipv6.NextHeaderIcmpv6, icmp6, 64);

        byte[]? back = Nat64().Translate6to4(outer);
        Assert.NotNull(back);
        var msg = back.AsSpan(20);
        Assert.Equal(Icmpv4.TypeDestinationUnreachable, Icmpv4.Type(msg));
        Assert.Equal(Icmpv4.CodePortUnreachable, Icmpv4.Code(msg));
        Assert.True(Icmpv4.VerifyChecksum(msg));

        var embedded = msg.Slice(Icmpv4.HeaderSize);
        Assert.Equal(Src4, Ipv4.Source(embedded));
        Assert.Equal(Dst4, Ipv4.Destination(embedded));
        Assert.Equal(Ipv4.ProtocolUdp, Ipv4.Protocol(embedded));
    }

    [Fact]
    public void PacketTooBig_6to4_BecomesFragmentationNeeded()
    {
        byte[] offSeg = UdpSegment(Src6, Dst6, 4000, 53, new byte[] { 1 });
        byte[] offendingV6 = Ipv6.Build(Src6, Dst6, Ipv6.NextHeaderUdp, offSeg, 64);
        byte[] icmp6 = Icmpv6.BuildPacketTooBig(1500, offendingV6, Src6, Dst6);
        byte[] outer = Ipv6.Build(Src6, Dst6, Ipv6.NextHeaderIcmpv6, icmp6, 64);

        byte[]? back = Nat64().Translate6to4(outer);
        Assert.NotNull(back);
        var msg = back.AsSpan(20);
        Assert.Equal(Icmpv4.TypeDestinationUnreachable, Icmpv4.Type(msg));
        Assert.Equal(Icmpv4.CodeFragmentationNeeded, Icmpv4.Code(msg));
        Assert.Equal(1480, Icmpv4.NextHopMtu(msg));       // IPv6 MTU − 20
        Assert.True(Icmpv4.VerifyChecksum(msg));
    }

    [Fact]
    public void EmbeddedUnmappableAddress_Drops()
    {
        var eamOnly = new SiitTranslator(new ExplicitAddressMap()
            .Add(new EamEntry(V4("192.0.2.0"), 24, V6("2001:db8::"), 120)));

        byte[] offSeg = UdpSegment(V4("8.8.8.8"), V4("192.0.2.2"), 4000, 53, new byte[] { 1 });
        byte[] offending = Ipv4Packet(V4("8.8.8.8"), V4("192.0.2.2"), Ipv4.ProtocolUdp, offSeg, 0, 64);
        byte[] icmp = Icmpv4.BuildDestinationUnreachable(Icmpv4.CodePortUnreachable, offending);
        byte[] outer = Ipv4Packet(V4("192.0.2.1"), V4("192.0.2.2"), Ipv4.ProtocolIcmp, icmp, 0, 64);

        Assert.Null(eamOnly.Translate4to6(outer));       // outer maps, embedded 8.8.8.8 does not
        Assert.Equal(SiitDropReason.AddressNotMapped, eamOnly.LastDropReason);
    }

    [Fact]
    public void UnsupportedIcmpType_Drops()
    {
        byte[] icmp = new byte[Icmpv4.HeaderSize];
        icmp[0] = 13;                                     // Timestamp — no translation defined
        byte[] packet = Ipv4Packet(Src4, Dst4, Ipv4.ProtocolIcmp, icmp, 0, 64);

        var t = Nat64();
        Assert.Null(t.Translate4to6(packet));
        Assert.Equal(SiitDropReason.UnsupportedIcmp, t.LastDropReason);
    }
}
