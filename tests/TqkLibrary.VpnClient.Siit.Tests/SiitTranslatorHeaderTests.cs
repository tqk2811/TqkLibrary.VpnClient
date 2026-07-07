using System.Net;
using TqkLibrary.VpnClient.IpStack;
using TqkLibrary.VpnClient.Siit.Enums;
using TqkLibrary.VpnClient.Siit.Models;
using Xunit;
using static TqkLibrary.VpnClient.Siit.Tests.TestPackets;

namespace TqkLibrary.VpnClient.Siit.Tests;

public class SiitTranslatorHeaderTests
{
    static readonly IPAddress Src4 = V4("192.0.2.1");
    static readonly IPAddress Dst4 = V4("198.51.100.2");
    static readonly IPAddress Src6 = V6("64:ff9b::c000:201");
    static readonly IPAddress Dst6 = V6("64:ff9b::c633:6402");

    static SiitTranslator Nat64() => new SiitTranslator(new Rfc6052AddressMapper());

    [Fact]
    public void Udp4to6_HeaderFieldsAndChecksum()
    {
        byte[] seg = UdpSegment(Src4, Dst4, 4000, 53, new byte[] { 1, 2, 3, 4 });
        byte[] packet = Ipv4Packet(Src4, Dst4, Ipv4.ProtocolUdp, seg, id: 0, ttl: 64);

        byte[]? v6 = Nat64().Translate4to6(packet);
        Assert.NotNull(v6);
        Assert.Equal(6, Ipv6.Version(v6));
        Assert.Equal(Ipv6.NextHeaderUdp, Ipv6.NextHeader(v6));
        Assert.Equal(63, Ipv6.HopLimit(v6));
        Assert.Equal(Src6, Ipv6.Source(v6));
        Assert.Equal(Dst6, Ipv6.Destination(v6));
        Assert.Equal(seg.Length, Ipv6.PayloadLength(v6));
        Assert.True(VerifyUdpTcpChecksum(Src6, Dst6, Ipv4.ProtocolUdp, v6.AsSpan(Ipv6.HeaderLength)));
    }

    [Fact]
    public void Udp_RoundTrip_ByteExactExceptTtl()
    {
        byte[] seg = UdpSegment(Src4, Dst4, 4000, 53, new byte[] { 9, 8, 7, 6, 5 });
        byte[] packet = Ipv4Packet(Src4, Dst4, Ipv4.ProtocolUdp, seg, id: 0, ttl: 64);

        var t = Nat64();
        byte[]? v6 = t.Translate4to6(packet);
        Assert.NotNull(v6);
        byte[]? back = t.Translate6to4(v6);
        Assert.NotNull(back);

        byte[] expected = (byte[])packet.Clone();
        expected[8] = 62;                 // TTL decremented once each way
        RewriteIpv4Checksum(expected);
        Assert.Equal(expected, back);
    }

    [Fact]
    public void Tcp_RoundTrip_ByteExactExceptTtl()
    {
        byte[] seg = TcpSegment(Src4, Dst4, 12345, 443, new byte[] { 0xAA, 0xBB, 0xCC });
        byte[] packet = Ipv4Packet(Src4, Dst4, Ipv4.ProtocolTcp, seg, id: 0, ttl: 64);

        var t = Nat64();
        byte[]? back = t.Translate6to4(t.Translate4to6(packet)!);
        Assert.NotNull(back);

        byte[] expected = (byte[])packet.Clone();
        expected[8] = 62;
        RewriteIpv4Checksum(expected);
        Assert.Equal(expected, back);
    }

    [Fact]
    public void TrafficClass_CopiedBothWays()
    {
        byte[] seg = UdpSegment(Src4, Dst4, 4000, 53, new byte[] { 1 });
        byte[] packet = Ipv4Packet(Src4, Dst4, Ipv4.ProtocolUdp, seg, id: 0, ttl: 64);
        packet[1] = 0xB8;                  // DSCP EF + ECN
        RewriteIpv4Checksum(packet);

        var t = Nat64();
        byte[]? v6 = t.Translate4to6(packet);
        Assert.NotNull(v6);
        int tc = ((v6[0] & 0x0F) << 4) | (v6[1] >> 4);
        Assert.Equal(0xB8, tc);

        byte[]? back = t.Translate6to4(v6);
        Assert.NotNull(back);
        Assert.Equal(0xB8, back[1]);
    }

    [Fact]
    public void Udp_ZeroChecksum4to6_ComputesChecksum()
    {
        byte[] seg = UdpSegment(Src4, Dst4, 4000, 53, new byte[] { 1, 2, 3, 4 }, zeroChecksum: true);
        byte[] packet = Ipv4Packet(Src4, Dst4, Ipv4.ProtocolUdp, seg, id: 0, ttl: 64);

        byte[]? v6 = Nat64().Translate4to6(packet);
        Assert.NotNull(v6);
        var segment = v6.AsSpan(Ipv6.HeaderLength);
        Assert.False(segment[6] == 0 && segment[7] == 0);              // IPv6 UDP checksum is mandatory
        Assert.True(VerifyUdpTcpChecksum(Src6, Dst6, Ipv4.ProtocolUdp, segment));
    }

    [Fact]
    public void FirstFragment4to6_InsertsFragmentHeader_AndRoundTrips()
    {
        byte[] seg = UdpSegment(Src4, Dst4, 4000, 53, new byte[] { 1, 2, 3, 4, 5, 6, 7, 8 });
        byte[] frag = Ipv4.BuildFragment(Src4, Dst4, Ipv4.ProtocolUdp, seg, identification: 0x1234, fragmentOffset: 0, moreFragments: true);

        var t = Nat64();
        byte[]? v6 = t.Translate4to6(frag);
        Assert.NotNull(v6);
        Assert.True(Ipv6.TryGetFragment(v6, out _, out _, out byte fragNext, out int off, out bool mf, out uint id));
        Assert.Equal(Ipv6.NextHeaderUdp, fragNext);
        Assert.Equal(0, off);
        Assert.True(mf);
        Assert.Equal(0x1234u, id);

        byte[]? back = t.Translate6to4(v6);
        Assert.NotNull(back);
        byte[] expected = (byte[])frag.Clone();
        expected[8] = 62;
        RewriteIpv4Checksum(expected);
        Assert.Equal(expected, back);
    }

    [Fact]
    public void Df0_ProducesAtomicFragmentHeader()
    {
        byte[] seg = UdpSegment(Src4, Dst4, 4000, 53, new byte[] { 1, 2 });
        byte[] packet = Ipv4.BuildFragment(Src4, Dst4, Ipv4.ProtocolUdp, seg, identification: 0x5678, fragmentOffset: 0, moreFragments: false); // DF cleared, not a fragment

        byte[]? v6 = Nat64().Translate4to6(packet);
        Assert.NotNull(v6);
        Assert.True(Ipv6.TryGetFragment(v6, out _, out _, out _, out int off, out bool mf, out uint id));
        Assert.Equal(0, off);
        Assert.False(mf);
        Assert.Equal(0x5678u, id);
    }

    [Fact]
    public void Ttl1_4to6_Drops()
    {
        byte[] seg = UdpSegment(Src4, Dst4, 4000, 53, new byte[] { 1 });
        byte[] packet = Ipv4Packet(Src4, Dst4, Ipv4.ProtocolUdp, seg, id: 0, ttl: 1);

        var t = Nat64();
        Assert.Null(t.Translate4to6(packet));
        Assert.Equal(SiitDropReason.HopLimitExceeded, t.LastDropReason);
    }

    [Fact]
    public void Hop1_6to4_Drops()
    {
        byte[] seg = UdpSegment(Src4, Dst4, 4000, 53, new byte[] { 1 });
        var t = Nat64();
        byte[] v6 = t.Translate4to6(Ipv4Packet(Src4, Dst4, Ipv4.ProtocolUdp, seg, 0, 64))!;
        v6[7] = 1;                          // hop limit 1
        Assert.Null(t.Translate6to4(v6));
        Assert.Equal(SiitDropReason.HopLimitExceeded, t.LastDropReason);
    }

    [Fact]
    public void UnsupportedProtocol_Drops()
    {
        byte[] packet = Ipv4Packet(Src4, Dst4, protocol: 4 /* IP-in-IP */, payload: new byte[10], id: 0, ttl: 64);
        var t = Nat64();
        Assert.Null(t.Translate4to6(packet));
        Assert.Equal(SiitDropReason.UnsupportedProtocol, t.LastDropReason);
    }

    [Fact]
    public void UnmappableAddress_Drops()
    {
        var eamOnly = new SiitTranslator(new ExplicitAddressMap()
            .Add(new EamEntry(V4("192.0.2.0"), 24, V6("2001:db8::"), 120)));
        byte[] seg = UdpSegment(V4("10.0.0.1"), V4("192.0.2.5"), 4000, 53, new byte[] { 1 });
        byte[] packet = Ipv4Packet(V4("10.0.0.1"), V4("192.0.2.5"), Ipv4.ProtocolUdp, seg, 0, 64);
        Assert.Null(eamOnly.Translate4to6(packet));
        Assert.Equal(SiitDropReason.AddressNotMapped, eamOnly.LastDropReason);
    }

    [Fact]
    public void MulticastDestination_Drops()
    {
        byte[] seg = UdpSegment(Src4, V4("224.0.0.5"), 4000, 53, new byte[] { 1 });
        byte[] packet = Ipv4Packet(Src4, V4("224.0.0.5"), Ipv4.ProtocolUdp, seg, 0, 64);
        var t = Nat64();
        Assert.Null(t.Translate4to6(packet));
        Assert.Equal(SiitDropReason.Multicast, t.LastDropReason);
    }

    [Fact]
    public void UnsupportedExtensionHeader_6to4_Drops()
    {
        byte[] seg = UdpSegment(Src4, Dst4, 4000, 53, new byte[] { 1 });
        var t = Nat64();
        byte[] v6 = t.Translate4to6(Ipv4Packet(Src4, Dst4, Ipv4.ProtocolUdp, seg, 0, 64))!;
        v6[6] = Ipv6.NextHeaderRouting;     // claim a Routing extension header
        Assert.Null(t.Translate6to4(v6));
        Assert.Equal(SiitDropReason.UnsupportedExtensionHeader, t.LastDropReason);
    }

    [Fact]
    public void MalformedShort_Drops()
    {
        var t = Nat64();
        Assert.Null(t.Translate4to6(new byte[10]));
        Assert.Equal(SiitDropReason.Malformed, t.LastDropReason);
        Assert.Null(t.Translate6to4(new byte[10]));
        Assert.Equal(SiitDropReason.Malformed, t.LastDropReason);
    }
}
