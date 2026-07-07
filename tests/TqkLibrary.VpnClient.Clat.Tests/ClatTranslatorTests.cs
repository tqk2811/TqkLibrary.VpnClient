using System.Net;
using TqkLibrary.VpnClient.IpStack;
using TqkLibrary.VpnClient.Siit.Enums;
using Xunit;
using static TqkLibrary.VpnClient.Clat.Tests.TestPackets;

namespace TqkLibrary.VpnClient.Clat.Tests;

public class ClatTranslatorTests
{
    // Device 192.0.0.1 (RFC 7335) with a dedicated CLAT /96 + NAT64 WKP 64:ff9b::/96.
    static ClatConfig Config() => new ClatConfig(
        deviceIpv4: IPAddress.Parse("192.0.0.1"),
        clatIpv6Prefix: IPAddress.Parse("2001:db8:aaaa::"),
        nat64Prefix: IPAddress.Parse("64:ff9b::"),
        nat64PrefixLength: 96);

    static readonly IPAddress Device4 = IPAddress.Parse("192.0.0.1");
    static readonly IPAddress Native4 = IPAddress.Parse("8.8.8.8");
    static readonly IPAddress ClatV6 = IPAddress.Parse("2001:db8:aaaa::");   // device source in the CLAT /96 (empty suffix)
    static readonly IPAddress NativeNat64 = IPAddress.Parse("64:ff9b::808:808");

    [Fact]
    public void Udp4to6_UsesClatSourceAndNat64Destination_AndValidChecksum()
    {
        byte[] seg = UdpSegment(Device4, Native4, 40000, 443, new byte[] { 1, 2, 3, 4 });
        byte[] packet = Ipv4Packet(Device4, Native4, Ipv4.ProtocolUdp, seg, id: 0, ttl: 64);

        byte[]? v6 = new ClatTranslator(Config()).Translate4to6(packet);
        Assert.NotNull(v6);
        Assert.Equal(6, Ipv6.Version(v6));
        Assert.Equal(Ipv6.NextHeaderUdp, Ipv6.NextHeader(v6));
        Assert.Equal(63, Ipv6.HopLimit(v6));
        Assert.Equal(ClatV6, Ipv6.Source(v6));           // device IPv4 -> CLAT IPv6 (EAM)
        Assert.Equal(NativeNat64, Ipv6.Destination(v6)); // native IPv4 -> NAT64 (RFC 6052)
        Assert.True(VerifyUdpTcpChecksum(ClatV6, NativeNat64, Ipv4.ProtocolUdp, v6.AsSpan(Ipv6.HeaderLength)));
    }

    [Fact]
    public void Udp_RoundTrip_ByteExactExceptTtl()
    {
        byte[] seg = UdpSegment(Device4, Native4, 40000, 53, new byte[] { 9, 8, 7, 6, 5 });
        byte[] packet = Ipv4Packet(Device4, Native4, Ipv4.ProtocolUdp, seg, id: 0, ttl: 64);

        var t = new ClatTranslator(Config());
        byte[]? back = t.Translate6to4(t.Translate4to6(packet)!);
        Assert.NotNull(back);

        byte[] expected = (byte[])packet.Clone();
        expected[8] = 62;   // TTL decremented once each way
        RewriteIpv4Checksum(expected);
        Assert.Equal(expected, back);
    }

    [Fact]
    public void Tcp_RoundTrip_ByteExactExceptTtl()
    {
        byte[] seg = TcpSegment(Device4, Native4, 12345, 443, new byte[] { 0xAA, 0xBB, 0xCC });
        byte[] packet = Ipv4Packet(Device4, Native4, Ipv4.ProtocolTcp, seg, id: 0, ttl: 64);

        var t = new ClatTranslator(Config());
        byte[]? back = t.Translate6to4(t.Translate4to6(packet)!);
        Assert.NotNull(back);

        byte[] expected = (byte[])packet.Clone();
        expected[8] = 62;
        RewriteIpv4Checksum(expected);
        Assert.Equal(expected, back);
    }

    [Fact]
    public void FromDiscoveredPrefix_ProducesWorkingTranslator()
    {
        var pref64 = new Pref64Prefix(IPAddress.Parse("64:ff9b::"), 96, 3600);
        var t = ClatTranslator.FromDiscoveredPrefix(pref64, Device4, IPAddress.Parse("2001:db8:aaaa::"));

        byte[] seg = UdpSegment(Device4, Native4, 40000, 443, new byte[] { 1 });
        byte[] packet = Ipv4Packet(Device4, Native4, Ipv4.ProtocolUdp, seg, id: 0, ttl: 64);
        byte[]? v6 = t.Translate4to6(packet);
        Assert.NotNull(v6);
        Assert.Equal(NativeNat64, Ipv6.Destination(v6));
    }

    [Fact]
    public void Translate6to4_UnmappedSource_Drops()
    {
        // Inbound IPv6 whose destination is the CLAT address but whose source is neither CLAT nor under the NAT64 prefix.
        byte[] seg = UdpSegment(IPAddress.Parse("2001:dead::1"), ClatV6, 443, 40000, new byte[] { 1 });
        byte[] v6 = Ipv6.Build(IPAddress.Parse("2001:dead::1"), ClatV6, Ipv6.NextHeaderUdp, seg, hopLimit: 64);

        var t = new ClatTranslator(Config());
        Assert.Null(t.Translate6to4(v6));
        Assert.Equal(SiitDropReason.AddressNotMapped, t.LastDropReason);
    }

    [Fact]
    public void Ctor_RejectsInvalidNat64PrefixLength()
        => Assert.Throws<ArgumentOutOfRangeException>(() => new ClatConfig(
            IPAddress.Parse("192.0.0.1"), IPAddress.Parse("2001:db8:aaaa::"), IPAddress.Parse("64:ff9b::"), nat64PrefixLength: 24));

    [Fact]
    public void Ctor_RejectsIpv4AsClatPrefix()
        => Assert.Throws<ArgumentException>(() => new ClatConfig(
            IPAddress.Parse("192.0.0.1"), IPAddress.Parse("10.0.0.0"), IPAddress.Parse("64:ff9b::"), nat64PrefixLength: 96));
}
