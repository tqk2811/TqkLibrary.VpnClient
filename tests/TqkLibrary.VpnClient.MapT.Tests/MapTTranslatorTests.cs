using System.Net;
using TqkLibrary.VpnClient.IpStack;
using TqkLibrary.VpnClient.Siit.Enums;
using Xunit;
using static TqkLibrary.VpnClient.MapT.Tests.TestPackets;

namespace TqkLibrary.VpnClient.MapT.Tests;

public class MapTTranslatorTests
{
    // RFC 7597 Appendix A Example 1 CE (192.0.2.18, PSID 0x34) + DMR = 64:ff9b::/96.
    static MapTConfig Config() => new MapTConfig(
        new MapRule(IPAddress.Parse("2001:db8::"), 40, IPAddress.Parse("192.0.2.0"), 24, eaBitsLength: 16, psidOffset: 6),
        ceIpv4: IPAddress.Parse("192.0.2.18"), psid: 0x34,
        dmrPrefix: IPAddress.Parse("64:ff9b::"), dmrPrefixLength: 96);

    static readonly IPAddress Ce4 = IPAddress.Parse("192.0.2.18");
    static readonly IPAddress Native4 = IPAddress.Parse("8.8.8.8");
    static readonly IPAddress CeMapV6 = IPAddress.Parse("2001:db8:12:3400:0:c000:212:34");
    static readonly IPAddress NativeDmr6 = IPAddress.Parse("64:ff9b::808:808");

    [Fact]
    public void Udp4to6_UsesMapAndDmrAddresses_AndValidChecksum()
    {
        byte[] seg = UdpSegment(Ce4, Native4, 40000, 443, new byte[] { 1, 2, 3, 4 });
        byte[] packet = Ipv4Packet(Ce4, Native4, Ipv4.ProtocolUdp, seg, id: 0, ttl: 64);

        byte[]? v6 = new MapTTranslator(Config()).Translate4to6(packet);
        Assert.NotNull(v6);
        Assert.Equal(6, Ipv6.Version(v6));
        Assert.Equal(Ipv6.NextHeaderUdp, Ipv6.NextHeader(v6));
        Assert.Equal(63, Ipv6.HopLimit(v6));
        Assert.Equal(CeMapV6, Ipv6.Source(v6));       // CE IPv4 -> fixed MAP IPv6
        Assert.Equal(NativeDmr6, Ipv6.Destination(v6)); // native IPv4 -> DMR (RFC 6052)
        Assert.True(VerifyUdpTcpChecksum(CeMapV6, NativeDmr6, Ipv4.ProtocolUdp, v6.AsSpan(Ipv6.HeaderLength)));
    }

    [Fact]
    public void Udp_DoubleTranslation_RoundTrip_ByteExactExceptTtl()
    {
        byte[] seg = UdpSegment(Ce4, Native4, 40000, 53, new byte[] { 9, 8, 7, 6, 5 });
        byte[] packet = Ipv4Packet(Ce4, Native4, Ipv4.ProtocolUdp, seg, id: 0, ttl: 64);

        var t = new MapTTranslator(Config());
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
    public void Tcp_DoubleTranslation_RoundTrip_ByteExactExceptTtl()
    {
        byte[] seg = TcpSegment(Ce4, Native4, 12345, 443, new byte[] { 0xAA, 0xBB, 0xCC });
        byte[] packet = Ipv4Packet(Ce4, Native4, Ipv4.ProtocolTcp, seg, id: 0, ttl: 64);

        var t = new MapTTranslator(Config());
        byte[]? back = t.Translate6to4(t.Translate4to6(packet)!);
        Assert.NotNull(back);

        byte[] expected = (byte[])packet.Clone();
        expected[8] = 62;
        RewriteIpv4Checksum(expected);
        Assert.Equal(expected, back);
    }

    [Fact]
    public void Translate6to4_UnmappedSourceAddress_Drops()
    {
        // Inbound IPv6 whose destination is the CE but whose source is neither CE nor under the DMR prefix.
        byte[] seg = UdpSegment(IPAddress.Parse("2001:dead::1"), CeMapV6, 443, 40000, new byte[] { 1 });
        byte[] v6 = Ipv6.Build(IPAddress.Parse("2001:dead::1"), CeMapV6, Ipv6.NextHeaderUdp, seg, hopLimit: 64);

        var t = new MapTTranslator(Config());
        Assert.Null(t.Translate6to4(v6));
        Assert.Equal(SiitDropReason.AddressNotMapped, t.LastDropReason);
    }
}
