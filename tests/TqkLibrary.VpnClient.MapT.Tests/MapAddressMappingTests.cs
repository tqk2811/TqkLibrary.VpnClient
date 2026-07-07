using System.Net;
using Xunit;

namespace TqkLibrary.VpnClient.MapT.Tests;

public class MapAddressMappingTests
{
    // RFC 7597 Appendix A, Example 1 BMR:
    //   End-user IPv6 prefix 2001:db8:0012:3400::/56, Rule IPv6 2001:db8::/40,
    //   Rule IPv4 192.0.2.0/24, EA-bits 16, PSID offset 6  =>  IPv4 192.0.2.18, PSID 0x34, k=8, ratio 256.
    static MapRule Example1Rule() => new MapRule(
        IPAddress.Parse("2001:db8::"), 40,
        IPAddress.Parse("192.0.2.0"), 24,
        eaBitsLength: 16, psidOffset: 6);

    [Fact]
    public void Example1_DeriveCeFromEndUserPrefix_MatchesRfc7597()
    {
        var rule = Example1Rule();
        Assert.True(MapAddressMapping.TryDeriveCe(rule, IPAddress.Parse("2001:db8:12:3400::"), out var ce4, out var psid));
        Assert.Equal(IPAddress.Parse("192.0.2.18"), ce4);
        Assert.Equal(0x34, psid);
    }

    [Fact]
    public void Example1_DeriveMapIpv6_MatchesRfc7597()
    {
        var rule = Example1Rule();
        var mapV6 = MapAddressMapping.DeriveMapIpv6(rule, IPAddress.Parse("192.0.2.18"), 0x34);
        // RFC 7597 Appendix A Example 1: 2001:db8:0012:3400:0000:c000:0212:0034
        Assert.Equal(IPAddress.Parse("2001:db8:12:3400:0:c000:212:34"), mapV6);
    }

    [Fact]
    public void Example1_TryParseMapIpv6_RecoversIpv4AndPsid()
    {
        var rule = Example1Rule();
        Assert.True(MapAddressMapping.TryParseMapIpv6(rule, IPAddress.Parse("2001:db8:12:3400:0:c000:212:34"), out var v4, out var psid));
        Assert.Equal(IPAddress.Parse("192.0.2.18"), v4);
        Assert.Equal(0x34, psid);
    }

    [Fact]
    public void Example1_PsidLengthAndSharingRatio()
    {
        var rule = Example1Rule();
        Assert.Equal(8, rule.PsidLength);
        Assert.Equal(256, rule.SharingRatio);
    }

    [Fact]
    public void Example4_NoEaBits_NoSharing()
    {
        // RFC 7597 Appendix A Example 4: Rule IPv6 2001:db8:12:3400::/56, Rule IPv4 192.0.2.18/32, EA-bits 0.
        var rule = new MapRule(IPAddress.Parse("2001:db8:12:3400::"), 56, IPAddress.Parse("192.0.2.18"), 32, eaBitsLength: 0);
        Assert.Equal(0, rule.PsidLength);
        Assert.Equal(1, rule.SharingRatio);
        var v6 = MapAddressMapping.DeriveMapIpv6(rule, IPAddress.Parse("192.0.2.18"), 0);
        // 2001:db8:0012:3400:0000:c000:0212:0000
        Assert.Equal(IPAddress.Parse("2001:db8:12:3400:0:c000:212:0"), v6);
    }

    [Fact]
    public void Example5_NoEaBits_ExplicitPsidSharing256()
    {
        // RFC 7597 Appendix A Example 5: same as Example 4 but explicit PSID length 8 (ratio 256), PSID 0x34.
        var rule = new MapRule(IPAddress.Parse("2001:db8:12:3400::"), 56, IPAddress.Parse("192.0.2.18"), 32, eaBitsLength: 0, psidOffset: 6, psidLength: 8);
        Assert.Equal(8, rule.PsidLength);
        Assert.Equal(256, rule.SharingRatio);
        var v6 = MapAddressMapping.DeriveMapIpv6(rule, IPAddress.Parse("192.0.2.18"), 0x34);
        // 2001:db8:0012:3400:0000:c000:0212:0034
        Assert.Equal(IPAddress.Parse("2001:db8:12:3400:0:c000:212:34"), v6);
        Assert.True(MapAddressMapping.TryParseMapIpv6(rule, v6, out var v4, out var psid));
        Assert.Equal(IPAddress.Parse("192.0.2.18"), v4);
        Assert.Equal(0x34, psid);
    }

    // Round-trip (IPv4 + PSID) -> MAP IPv6 -> (IPv4 + PSID) across several sharing ratios, all within the
    // derived BMR formula k = EA-bits - (32 - o).
    [Theory]
    [InlineData("2001:db8::", 40, "192.0.2.0", 24, 16, "192.0.2.18", 0x34, 8)]     // ratio 256
    [InlineData("2001:db8::", 40, "192.0.2.0", 24, 12, "192.0.2.99", 0x5, 4)]      // ratio 16
    [InlineData("2001:db8::", 40, "192.0.2.0", 24, 8, "192.0.2.200", 0, 0)]        // ratio 1 (no PSID)
    [InlineData("2001:db8::", 40, "192.0.0.0", 16, 24, "192.0.130.7", 0xAB, 8)]    // /16 rule, ratio 256
    public void RoundTrip_Ipv4Psid_AcrossSharingRatios(string rv6, int n, string rv4, int o, int ea, string ipv4, int psid, int expectedK)
    {
        var rule = new MapRule(IPAddress.Parse(rv6), n, IPAddress.Parse(rv4), o, ea, psidOffset: 6);
        Assert.Equal(expectedK, rule.PsidLength);

        var v6 = MapAddressMapping.DeriveMapIpv6(rule, IPAddress.Parse(ipv4), psid);
        Assert.True(MapAddressMapping.TryParseMapIpv6(rule, v6, out var backV4, out var backPsid));
        Assert.Equal(IPAddress.Parse(ipv4), backV4);
        Assert.Equal(psid, backPsid);
    }

    [Fact]
    public void TryParseMapIpv6_RejectsWrongRulePrefix()
    {
        var rule = Example1Rule();
        Assert.False(MapAddressMapping.TryParseMapIpv6(rule, IPAddress.Parse("2001:dead:12:3400:0:c000:212:34"), out _, out _));
    }

    [Fact]
    public void TryParseMapIpv6_RejectsPsidWiderThanK()
    {
        var rule = Example1Rule();   // k = 8, so the 16-bit PSID field's high byte must be zero
        Assert.False(MapAddressMapping.TryParseMapIpv6(rule, IPAddress.Parse("2001:db8:12:3400:0:c000:212:1234"), out _, out _));
    }
}
