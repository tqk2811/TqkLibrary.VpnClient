using System.Net;
using Xunit;

namespace TqkLibrary.VpnClient.MapT.Tests;

public class MapAddressTranslatorTests
{
    // RFC 7597 Appendix A Example 1 CE + DMR = RFC 6052 Well-Known Prefix 64:ff9b::/96.
    static MapTConfig Config() => new MapTConfig(
        new MapRule(IPAddress.Parse("2001:db8::"), 40, IPAddress.Parse("192.0.2.0"), 24, eaBitsLength: 16, psidOffset: 6),
        ceIpv4: IPAddress.Parse("192.0.2.18"),
        psid: 0x34,
        dmrPrefix: IPAddress.Parse("64:ff9b::"),
        dmrPrefixLength: 96);

    static readonly IPAddress CeMapV6 = IPAddress.Parse("2001:db8:12:3400:0:c000:212:34");

    [Fact]
    public void CeIpv4_TranslatesToFixedMapIpv6()
    {
        var t = new MapAddressTranslator(Config());
        Assert.True(t.TryTranslate4to6(IPAddress.Parse("192.0.2.18"), out var v6));
        Assert.Equal(CeMapV6, v6);
        Assert.Equal(CeMapV6, t.CeMapIpv6);
    }

    [Fact]
    public void CeMapIpv6_TranslatesBackToCeIpv4()
    {
        var t = new MapAddressTranslator(Config());
        Assert.True(t.TryTranslate6to4(CeMapV6, out var v4));
        Assert.Equal(IPAddress.Parse("192.0.2.18"), v4);
    }

    [Fact]
    public void NativeIpv4_TranslatesViaDmr()
    {
        var t = new MapAddressTranslator(Config());
        Assert.True(t.TryTranslate4to6(IPAddress.Parse("8.8.8.8"), out var v6));
        Assert.Equal(IPAddress.Parse("64:ff9b::808:808"), v6);   // RFC 6052 embedding under DMR
    }

    [Fact]
    public void DmrIpv6_TranslatesBackToNativeIpv4()
    {
        var t = new MapAddressTranslator(Config());
        Assert.True(t.TryTranslate6to4(IPAddress.Parse("64:ff9b::808:808"), out var v4));
        Assert.Equal(IPAddress.Parse("8.8.8.8"), v4);
    }

    [Fact]
    public void ForeignIpv6_NotCeNorDmr_IsDropped()
    {
        var t = new MapAddressTranslator(Config());
        Assert.False(t.TryTranslate6to4(IPAddress.Parse("2001:dead::1"), out _));
    }

    [Fact]
    public void FromEndUserIpv6Prefix_DerivesSameCeMapAddress()
    {
        var rule = new MapRule(IPAddress.Parse("2001:db8::"), 40, IPAddress.Parse("192.0.2.0"), 24, eaBitsLength: 16, psidOffset: 6);
        var config = MapTConfig.FromEndUserIpv6Prefix(rule, IPAddress.Parse("2001:db8:12:3400::"), IPAddress.Parse("64:ff9b::"), 96);
        Assert.Equal(IPAddress.Parse("192.0.2.18"), config.CeIpv4);
        Assert.Equal(0x34, config.Psid);
        Assert.Equal(CeMapV6, config.CeMapIpv6);
    }

    [Fact]
    public void CeIpv4OutsideRulePrefix_Throws()
    {
        var rule = new MapRule(IPAddress.Parse("2001:db8::"), 40, IPAddress.Parse("192.0.2.0"), 24, eaBitsLength: 16, psidOffset: 6);
        Assert.Throws<ArgumentException>(() => new MapTConfig(rule, IPAddress.Parse("10.0.0.1"), 0x34, IPAddress.Parse("64:ff9b::"), 96));
    }
}
