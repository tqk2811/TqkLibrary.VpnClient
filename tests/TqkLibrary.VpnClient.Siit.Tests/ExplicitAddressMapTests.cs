using System.Net;
using TqkLibrary.VpnClient.Siit.Models;
using Xunit;

namespace TqkLibrary.VpnClient.Siit.Tests;

public class ExplicitAddressMapTests
{
    [Fact]
    public void EqualSuffix_RoundTrips()
    {
        var map = new ExplicitAddressMap()
            .Add(new EamEntry(IPAddress.Parse("192.0.2.0"), 24, IPAddress.Parse("2001:db8:1:2:3:4:5:0"), 120));

        Assert.True(map.TryTranslate4to6(IPAddress.Parse("192.0.2.33"), out var v6));
        Assert.Equal(IPAddress.Parse("2001:db8:1:2:3:4:5:21"), v6);
        Assert.True(map.TryTranslate6to4(v6, out var v4));
        Assert.Equal(IPAddress.Parse("192.0.2.33"), v4);
    }

    [Fact]
    public void LongestPrefixMatch_WinsOverShorter()
    {
        var map = new ExplicitAddressMap()
            .Add(new EamEntry(IPAddress.Parse("10.0.0.0"), 8, IPAddress.Parse("2001:db8:a::"), 40))
            .Add(new EamEntry(IPAddress.Parse("10.1.0.0"), 16, IPAddress.Parse("2001:db8:b::"), 48));

        // 10.1.2.3 matches both /8 and /16 — the /16 entry (2001:db8:b::) must win.
        Assert.True(map.TryTranslate4to6(IPAddress.Parse("10.1.2.3"), out var v6));
        Assert.Equal(IPAddress.Parse("2001:db8:b:203::"), v6);
    }

    [Fact]
    public void UnequalSuffix_PadsAndTruncates()
    {
        var map = new ExplicitAddressMap()
            .Add(new EamEntry(IPAddress.Parse("192.0.2.0"), 24, IPAddress.Parse("2001:db8:aaaa:bbbb:cccc:dddd::"), 96));

        Assert.True(map.TryTranslate4to6(IPAddress.Parse("192.0.2.33"), out var v6));
        Assert.Equal(IPAddress.Parse("2001:db8:aaaa:bbbb:cccc:dddd:2100:0"), v6);
        Assert.True(map.TryTranslate6to4(v6, out var v4));
        Assert.Equal(IPAddress.Parse("192.0.2.33"), v4);
    }

    [Fact]
    public void HostMapping_32_128_RoundTrips()
    {
        var map = new ExplicitAddressMap()
            .Add(new EamEntry(IPAddress.Parse("203.0.113.1"), 32, IPAddress.Parse("2001:db8::1"), 128));

        Assert.True(map.TryTranslate4to6(IPAddress.Parse("203.0.113.1"), out var v6));
        Assert.Equal(IPAddress.Parse("2001:db8::1"), v6);
        Assert.True(map.TryTranslate6to4(IPAddress.Parse("2001:db8::1"), out var v4));
        Assert.Equal(IPAddress.Parse("203.0.113.1"), v4);
    }

    [Fact]
    public void NoMatch_ReturnsFalseBothDirections()
    {
        var map = new ExplicitAddressMap()
            .Add(new EamEntry(IPAddress.Parse("192.0.2.0"), 24, IPAddress.Parse("2001:db8::"), 120));

        Assert.False(map.TryTranslate4to6(IPAddress.Parse("198.51.100.1"), out _));
        Assert.False(map.TryTranslate6to4(IPAddress.Parse("2001:dead::1"), out _));
    }

    [Fact]
    public void Add_RejectsSuffixConstraintViolation()
    {
        // IPv4 suffix (32-24 = 8) must not exceed IPv6 suffix (128-128 = 0).
        var map = new ExplicitAddressMap();
        Assert.Throws<ArgumentException>(() =>
            map.Add(new EamEntry(IPAddress.Parse("192.0.2.0"), 24, IPAddress.Parse("2001:db8::1"), 128)));
    }
}
