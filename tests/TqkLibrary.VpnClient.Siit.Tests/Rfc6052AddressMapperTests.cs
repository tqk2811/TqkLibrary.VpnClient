using System.Net;
using Xunit;

namespace TqkLibrary.VpnClient.Siit.Tests;

public class Rfc6052AddressMapperTests
{
    // RFC 6052 §2.4 test vectors (IPv4 192.0.2.33 embedded at each allowed prefix length).
    [Theory]
    [InlineData("2001:db8::", 32, "192.0.2.33", "2001:db8:c000:221::")]
    [InlineData("2001:db8:100::", 40, "192.0.2.33", "2001:db8:1c0:2:21::")]
    [InlineData("2001:db8:122::", 48, "192.0.2.33", "2001:db8:122:c000:2:2100::")]
    [InlineData("2001:db8:122:300::", 56, "192.0.2.33", "2001:db8:122:3c0:0:221::")]
    [InlineData("2001:db8:122:344::", 64, "192.0.2.33", "2001:db8:122:344:c0:2:2100::")]
    [InlineData("2001:db8:122:344::", 96, "192.0.2.33", "2001:db8:122:344::c000:221")]
    public void Embed_MatchesRfc6052Vectors(string prefix, int len, string v4, string expectedV6)
    {
        var mapper = new Rfc6052AddressMapper(IPAddress.Parse(prefix), len);
        Assert.True(mapper.TryTranslate4to6(IPAddress.Parse(v4), out var v6));
        Assert.Equal(IPAddress.Parse(expectedV6), v6);
    }

    [Theory]
    [InlineData("2001:db8::", 32, "2001:db8:c000:221::", "192.0.2.33")]
    [InlineData("2001:db8:100::", 40, "2001:db8:1c0:2:21::", "192.0.2.33")]
    [InlineData("2001:db8:122::", 48, "2001:db8:122:c000:2:2100::", "192.0.2.33")]
    [InlineData("2001:db8:122:300::", 56, "2001:db8:122:3c0:0:221::", "192.0.2.33")]
    [InlineData("2001:db8:122:344::", 64, "2001:db8:122:344:c0:2:2100::", "192.0.2.33")]
    [InlineData("2001:db8:122:344::", 96, "2001:db8:122:344::c000:221", "192.0.2.33")]
    public void Extract_MatchesRfc6052Vectors(string prefix, int len, string v6, string expectedV4)
    {
        var mapper = new Rfc6052AddressMapper(IPAddress.Parse(prefix), len);
        Assert.True(mapper.TryTranslate6to4(IPAddress.Parse(v6), out var v4));
        Assert.Equal(IPAddress.Parse(expectedV4), v4);
    }

    [Fact]
    public void DefaultCtor_UsesWellKnownPrefix96()
    {
        var mapper = new Rfc6052AddressMapper();
        Assert.Equal(96, mapper.PrefixLength);
        Assert.True(mapper.TryTranslate4to6(IPAddress.Parse("203.0.113.7"), out var v6));
        Assert.Equal(IPAddress.Parse("64:ff9b::cb00:7107"), v6);
        Assert.True(mapper.TryTranslate6to4(v6, out var v4));
        Assert.Equal(IPAddress.Parse("203.0.113.7"), v4);
    }

    [Fact]
    public void Extract_RejectsNonZeroUOctet()
    {
        // /64 prefix: byte index 8 (the u-octet) must be zero.
        var mapper = new Rfc6052AddressMapper(IPAddress.Parse("2001:db8:122:344::"), 64);
        var bytes = IPAddress.Parse("2001:db8:122:344:c0:2:2100::").GetAddressBytes();
        bytes[8] = 0x01; // corrupt the u-octet
        Assert.False(mapper.TryTranslate6to4(new IPAddress(bytes), out _));
    }

    [Fact]
    public void Extract_RejectsWrongPrefix()
    {
        var mapper = new Rfc6052AddressMapper(IPAddress.Parse("2001:db8::"), 32);
        Assert.False(mapper.TryTranslate6to4(IPAddress.Parse("2001:dead:c000:221::"), out _));
    }

    [Fact]
    public void Embed_LeavesUOctetZero_At64()
    {
        var mapper = new Rfc6052AddressMapper(IPAddress.Parse("2001:db8:122:344::"), 64);
        Assert.True(mapper.TryTranslate4to6(IPAddress.Parse("10.11.12.13"), out var v6));
        Assert.Equal(0, v6.GetAddressBytes()[8]);
    }

    [Theory]
    [InlineData(24)]
    [InlineData(0)]
    [InlineData(128)]
    public void Ctor_RejectsInvalidPrefixLength(int len)
        => Assert.Throws<ArgumentOutOfRangeException>(() => new Rfc6052AddressMapper(IPAddress.Parse("2001:db8::"), len));

    [Fact]
    public void Ctor_RejectsIpv4Prefix()
        => Assert.Throws<ArgumentException>(() => new Rfc6052AddressMapper(IPAddress.Parse("192.0.2.0"), 32));
}
