using System.Net;
using TqkLibrary.VpnClient.Siit;
using Xunit;

namespace TqkLibrary.VpnClient.Clat.Tests;

public class Rfc7050WellKnownPrefixTests
{
    // Synthesises an ipv4only.arpa AAAA by embedding a well-known IPv4 into a NAT64 prefix (reuses the RFC 6052 mapper).
    static byte[] SynthAaaa(string prefix, int len, string wellKnownV4)
    {
        var mapper = new Rfc6052AddressMapper(IPAddress.Parse(prefix), len);
        Assert.True(mapper.TryTranslate4to6(IPAddress.Parse(wellKnownV4), out var v6));
        return v6.GetAddressBytes();
    }

    // A well-known IPv4 (192.0.0.170) embedded at each RFC 6052 §2.2 length must be recovered exactly.
    [Theory]
    [InlineData("2001:db8::", 32)]
    [InlineData("2001:db8:100::", 40)]
    [InlineData("2001:db8:122::", 48)]
    [InlineData("2001:db8:122:300::", 56)]
    [InlineData("2001:db8:122:344::", 64)]
    [InlineData("64:ff9b::", 96)]
    public void TryExtract_RecoversPrefixAndLength(string prefix, int len)
    {
        byte[] aaaa = SynthAaaa(prefix, len, "192.0.0.170");
        Assert.True(Rfc7050WellKnownPrefix.TryExtractNat64Prefix(aaaa, out var got, out int gotLen));
        Assert.Equal(IPAddress.Parse(prefix), got);
        Assert.Equal(len, gotLen);
    }

    [Fact]
    public void TryExtract_AlsoAcceptsSecondWellKnownAddress()
    {
        // RFC 7050 defines two well-known addresses (192.0.0.170 / 192.0.0.171).
        byte[] aaaa = SynthAaaa("64:ff9b::", 96, "192.0.0.171");
        Assert.True(Rfc7050WellKnownPrefix.TryExtractNat64Prefix(aaaa, out var got, out int gotLen));
        Assert.Equal(IPAddress.Parse("64:ff9b::"), got);
        Assert.Equal(96, gotLen);
    }

    [Fact]
    public void TryExtract_ReturnsFalseWhenNoWellKnownIpv4()
    {
        byte[] aaaa = IPAddress.Parse("64:ff9b::1234:5678").GetAddressBytes(); // embeds 18.52.86.120, not well-known
        Assert.False(Rfc7050WellKnownPrefix.TryExtractNat64Prefix(aaaa, out _, out _));
    }

    [Fact]
    public void TryExtract_ReturnsFalseForNon16ByteInput()
    {
        Assert.False(Rfc7050WellKnownPrefix.TryExtractNat64Prefix(new byte[4], out _, out _));
    }
}
