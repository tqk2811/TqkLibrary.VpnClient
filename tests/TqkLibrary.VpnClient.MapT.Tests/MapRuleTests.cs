using System.Net;
using Xunit;

namespace TqkLibrary.VpnClient.MapT.Tests;

public class MapRuleTests
{
    static readonly IPAddress V6 = IPAddress.Parse("2001:db8::");
    static readonly IPAddress V4 = IPAddress.Parse("192.0.2.0");

    [Fact]
    public void EaBitsSmallerThanIpv4Suffix_Throws()
    {
        // o=24 => IPv4 suffix 8 bits; EA-bits 4 < 8 => negative derived PSID length.
        Assert.Throws<ArgumentException>(() => new MapRule(V6, 40, V4, 24, eaBitsLength: 4));
    }

    [Fact]
    public void PsidOffsetPlusLengthExceeds16_Throws()
    {
        // o=24 => suffix 8, EA-bits 24 => k=16; offset 6 + 16 = 22 > 16.
        Assert.Throws<ArgumentException>(() => new MapRule(V6, 40, V4, 24, eaBitsLength: 24, psidOffset: 6));
    }

    [Fact]
    public void PrefixPlusEaBitsExceeds64_Throws()
    {
        // n=60 + EA-bits 8 = 68 > 64 (no room for the 64-bit Interface Identifier).
        Assert.Throws<ArgumentException>(() => new MapRule(V6, 60, V4, 24, eaBitsLength: 8));
    }

    [Fact]
    public void Ipv4PrefixLengthOutOfRange_Throws()
        => Assert.Throws<ArgumentOutOfRangeException>(() => new MapRule(V6, 40, V4, 33, eaBitsLength: 8));

    [Fact]
    public void WrongFamilyRuleIpv6Prefix_Throws()
        => Assert.Throws<ArgumentException>(() => new MapRule(IPAddress.Parse("192.0.2.0"), 40, V4, 24, eaBitsLength: 16));

    [Fact]
    public void InconsistentExplicitPsidLength_Throws()
    {
        // EA-bits 16, o=24 => derived k=8; explicit k=4 contradicts the embedded PSID.
        Assert.Throws<ArgumentException>(() => new MapRule(V6, 40, V4, 24, eaBitsLength: 16, psidOffset: 6, psidLength: 4));
    }
}
