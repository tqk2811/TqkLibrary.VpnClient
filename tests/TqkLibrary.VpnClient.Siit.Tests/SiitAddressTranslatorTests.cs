using System.Net;
using TqkLibrary.VpnClient.Siit.Models;
using Xunit;

namespace TqkLibrary.VpnClient.Siit.Tests;

public class SiitAddressTranslatorTests
{
    static SiitAddressTranslator Build()
    {
        var eam = new ExplicitAddressMap()
            .Add(new EamEntry(IPAddress.Parse("192.0.2.0"), 24, IPAddress.Parse("2001:db8:eee::"), 120));
        var rfc6052 = new Rfc6052AddressMapper(); // 64:ff9b::/96
        return new SiitAddressTranslator(eam, rfc6052);
    }

    [Fact]
    public void Eam_TakesPrecedenceOverRfc6052_4to6()
    {
        var t = Build();
        Assert.True(t.TryTranslate4to6(IPAddress.Parse("192.0.2.5"), out var v6));
        Assert.Equal(IPAddress.Parse("2001:db8:eee::5"), v6);   // EAM, not 64:ff9b::
    }

    [Fact]
    public void FallsBackToRfc6052_WhenNoEamMatch_4to6()
    {
        var t = Build();
        Assert.True(t.TryTranslate4to6(IPAddress.Parse("8.8.8.8"), out var v6));
        Assert.Equal(IPAddress.Parse("64:ff9b::808:808"), v6);
    }

    [Fact]
    public void Eam_TakesPrecedenceOverRfc6052_6to4()
    {
        var t = Build();
        Assert.True(t.TryTranslate6to4(IPAddress.Parse("2001:db8:eee::5"), out var v4));
        Assert.Equal(IPAddress.Parse("192.0.2.5"), v4);
    }

    [Fact]
    public void FallsBackToRfc6052_WhenNoEamMatch_6to4()
    {
        var t = Build();
        Assert.True(t.TryTranslate6to4(IPAddress.Parse("64:ff9b::808:808"), out var v4));
        Assert.Equal(IPAddress.Parse("8.8.8.8"), v4);
    }

    [Fact]
    public void EmptyChain_Throws()
        => Assert.Throws<ArgumentException>(() => new SiitAddressTranslator());
}
