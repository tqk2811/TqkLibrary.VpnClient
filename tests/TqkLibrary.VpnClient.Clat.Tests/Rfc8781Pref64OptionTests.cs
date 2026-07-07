using System.Net;
using Xunit;

namespace TqkLibrary.VpnClient.Clat.Tests;

public class Rfc8781Pref64OptionTests
{
    // Builds a 16-byte RFC 8781 PREF64 option (type 38, length 2) carrying the given PLC, lifetime and 96-bit prefix.
    static byte[] BuildOption(int plc, int lifetimeSeconds, string prefix96)
    {
        byte[] opt = new byte[16];
        opt[0] = Rfc8781Pref64Option.OptionType; // 38
        opt[1] = 2;                              // length in units of 8 bytes
        int field = ((lifetimeSeconds / 8) << 3) | (plc & 0x07);
        opt[2] = (byte)(field >> 8);
        opt[3] = (byte)field;
        byte[] p = IPAddress.Parse(prefix96).GetAddressBytes(); // 16 bytes
        Array.Copy(p, 0, opt, 4, 12);
        return opt;
    }

    // Every RFC 8781 §4 Prefix Length Code -> prefix length, with the scaled lifetime decoded (× 8).
    [Theory]
    [InlineData(0, 96, 3600)]
    [InlineData(1, 64, 600)]
    [InlineData(2, 56, 0)]
    [InlineData(3, 48, 65528)]
    [InlineData(4, 40, 8)]
    [InlineData(5, 32, 1800)]
    public void TryParse_DecodesAllPrefixLengthCodes(int plc, int expectedLength, int lifetime)
    {
        byte[] opt = BuildOption(plc, lifetime, "64:ff9b::");
        Assert.True(Rfc8781Pref64Option.TryParse(opt, out var pref));
        Assert.Equal(IPAddress.Parse("64:ff9b::"), pref.Prefix);
        Assert.Equal(expectedLength, pref.PrefixLength);
        Assert.Equal(lifetime, pref.LifetimeSeconds);
    }

    [Theory]
    [InlineData(6)]
    [InlineData(7)]
    public void TryParse_RejectsReservedPrefixLengthCode(int plc)
    {
        byte[] opt = BuildOption(plc, 3600, "64:ff9b::");
        Assert.False(Rfc8781Pref64Option.TryParse(opt, out _));
    }

    [Fact]
    public void TryParse_RejectsWrongOptionType()
    {
        byte[] opt = BuildOption(0, 3600, "64:ff9b::");
        opt[0] = 3; // Prefix Information option, not PREF64
        Assert.False(Rfc8781Pref64Option.TryParse(opt, out _));
    }

    [Fact]
    public void TryParse_RejectsWrongLengthField()
    {
        byte[] opt = BuildOption(0, 3600, "64:ff9b::");
        opt[1] = 3; // must be 2 (16 bytes)
        Assert.False(Rfc8781Pref64Option.TryParse(opt, out _));
    }

    [Fact]
    public void TryParse_RejectsTooShort()
    {
        byte[] opt = BuildOption(0, 3600, "64:ff9b::");
        Assert.False(Rfc8781Pref64Option.TryParse(opt.AsSpan(0, 15), out _));
    }

    [Fact]
    public void ParseRaOptions_PicksPref64AmongOtherOptions()
    {
        // Source Link-Layer Address (type 1, len 1) + PREF64 (type 38, len 2) + Prefix Information (type 3, len 4).
        byte[] slla = new byte[8]; slla[0] = 1; slla[1] = 1;
        byte[] pref64 = BuildOption(0, 3600, "64:ff9b::");
        byte[] pio = new byte[32]; pio[0] = 3; pio[1] = 4;

        byte[] all = new byte[slla.Length + pref64.Length + pio.Length];
        slla.CopyTo(all, 0);
        pref64.CopyTo(all, slla.Length);
        pio.CopyTo(all, slla.Length + pref64.Length);

        var list = Rfc8781Pref64Option.ParseRaOptions(all);
        Assert.Single(list);
        Assert.Equal(IPAddress.Parse("64:ff9b::"), list[0].Prefix);
        Assert.Equal(96, list[0].PrefixLength);
        Assert.Equal(3600, list[0].LifetimeSeconds);
    }

    [Fact]
    public void ParseRaOptions_ReturnsEveryPref64()
    {
        byte[] a = BuildOption(0, 3600, "64:ff9b::");
        byte[] b = BuildOption(5, 1800, "2001:db8::");
        byte[] all = new byte[a.Length + b.Length];
        a.CopyTo(all, 0);
        b.CopyTo(all, a.Length);

        var list = Rfc8781Pref64Option.ParseRaOptions(all);
        Assert.Equal(2, list.Count);
        Assert.Equal(96, list[0].PrefixLength);
        Assert.Equal(32, list[1].PrefixLength);
    }

    [Fact]
    public void ParseRaOptions_StopsAtMalformedZeroLengthOption()
    {
        byte[] pref64 = BuildOption(0, 3600, "64:ff9b::");
        byte[] all = new byte[pref64.Length + 8];
        pref64.CopyTo(all, 0);
        all[pref64.Length] = 7;     // some option type
        all[pref64.Length + 1] = 0; // length 0 is invalid -> stop after the good one

        var list = Rfc8781Pref64Option.ParseRaOptions(all);
        Assert.Single(list);
    }
}
