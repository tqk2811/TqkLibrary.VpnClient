using System.Net;

namespace TqkLibrary.VpnClient.Clat;

/// <summary>
/// Codec for the RFC 8781 "PREF64" option carried inside an ICMPv6 Router Advertisement: it lets a CLAT learn the
/// NAT64 prefix from the router instead of static configuration. The option is a fixed 16-byte TLV
/// (<c>Type(1)=38 · Length(1)=2 · Scaled-Lifetime(13 bit)‖PLC(3 bit) · Highest-96-bits-of-Prefix(12 byte)</c>).
/// Stateless — reads only, does not build.
/// </summary>
public static class Rfc8781Pref64Option
{
    /// <summary>The RFC 8781 §4 PREF64 option type in an ICMPv6 Router Advertisement.</summary>
    public const byte OptionType = 38;

    // RFC 8781 §4: Length is in units of 8 bytes; a PREF64 option is always 2 units = 16 bytes.
    const byte LengthUnits = 2;
    const int OptionBytes = LengthUnits * 8;

    /// <summary>
    /// Parses a single 16-byte PREF64 option (RFC 8781 §4). Returns false when the type/length is wrong, the buffer
    /// is too short, or the Prefix Length Code (PLC) is not one of the six RFC 6052 §2.2 values.
    /// </summary>
    public static bool TryParse(ReadOnlySpan<byte> raOption, out Pref64Prefix prefix)
    {
        prefix = default!;
        if (raOption.Length < OptionBytes) return false;
        if (raOption[0] != OptionType) return false;
        if (raOption[1] != LengthUnits) return false;

        // Scaled Lifetime (13 bits) ‖ PLC (3 bits), big-endian.
        int field = (raOption[2] << 8) | raOption[3];
        int plc = field & 0x07;
        if (!TryPlcToPrefixLength(plc, out int prefixLength)) return false;

        int lifetimeSeconds = (field >> 3) << 3;   // 13-bit scaled lifetime, in units of 8 seconds

        // Highest 96 bits of the prefix live in bytes 4..15; the low 32 bits of the IPv6 address are zero.
        byte[] p = new byte[16];
        raOption.Slice(4, 12).CopyTo(p);
        prefix = new Pref64Prefix(new IPAddress(p), prefixLength, lifetimeSeconds);
        return true;
    }

    /// <summary>
    /// Walks a Router Advertisement option area (a chain of RFC 4861 TLV options, each length in 8-byte units) and
    /// returns every valid PREF64 option (type 38) found. Stops at a malformed option (zero length or overrun).
    /// </summary>
    public static IReadOnlyList<Pref64Prefix> ParseRaOptions(ReadOnlySpan<byte> allOptions)
    {
        var result = new List<Pref64Prefix>();
        int i = 0;
        while (i + 2 <= allOptions.Length)
        {
            int lenUnits = allOptions[i + 1];
            if (lenUnits == 0) break;             // RFC 4861 §4.6: a length of 0 is invalid
            int optLen = lenUnits * 8;
            if (i + optLen > allOptions.Length) break;
            if (allOptions[i] == OptionType && TryParse(allOptions.Slice(i, optLen), out var pref))
                result.Add(pref);
            i += optLen;
        }
        return result;
    }

    // RFC 8781 §4 Prefix Length Code -> prefix length in bits. Any other value is reserved / ignored.
    static bool TryPlcToPrefixLength(int plc, out int prefixLength)
    {
        switch (plc)
        {
            case 0: prefixLength = 96; return true;
            case 1: prefixLength = 64; return true;
            case 2: prefixLength = 56; return true;
            case 3: prefixLength = 48; return true;
            case 4: prefixLength = 40; return true;
            case 5: prefixLength = 32; return true;
            default: prefixLength = 0; return false;
        }
    }
}
