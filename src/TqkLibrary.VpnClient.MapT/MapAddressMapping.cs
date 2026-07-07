using System.Net;
using System.Net.Sockets;
using TqkLibrary.VpnClient.Siit.Helpers;

namespace TqkLibrary.VpnClient.MapT;

/// <summary>
/// The pure MAP addressing algorithm (RFC 7597 §5.2). Converts between a CE's (IPv4 address, PSID) and its
/// MAP IPv6 address, and derives (IPv4, PSID) from an End-user IPv6 prefix via the Basic Mapping Rule.
/// Stateless — the non-byte-aligned bit copies reuse <see cref="AddressBits"/> from the SIIT engine.
/// </summary>
public static class MapAddressMapping
{
    /// <summary>
    /// Builds a CE's MAP IPv6 address (RFC 7597 §5.2): Rule-IPv6-prefix(n) ‖ EA-bits ‖ subnet-id(0) ‖
    /// Interface-Identifier, where the 64-bit IID = 0x0000 ‖ IPv4(32) ‖ PSID(16, right-aligned).
    /// </summary>
    public static IPAddress DeriveMapIpv6(MapRule rule, IPAddress ipv4, int psid)
    {
        if (rule is null) throw new ArgumentNullException(nameof(rule));
        if (ipv4 is null) throw new ArgumentNullException(nameof(ipv4));
        if (ipv4.AddressFamily != AddressFamily.InterNetwork)
            throw new ArgumentException("An IPv4 address is required.", nameof(ipv4));
        if (psid < 0 || psid >= (1 << rule.PsidLength))
            throw new ArgumentOutOfRangeException(nameof(psid), psid, $"PSID must be 0..{(1 << rule.PsidLength) - 1} for PSID length {rule.PsidLength}.");

        byte[] v4 = ipv4.GetAddressBytes();
        byte[] result = new byte[16];

        // Rule IPv6 prefix (n bits, MSB-first, possibly non-byte-aligned).
        AddressBits.CopyBits(result, 0, rule.RuleIpv6Prefix.GetAddressBytes(), 0, rule.RuleIpv6PrefixLength);

        // EA-bits = IPv4-suffix(32−o bits) ‖ PSID(k bits), placed just after the rule prefix.
        uint suffix = ExtractLowBits(ToUInt32(v4), rule.Ipv4SuffixBits);
        ulong ea = ((ulong)suffix << rule.PsidLength) | (uint)psid;
        WriteBits(result, rule.RuleIpv6PrefixLength, ea, rule.EaBitsLength);

        // subnet-id (bits [n+EA, 64)) stays zero.

        // Interface Identifier (RFC 7597 §5.2): 0x0000 ‖ full IPv4 ‖ PSID (16-bit, right-aligned).
        result[8] = 0x00;
        result[9] = 0x00;
        result[10] = v4[0];
        result[11] = v4[1];
        result[12] = v4[2];
        result[13] = v4[3];
        result[14] = (byte)(psid >> 8);
        result[15] = (byte)psid;

        return new IPAddress(result);
    }

    /// <summary>
    /// Extracts a CE's IPv4 address and PSID from a MAP IPv6 address by reading its Interface Identifier
    /// (0x0000 ‖ IPv4 ‖ PSID). Returns false if the address family, Rule IPv6 prefix, IID shape or PSID
    /// width do not match <paramref name="rule"/>.
    /// </summary>
    public static bool TryParseMapIpv6(MapRule rule, IPAddress v6, out IPAddress ipv4, out int psid)
    {
        if (rule is null) throw new ArgumentNullException(nameof(rule));
        ipv4 = IPAddress.None;
        psid = 0;
        if (v6 is null || v6.AddressFamily != AddressFamily.InterNetworkV6) return false;

        byte[] a = v6.GetAddressBytes();
        if (!AddressBits.PrefixMatches(a, rule.RuleIpv6Prefix.GetAddressBytes(), rule.RuleIpv6PrefixLength))
            return false;
        if (a[8] != 0x00 || a[9] != 0x00) return false;              // IID must start with 0x0000

        int candidatePsid = (a[14] << 8) | a[15];
        if (candidatePsid >= (1 << rule.PsidLength)) return false;    // PSID must fit in k bits (high bits zero)

        ipv4 = new IPAddress(new[] { a[10], a[11], a[12], a[13] });
        psid = candidatePsid;
        return true;
    }

    /// <summary>
    /// Derives a CE's IPv4 address and PSID from its End-user IPv6 prefix using the Basic Mapping Rule
    /// (RFC 7597 §5): reads the EA-bits following the Rule IPv6 prefix, splitting them into the IPv4 suffix
    /// (high 32−o bits) and PSID (low k bits). Returns false on an address-family mismatch.
    /// </summary>
    public static bool TryDeriveCe(MapRule rule, IPAddress endUserIpv6Prefix, out IPAddress ipv4, out int psid)
    {
        if (rule is null) throw new ArgumentNullException(nameof(rule));
        ipv4 = IPAddress.None;
        psid = 0;
        if (endUserIpv6Prefix is null || endUserIpv6Prefix.AddressFamily != AddressFamily.InterNetworkV6) return false;

        byte[] a = endUserIpv6Prefix.GetAddressBytes();
        ulong ea = ReadBits(a, rule.RuleIpv6PrefixLength, rule.EaBitsLength);
        uint suffix = (uint)(ea >> rule.PsidLength);
        psid = (int)(ea & (ulong)((1 << rule.PsidLength) - 1));

        uint prefix = MaskHighBits(ToUInt32(rule.RuleIpv4Prefix.GetAddressBytes()), rule.RuleIpv4PrefixLength);
        ipv4 = FromUInt32(prefix | suffix);
        return true;
    }

    // ---- MSB-first bit helpers built on the SIIT AddressBits primitives (no rewrite) ----

    static void WriteBits(Span<byte> dst, int startBit, ulong value, int bitLength)
    {
        for (int i = 0; i < bitLength; i++)
            AddressBits.SetBit(dst, startBit + i, (int)((value >> (bitLength - 1 - i)) & 1));
    }

    static ulong ReadBits(ReadOnlySpan<byte> src, int startBit, int bitLength)
    {
        ulong value = 0;
        for (int i = 0; i < bitLength; i++)
            value = (value << 1) | (uint)AddressBits.GetBit(src, startBit + i);
        return value;
    }

    static uint ExtractLowBits(uint value, int bits)
        => bits <= 0 ? 0u : bits >= 32 ? value : value & ((1u << bits) - 1);

    static uint MaskHighBits(uint value, int highBits)
        => highBits <= 0 ? 0u : highBits >= 32 ? value : value & (0xFFFFFFFFu << (32 - highBits));

    static uint ToUInt32(byte[] b) => ((uint)b[0] << 24) | ((uint)b[1] << 16) | ((uint)b[2] << 8) | b[3];

    static IPAddress FromUInt32(uint v)
        => new IPAddress(new[] { (byte)(v >> 24), (byte)(v >> 16), (byte)(v >> 8), (byte)v });
}
