using System.Net;
using System.Net.Sockets;
using TqkLibrary.VpnClient.Siit.Interfaces;

namespace TqkLibrary.VpnClient.Siit;

/// <summary>
/// Embeds an IPv4 address inside an IPv6 address (and extracts it) per RFC 6052 §2.2 for the allowed prefix
/// lengths 32/40/48/56/64/96. The reserved "u" octet (bits 64..71) is always zero, so the 32 IPv4 bits are
/// laid out around byte index 8. The default is the IANA Well-Known Prefix <c>64:ff9b::/96</c> (RFC 6052 §2.1).
/// Stateful (holds the configured prefix) and used behind <see cref="IAddressTranslator"/> for DI/testability.
/// </summary>
public sealed class Rfc6052AddressMapper : IAddressTranslator
{
    /// <summary>The IANA "Well-Known Prefix" <c>64:ff9b::/96</c> (RFC 6052 §2.1) — the default NAT64 prefix.</summary>
    public static IPAddress WellKnownPrefix { get; } = IPAddress.Parse("64:ff9b::");

    static readonly int[] AllowedLengths = { 32, 40, 48, 56, 64, 96 };

    readonly byte[] _prefix; // 16 bytes; only the first _prefixBytes are significant
    readonly int _prefixBytes;

    /// <summary>Creates a mapper for the Well-Known Prefix <c>64:ff9b::/96</c>.</summary>
    public Rfc6052AddressMapper() : this(WellKnownPrefix, 96) { }

    /// <summary>Creates a mapper for a custom NAT64 <paramref name="prefix"/> whose length must be one of 32/40/48/56/64/96 (RFC 6052 §2.2).</summary>
    public Rfc6052AddressMapper(IPAddress prefix, int prefixLength)
    {
        if (prefix is null) throw new ArgumentNullException(nameof(prefix));
        if (prefix.AddressFamily != AddressFamily.InterNetworkV6)
            throw new ArgumentException("Prefix must be an IPv6 address.", nameof(prefix));
        if (Array.IndexOf(AllowedLengths, prefixLength) < 0)
            throw new ArgumentOutOfRangeException(nameof(prefixLength), prefixLength, "RFC 6052 §2.2 allows only prefix lengths 32, 40, 48, 56, 64 or 96.");

        _prefix = prefix.GetAddressBytes();
        PrefixLength = prefixLength;
        _prefixBytes = prefixLength / 8;
    }

    /// <summary>The configured prefix length in bits.</summary>
    public int PrefixLength { get; }

    /// <inheritdoc/>
    public bool TryTranslate4to6(IPAddress v4, out IPAddress v6)
    {
        v6 = IPAddress.IPv6None;
        if (v4 is null || v4.AddressFamily != AddressFamily.InterNetwork) return false;

        byte[] a = v4.GetAddressBytes();
        byte[] r = new byte[16];
        Array.Copy(_prefix, 0, r, 0, _prefixBytes);

        int b = _prefixBytes;
        for (int i = 0; i < 4; i++)
        {
            if (b == 8) b = 9;      // skip the reserved u-octet (bits 64..71)
            r[b] = a[i];
            b++;
        }
        v6 = new IPAddress(r);
        return true;
    }

    /// <inheritdoc/>
    public bool TryTranslate6to4(IPAddress v6, out IPAddress v4)
    {
        v4 = IPAddress.None;
        if (v6 is null || v6.AddressFamily != AddressFamily.InterNetworkV6) return false;

        byte[] a = v6.GetAddressBytes();
        for (int i = 0; i < _prefixBytes; i++)
            if (a[i] != _prefix[i]) return false;                 // prefix must match

        if (_prefixBytes <= 8 && a[8] != 0) return false;         // RFC 6052 §2.2: u-octet MUST be zero

        byte[] o = new byte[4];
        int b = _prefixBytes;
        for (int i = 0; i < 4; i++)
        {
            if (b == 8) b = 9;
            o[i] = a[b];
            b++;
        }
        v4 = new IPAddress(o);
        return true;
    }
}
