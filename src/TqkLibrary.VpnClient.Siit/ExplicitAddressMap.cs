using System.Net;
using System.Net.Sockets;
using TqkLibrary.VpnClient.Siit.Helpers;
using TqkLibrary.VpnClient.Siit.Interfaces;
using TqkLibrary.VpnClient.Siit.Models;

namespace TqkLibrary.VpnClient.Siit;

/// <summary>
/// Explicit Address Mapping Table (RFC 7757): a longest-prefix-match table of IPv4↔IPv6 prefix pairs. On translation
/// the matched prefix is stripped, the remaining suffix bits are prepended with the opposite prefix, then the result
/// is zero-padded (to 128 bits, 4→6) or truncated (to 32 bits, 6→4) — RFC 7757 §3.3.1/§3.3.2. Stateful; behind
/// <see cref="IAddressTranslator"/> for DI/testability.
/// </summary>
public sealed class ExplicitAddressMap : IAddressTranslator
{
    sealed class Entry
    {
        public byte[] V4Prefix = default!;
        public int V4Len;
        public byte[] V6Prefix = default!;
        public int V6Len;
    }

    readonly List<Entry> _entries = new();

    /// <summary>Creates an empty table.</summary>
    public ExplicitAddressMap() { }

    /// <summary>Creates a table pre-populated with <paramref name="entries"/>.</summary>
    public ExplicitAddressMap(IEnumerable<EamEntry> entries)
    {
        if (entries is null) throw new ArgumentNullException(nameof(entries));
        foreach (var e in entries) Add(e);
    }

    /// <summary>Adds an EAM entry, validating the RFC 7757 §3.3 constraints. Returns this table for chaining.</summary>
    public ExplicitAddressMap Add(EamEntry entry)
    {
        if (entry is null) throw new ArgumentNullException(nameof(entry));
        if (entry.Ipv4Prefix.AddressFamily != AddressFamily.InterNetwork)
            throw new ArgumentException("Ipv4Prefix must be an IPv4 address.", nameof(entry));
        if (entry.Ipv6Prefix.AddressFamily != AddressFamily.InterNetworkV6)
            throw new ArgumentException("Ipv6Prefix must be an IPv6 address.", nameof(entry));
        if (entry.Ipv4PrefixLength < 0 || entry.Ipv4PrefixLength > 32)
            throw new ArgumentOutOfRangeException(nameof(entry), entry.Ipv4PrefixLength, "IPv4 prefix length must be 0..32.");
        if (entry.Ipv6PrefixLength < 0 || entry.Ipv6PrefixLength > 128)
            throw new ArgumentOutOfRangeException(nameof(entry), entry.Ipv6PrefixLength, "IPv6 prefix length must be 0..128.");
        // RFC 7757 §3.3: the IPv4 suffix must have no more bits than the IPv6 suffix.
        if ((32 - entry.Ipv4PrefixLength) > (128 - entry.Ipv6PrefixLength))
            throw new ArgumentException("RFC 7757 §3.3: the IPv4 suffix length (32 − IPv4 prefix length) must not exceed the IPv6 suffix length (128 − IPv6 prefix length).", nameof(entry));

        _entries.Add(new Entry
        {
            V4Prefix = entry.Ipv4Prefix.GetAddressBytes(),
            V4Len = entry.Ipv4PrefixLength,
            V6Prefix = entry.Ipv6Prefix.GetAddressBytes(),
            V6Len = entry.Ipv6PrefixLength,
        });
        return this;
    }

    /// <inheritdoc/>
    public bool TryTranslate4to6(IPAddress v4, out IPAddress v6)
    {
        v6 = IPAddress.IPv6None;
        if (v4 is null || v4.AddressFamily != AddressFamily.InterNetwork) return false;

        byte[] a = v4.GetAddressBytes();
        Entry? best = null;
        foreach (var e in _entries)
            if (AddressBits.PrefixMatches(a, e.V4Prefix, e.V4Len) && (best is null || e.V4Len > best.V4Len))
                best = e;
        if (best is null) return false;

        byte[] r = new byte[16];
        AddressBits.CopyBits(r, 0, best.V6Prefix, 0, best.V6Len);       // IPv6 prefix
        AddressBits.CopyBits(r, best.V6Len, a, best.V4Len, 32 - best.V4Len); // IPv4 suffix (rest already zero-padded)
        v6 = new IPAddress(r);
        return true;
    }

    /// <inheritdoc/>
    public bool TryTranslate6to4(IPAddress v6, out IPAddress v4)
    {
        v4 = IPAddress.None;
        if (v6 is null || v6.AddressFamily != AddressFamily.InterNetworkV6) return false;

        byte[] a = v6.GetAddressBytes();
        Entry? best = null;
        foreach (var e in _entries)
            if (AddressBits.PrefixMatches(a, e.V6Prefix, e.V6Len) && (best is null || e.V6Len > best.V6Len))
                best = e;
        if (best is null) return false;

        byte[] r = new byte[4];
        AddressBits.CopyBits(r, 0, best.V4Prefix, 0, best.V4Len);       // IPv4 prefix
        int copy = Math.Min(128 - best.V6Len, 32 - best.V4Len);         // truncate to 32 bits
        AddressBits.CopyBits(r, best.V4Len, a, best.V6Len, copy);       // IPv6 suffix
        v4 = new IPAddress(r);
        return true;
    }
}
