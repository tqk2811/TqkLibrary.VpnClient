using System.Net;
using System.Net.Sockets;
using TqkLibrary.VpnClient.Siit;
using TqkLibrary.VpnClient.Siit.Models;

namespace TqkLibrary.VpnClient.Clat;

/// <summary>
/// A 464XLAT CLAT (RFC 6877) customer-side configuration: the device's own IPv4 address (or a small CLAT range) and
/// the dedicated CLAT IPv6 prefix it maps its <b>source</b> into, plus the NAT64 prefix used to embed IPv4
/// <b>destinations</b> (RFC 6052). The two address strategies are precomputed once at construction and combined
/// EAM-first (device source) then RFC 6052 (native destination) — exactly what the SIIT engine consumes.
/// </summary>
public sealed record ClatConfig
{
    /// <summary>
    /// Builds a CLAT config. The device source is mapped 1:1 via an <see cref="ExplicitAddressMap"/> (EAM) entry
    /// <c>DeviceIpv4/len ↔ ClatIpv6Prefix/len</c>; native IPv4 destinations are embedded into
    /// <paramref name="nat64Prefix"/> via <see cref="Rfc6052AddressMapper"/>.
    /// </summary>
    /// <param name="deviceIpv4">This device's private IPv4 address (e.g. <c>192.0.0.1</c>, RFC 7335) or the CLAT IPv4 prefix.</param>
    /// <param name="clatIpv6Prefix">The dedicated CLAT IPv6 prefix the device source is mapped into (typically a /96).</param>
    /// <param name="nat64Prefix">The NAT64 prefix that native IPv4 destinations are embedded into (RFC 6052).</param>
    /// <param name="nat64PrefixLength">NAT64 prefix length — one of 32/40/48/56/64/96 (RFC 6052 §2.2).</param>
    /// <param name="deviceIpv4PrefixLength">Device IPv4 prefix length (default 32 = single host).</param>
    /// <param name="clatIpv6PrefixLength">CLAT IPv6 prefix length (default 96).</param>
    public ClatConfig(
        IPAddress deviceIpv4,
        IPAddress clatIpv6Prefix,
        IPAddress nat64Prefix,
        int nat64PrefixLength,
        int deviceIpv4PrefixLength = 32,
        int clatIpv6PrefixLength = 96)
    {
        if (deviceIpv4 is null) throw new ArgumentNullException(nameof(deviceIpv4));
        if (clatIpv6Prefix is null) throw new ArgumentNullException(nameof(clatIpv6Prefix));
        if (nat64Prefix is null) throw new ArgumentNullException(nameof(nat64Prefix));
        if (deviceIpv4.AddressFamily != AddressFamily.InterNetwork)
            throw new ArgumentException("Device address must be an IPv4 address.", nameof(deviceIpv4));
        if (clatIpv6Prefix.AddressFamily != AddressFamily.InterNetworkV6)
            throw new ArgumentException("CLAT prefix must be an IPv6 address.", nameof(clatIpv6Prefix));
        if (nat64Prefix.AddressFamily != AddressFamily.InterNetworkV6)
            throw new ArgumentException("NAT64 prefix must be an IPv6 address.", nameof(nat64Prefix));

        DeviceIpv4 = deviceIpv4;
        DeviceIpv4PrefixLength = deviceIpv4PrefixLength;
        ClatIpv6Prefix = clatIpv6Prefix;
        ClatIpv6PrefixLength = clatIpv6PrefixLength;
        Nat64Prefix = nat64Prefix;
        Nat64PrefixLength = nat64PrefixLength;

        // EAM entry validates the RFC 7757 §3.3 suffix constraint; the RFC 6052 mapper validates the NAT64 length.
        ClatSourceMap = new ExplicitAddressMap(new[]
        {
            new EamEntry(deviceIpv4, deviceIpv4PrefixLength, clatIpv6Prefix, clatIpv6PrefixLength),
        });
        Nat64Mapper = new Rfc6052AddressMapper(nat64Prefix, nat64PrefixLength);
    }

    /// <summary>This device's IPv4 address (or CLAT IPv4 prefix).</summary>
    public IPAddress DeviceIpv4 { get; }

    /// <summary>Device IPv4 prefix length.</summary>
    public int DeviceIpv4PrefixLength { get; }

    /// <summary>The dedicated CLAT IPv6 prefix (device source is mapped here).</summary>
    public IPAddress ClatIpv6Prefix { get; }

    /// <summary>CLAT IPv6 prefix length.</summary>
    public int ClatIpv6PrefixLength { get; }

    /// <summary>The NAT64 prefix (native IPv4 destinations are embedded here).</summary>
    public IPAddress Nat64Prefix { get; }

    /// <summary>NAT64 prefix length.</summary>
    public int Nat64PrefixLength { get; }

    /// <summary>Precomputed EAM for the CLAT source (device IPv4 ↔ CLAT IPv6), tried first.</summary>
    public ExplicitAddressMap ClatSourceMap { get; }

    /// <summary>Precomputed RFC 6052 mapper for the NAT64 destination, tried as a fallback.</summary>
    public Rfc6052AddressMapper Nat64Mapper { get; }

    /// <summary>Builds the composite CLAT address translator (EAM source first, then RFC 6052 NAT64 destination).</summary>
    public SiitAddressTranslator CreateAddressTranslator() => new SiitAddressTranslator(ClatSourceMap, Nat64Mapper);

    /// <summary>
    /// Builds a config that uses a <see cref="Pref64Prefix"/> discovered via RFC 8781 / RFC 7050 as the NAT64 prefix.
    /// </summary>
    public static ClatConfig FromDiscoveredPrefix(
        Pref64Prefix nat64,
        IPAddress deviceIpv4,
        IPAddress clatIpv6Prefix,
        int deviceIpv4PrefixLength = 32,
        int clatIpv6PrefixLength = 96)
    {
        if (nat64 is null) throw new ArgumentNullException(nameof(nat64));
        return new ClatConfig(deviceIpv4, clatIpv6Prefix, nat64.Prefix, nat64.PrefixLength, deviceIpv4PrefixLength, clatIpv6PrefixLength);
    }
}
