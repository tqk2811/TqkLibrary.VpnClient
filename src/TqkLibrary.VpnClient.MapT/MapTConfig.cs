using System.Net;
using System.Net.Sockets;
using TqkLibrary.VpnClient.Siit;
using TqkLibrary.VpnClient.Siit.Helpers;

namespace TqkLibrary.VpnClient.MapT;

/// <summary>
/// A MAP-T CE (Customer Edge) domain configuration (RFC 7599): the Basic Mapping Rule plus this CE's own
/// IPv4 address and PSID, and the Default Mapping Rule (DMR) IPv6 prefix used to reach IPv4 native
/// destinations via RFC 6052 embedding. The CE's fixed MAP IPv6 address (<see cref="CeMapIpv6"/>) and the
/// reusable DMR mapper are computed once at construction.
/// </summary>
public sealed record MapTConfig
{
    /// <summary>Creates a config from this CE's IPv4 address and PSID.</summary>
    /// <param name="rule">The Basic Mapping Rule.</param>
    /// <param name="ceIpv4">This CE's IPv4 address (must be inside the Rule IPv4 prefix).</param>
    /// <param name="psid">This CE's PSID (0..<see cref="MapRule.SharingRatio"/>−1).</param>
    /// <param name="dmrPrefix">Default Mapping Rule IPv6 prefix (RFC 6052 embedding of native IPv4).</param>
    /// <param name="dmrPrefixLength">DMR prefix length (one of RFC 6052 §2.2: 32/40/48/56/64/96).</param>
    public MapTConfig(MapRule rule, IPAddress ceIpv4, int psid, IPAddress dmrPrefix, int dmrPrefixLength)
    {
        if (rule is null) throw new ArgumentNullException(nameof(rule));
        if (ceIpv4 is null) throw new ArgumentNullException(nameof(ceIpv4));
        if (dmrPrefix is null) throw new ArgumentNullException(nameof(dmrPrefix));
        if (ceIpv4.AddressFamily != AddressFamily.InterNetwork)
            throw new ArgumentException("A CE IPv4 address is required.", nameof(ceIpv4));
        if (dmrPrefix.AddressFamily != AddressFamily.InterNetworkV6)
            throw new ArgumentException("DMR prefix must be an IPv6 address.", nameof(dmrPrefix));
        if (psid < 0 || psid >= rule.SharingRatio)
            throw new ArgumentOutOfRangeException(nameof(psid), psid, $"PSID must be 0..{rule.SharingRatio - 1}.");
        if (!AddressBits.PrefixMatches(ceIpv4.GetAddressBytes(), rule.RuleIpv4Prefix.GetAddressBytes(), rule.RuleIpv4PrefixLength))
            throw new ArgumentException("CE IPv4 address is not inside the Rule IPv4 prefix.", nameof(ceIpv4));

        Rule = rule;
        CeIpv4 = ceIpv4;
        Psid = psid;
        DmrPrefix = dmrPrefix;
        DmrPrefixLength = dmrPrefixLength;
        // Reuse the SIIT RFC 6052 mapper for the DMR; its ctor validates the prefix length (32/40/48/56/64/96).
        DmrMapper = new Rfc6052AddressMapper(dmrPrefix, dmrPrefixLength);
        CeMapIpv6 = MapAddressMapping.DeriveMapIpv6(rule, ceIpv4, psid);
    }

    /// <summary>The Basic Mapping Rule.</summary>
    public MapRule Rule { get; }

    /// <summary>This CE's IPv4 address.</summary>
    public IPAddress CeIpv4 { get; }

    /// <summary>This CE's PSID.</summary>
    public int Psid { get; }

    /// <summary>Default Mapping Rule IPv6 prefix.</summary>
    public IPAddress DmrPrefix { get; }

    /// <summary>Default Mapping Rule prefix length.</summary>
    public int DmrPrefixLength { get; }

    /// <summary>The CE's fixed MAP IPv6 address, precomputed from the BMR + CE IPv4 + PSID.</summary>
    public IPAddress CeMapIpv6 { get; }

    /// <summary>Reused RFC 6052 mapper for the Default Mapping Rule (native IPv4 ↔ DMR-embedded IPv6).</summary>
    public Rfc6052AddressMapper DmrMapper { get; }

    /// <summary>
    /// Builds a config by first deriving this CE's IPv4 address and PSID from its End-user IPv6 prefix (BMR).
    /// </summary>
    public static MapTConfig FromEndUserIpv6Prefix(MapRule rule, IPAddress endUserIpv6Prefix, IPAddress dmrPrefix, int dmrPrefixLength)
    {
        if (rule is null) throw new ArgumentNullException(nameof(rule));
        if (!MapAddressMapping.TryDeriveCe(rule, endUserIpv6Prefix, out var ceIpv4, out var psid))
            throw new ArgumentException("Could not derive CE IPv4/PSID from the End-user IPv6 prefix.", nameof(endUserIpv6Prefix));
        return new MapTConfig(rule, ceIpv4, psid, dmrPrefix, dmrPrefixLength);
    }
}
