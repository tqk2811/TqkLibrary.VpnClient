using System.Net;
using System.Net.Sockets;

namespace TqkLibrary.VpnClient.MapT;

/// <summary>
/// A MAP Basic Mapping Rule (BMR, RFC 7597 §5): binds a Rule IPv6 prefix to a Rule IPv4 prefix with an
/// EA-bits field and a PSID offset. Together these describe how a CE's IPv4 address + PSID are algorithmically
/// derived from — and embedded into — its End-user IPv6 prefix. <see cref="PsidLength"/> (k) and
/// <see cref="SharingRatio"/> (2^k) are derived from the rule and validated for consistency at construction.
/// </summary>
public sealed record MapRule
{
    /// <summary>
    /// Creates and validates a BMR. By default the PSID length is derived (EA-bits − IPv4-suffix bits);
    /// pass <paramref name="psidLength"/> only for the RFC 7597 §5.2 "no EA-bits, explicit PSID" case
    /// (Appendix A Example 5) where the PSID is assigned out-of-band rather than embedded in the prefix.
    /// </summary>
    /// <param name="ruleIpv6Prefix">Rule IPv6 prefix (only the first <paramref name="ruleIpv6PrefixLength"/> bits are significant).</param>
    /// <param name="ruleIpv6PrefixLength">Rule IPv6 prefix length n in bits (0..128).</param>
    /// <param name="ruleIpv4Prefix">Rule IPv4 prefix (only the first <paramref name="ruleIpv4PrefixLength"/> bits are significant).</param>
    /// <param name="ruleIpv4PrefixLength">Rule IPv4 prefix length o in bits (0..32).</param>
    /// <param name="eaBitsLength">EA-bits length = (32 − o) + k. 0..48.</param>
    /// <param name="psidOffset">PSID offset a (default 6, the GMA "a-bits"). 0..16.</param>
    /// <param name="psidLength">Explicit PSID length k; when null it is derived as EA-bits − (32 − o).</param>
    public MapRule(
        IPAddress ruleIpv6Prefix, int ruleIpv6PrefixLength,
        IPAddress ruleIpv4Prefix, int ruleIpv4PrefixLength,
        int eaBitsLength, int psidOffset = 6, int? psidLength = null)
    {
        if (ruleIpv6Prefix is null) throw new ArgumentNullException(nameof(ruleIpv6Prefix));
        if (ruleIpv4Prefix is null) throw new ArgumentNullException(nameof(ruleIpv4Prefix));
        if (ruleIpv6Prefix.AddressFamily != AddressFamily.InterNetworkV6)
            throw new ArgumentException("Rule IPv6 prefix must be an IPv6 address.", nameof(ruleIpv6Prefix));
        if (ruleIpv4Prefix.AddressFamily != AddressFamily.InterNetwork)
            throw new ArgumentException("Rule IPv4 prefix must be an IPv4 address.", nameof(ruleIpv4Prefix));
        if (ruleIpv6PrefixLength < 0 || ruleIpv6PrefixLength > 128)
            throw new ArgumentOutOfRangeException(nameof(ruleIpv6PrefixLength), ruleIpv6PrefixLength, "IPv6 prefix length must be 0..128.");
        if (ruleIpv4PrefixLength < 0 || ruleIpv4PrefixLength > 32)
            throw new ArgumentOutOfRangeException(nameof(ruleIpv4PrefixLength), ruleIpv4PrefixLength, "IPv4 prefix length must be 0..32.");
        if (eaBitsLength < 0 || eaBitsLength > 48)
            throw new ArgumentOutOfRangeException(nameof(eaBitsLength), eaBitsLength, "EA-bits length must be 0..48.");
        if (psidOffset < 0 || psidOffset > 16)
            throw new ArgumentOutOfRangeException(nameof(psidOffset), psidOffset, "PSID offset must be 0..16.");

        int ipv4SuffixBits = 32 - ruleIpv4PrefixLength;
        int derivedPsidLength = eaBitsLength - ipv4SuffixBits;

        int resolvedPsidLength;
        if (psidLength.HasValue)
        {
            resolvedPsidLength = psidLength.Value;
            if (resolvedPsidLength < 0)
                throw new ArgumentOutOfRangeException(nameof(psidLength), resolvedPsidLength, "PSID length must be >= 0.");
            // When EA-bits carry the PSID (EA-bits exceed the IPv4 suffix), the explicit length must match the derivation.
            if (eaBitsLength > 0 && resolvedPsidLength != derivedPsidLength)
                throw new ArgumentException(
                    $"PSID length {resolvedPsidLength} is inconsistent with EA-bits {eaBitsLength} and IPv4 prefix /{ruleIpv4PrefixLength} (expected {derivedPsidLength}).",
                    nameof(psidLength));
        }
        else
        {
            if (derivedPsidLength < 0)
                throw new ArgumentException(
                    $"EA-bits length {eaBitsLength} is smaller than the IPv4 suffix length {ipv4SuffixBits} (32 − /{ruleIpv4PrefixLength}).",
                    nameof(eaBitsLength));
            resolvedPsidLength = derivedPsidLength;
        }

        // RFC 7597 §5.1: the PSID must fit inside the 16-bit port field at offset a.
        if (psidOffset + resolvedPsidLength > 16)
            throw new ArgumentException(
                $"PSID offset ({psidOffset}) + PSID length ({resolvedPsidLength}) must be <= 16 (RFC 7597 §5.1).",
                nameof(psidOffset));
        // The End-user IPv6 prefix (n + EA-bits) must leave room for the 64-bit Interface Identifier.
        if (ruleIpv6PrefixLength + eaBitsLength > 64)
            throw new ArgumentException(
                $"Rule IPv6 prefix length ({ruleIpv6PrefixLength}) + EA-bits ({eaBitsLength}) must be <= 64.",
                nameof(eaBitsLength));

        RuleIpv6Prefix = ruleIpv6Prefix;
        RuleIpv6PrefixLength = ruleIpv6PrefixLength;
        RuleIpv4Prefix = ruleIpv4Prefix;
        RuleIpv4PrefixLength = ruleIpv4PrefixLength;
        EaBitsLength = eaBitsLength;
        PsidOffset = psidOffset;
        PsidLength = resolvedPsidLength;
    }

    /// <summary>Rule IPv6 prefix.</summary>
    public IPAddress RuleIpv6Prefix { get; }

    /// <summary>Rule IPv6 prefix length n (bits).</summary>
    public int RuleIpv6PrefixLength { get; }

    /// <summary>Rule IPv4 prefix.</summary>
    public IPAddress RuleIpv4Prefix { get; }

    /// <summary>Rule IPv4 prefix length o (bits).</summary>
    public int RuleIpv4PrefixLength { get; }

    /// <summary>EA-bits length = (32 − o) + k (bits).</summary>
    public int EaBitsLength { get; }

    /// <summary>PSID offset a (bits from the top of the 16-bit port field).</summary>
    public int PsidOffset { get; }

    /// <summary>PSID length k (bits): derived as EA-bits − IPv4-suffix bits, or the explicit override.</summary>
    public int PsidLength { get; }

    /// <summary>Number of IPv4 suffix bits carried in EA-bits = 32 − o.</summary>
    public int Ipv4SuffixBits => 32 - RuleIpv4PrefixLength;

    /// <summary>Number of CEs sharing a single IPv4 address = 2^k.</summary>
    public int SharingRatio => 1 << PsidLength;
}
