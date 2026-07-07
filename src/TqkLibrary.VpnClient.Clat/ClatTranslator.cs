using System.Net;
using TqkLibrary.VpnClient.Siit;
using TqkLibrary.VpnClient.Siit.Enums;

namespace TqkLibrary.VpnClient.Clat;

/// <summary>
/// 464XLAT CLAT (RFC 6877) customer-side translator — a thin entry point that wraps a <see cref="SiitTranslator"/>
/// driven by the CLAT address translator (EAM device source + RFC 6052 NAT64 destination). All IPv4↔IPv6 header
/// work (checksum fix-up, ICMP↔ICMPv6, fragment handling, safe drops) is done by the reused SIIT engine; CLAT only
/// contributes the address mapping through the <c>IAddressTranslator</c> seam. Client-only — the PLAT/NAT64 server
/// side is out of scope. Not thread-safe: one instance per translating flow (mirrors <see cref="SiitTranslator"/>'s
/// per-instance <see cref="LastDropReason"/>).
/// </summary>
public sealed class ClatTranslator
{
    readonly SiitTranslator _siit;

    /// <summary>Creates a translator from a CLAT configuration.</summary>
    public ClatTranslator(ClatConfig config, Action<SiitDropReason>? onDrop = null)
    {
        if (config is null) throw new ArgumentNullException(nameof(config));
        _siit = new SiitTranslator(config.CreateAddressTranslator(), onDrop);
    }

    /// <summary>Reason the most recent translation returned <c>null</c> (or <see cref="SiitDropReason.None"/> on success).</summary>
    public SiitDropReason LastDropReason => _siit.LastDropReason;

    /// <summary>Translates a device IPv4 packet to IPv6 (device→NAT64 direction). Returns <c>null</c> on a safe drop.</summary>
    public byte[]? Translate4to6(ReadOnlySpan<byte> packet) => _siit.Translate4to6(packet);

    /// <summary>Translates an inbound IPv6 packet back to IPv4 (NAT64→device direction). Returns <c>null</c> on a safe drop.</summary>
    public byte[]? Translate6to4(ReadOnlySpan<byte> packet) => _siit.Translate6to4(packet);

    /// <summary>
    /// Builds a CLAT translator whose NAT64 prefix was discovered via RFC 8781 (RA option) or RFC 7050
    /// (<c>ipv4only.arpa</c>), rather than statically configured.
    /// </summary>
    public static ClatTranslator FromDiscoveredPrefix(
        Pref64Prefix nat64,
        IPAddress deviceIpv4,
        IPAddress clatIpv6Prefix,
        Action<SiitDropReason>? onDrop = null)
        => new ClatTranslator(ClatConfig.FromDiscoveredPrefix(nat64, deviceIpv4, clatIpv6Prefix), onDrop);
}
