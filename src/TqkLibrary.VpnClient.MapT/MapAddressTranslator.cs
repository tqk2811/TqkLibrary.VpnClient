using System.Net;
using System.Net.Sockets;
using TqkLibrary.VpnClient.Siit.Interfaces;

namespace TqkLibrary.VpnClient.MapT;

/// <summary>
/// Address-only translator (behind SIIT's <see cref="IAddressTranslator"/>) for a MAP-T CE. The CE's own
/// (IPv4 ↔ MAP IPv6) mapping is a fixed pair precomputed from the BMR; every other address is mapped against
/// the Default Mapping Rule via RFC 6052 (reusing the SIIT <c>Rfc6052AddressMapper</c>). This is the seam that
/// lets <see cref="TqkLibrary.VpnClient.Siit.SiitTranslator"/> perform MAP-T without any MAP-specific packet code.
/// </summary>
public sealed class MapAddressTranslator : IAddressTranslator
{
    readonly MapTConfig _config;
    readonly IAddressTranslator _dmr;

    /// <summary>Creates a translator for the given MAP-T CE configuration.</summary>
    public MapAddressTranslator(MapTConfig config)
    {
        _config = config ?? throw new ArgumentNullException(nameof(config));
        _dmr = config.DmrMapper;
    }

    /// <summary>The CE's fixed MAP IPv6 address.</summary>
    public IPAddress CeMapIpv6 => _config.CeMapIpv6;

    /// <inheritdoc/>
    public bool TryTranslate4to6(IPAddress v4, out IPAddress v6)
    {
        v6 = IPAddress.IPv6None;
        if (v4 is null || v4.AddressFamily != AddressFamily.InterNetwork) return false;
        if (_config.CeIpv4.Equals(v4)) { v6 = _config.CeMapIpv6; return true; }
        return _dmr.TryTranslate4to6(v4, out v6);      // native peer → DMR-embedded IPv6 (RFC 6052)
    }

    /// <inheritdoc/>
    public bool TryTranslate6to4(IPAddress v6, out IPAddress v4)
    {
        v4 = IPAddress.None;
        if (v6 is null || v6.AddressFamily != AddressFamily.InterNetworkV6) return false;
        if (_config.CeMapIpv6.Equals(v6)) { v4 = _config.CeIpv4; return true; }
        return _dmr.TryTranslate6to4(v6, out v4);       // DMR-prefixed IPv6 → native IPv4; else false (drop)
    }
}
