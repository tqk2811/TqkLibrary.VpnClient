using TqkLibrary.VpnClient.Siit;
using TqkLibrary.VpnClient.Siit.Enums;

namespace TqkLibrary.VpnClient.MapT;

/// <summary>
/// MAP-T (RFC 7599) double stateless translation — a thin entry point that wraps a <see cref="SiitTranslator"/>
/// driven by a <see cref="MapAddressTranslator"/>. All IPv4↔IPv6 header work (checksum fix-up, ICMP↔ICMPv6,
/// fragment handling, safe drops) is done by the reused SIIT engine; MAP-T only contributes the address
/// algorithm through the <c>IAddressTranslator</c> seam. Not thread-safe — one instance per translating flow
/// (mirrors <see cref="SiitTranslator"/>'s per-instance <see cref="LastDropReason"/>).
/// </summary>
public sealed class MapTTranslator
{
    readonly SiitTranslator _siit;

    /// <summary>Creates a translator from a MAP-T CE configuration.</summary>
    public MapTTranslator(MapTConfig config, Action<SiitDropReason>? onDrop = null)
        : this(new MapAddressTranslator(config ?? throw new ArgumentNullException(nameof(config))), onDrop) { }

    /// <summary>Creates a translator from an explicit MAP address translator.</summary>
    public MapTTranslator(MapAddressTranslator addressTranslator, Action<SiitDropReason>? onDrop = null)
    {
        if (addressTranslator is null) throw new ArgumentNullException(nameof(addressTranslator));
        _siit = new SiitTranslator(addressTranslator, onDrop);
    }

    /// <summary>Reason the most recent translation returned <c>null</c> (or <see cref="SiitDropReason.None"/> on success).</summary>
    public SiitDropReason LastDropReason => _siit.LastDropReason;

    /// <summary>Translates a CE IPv4 packet to IPv6 (CE→BR direction). Returns <c>null</c> on a safe drop.</summary>
    public byte[]? Translate4to6(ReadOnlySpan<byte> packet) => _siit.Translate4to6(packet);

    /// <summary>Translates an IPv6 packet back to IPv4 (BR→CE direction). Returns <c>null</c> on a safe drop.</summary>
    public byte[]? Translate6to4(ReadOnlySpan<byte> packet) => _siit.Translate6to4(packet);
}
