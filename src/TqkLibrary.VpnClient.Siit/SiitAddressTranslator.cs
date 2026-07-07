using System.Net;
using TqkLibrary.VpnClient.Siit.Interfaces;

namespace TqkLibrary.VpnClient.Siit;

/// <summary>
/// Composite <see cref="IAddressTranslator"/> that tries an ordered chain of translators and returns the first match.
/// The RFC 7757 recommended order is EAM first, then RFC 6052 embedding as fallback:
/// <c>new SiitAddressTranslator(eam, rfc6052)</c>.
/// </summary>
public sealed class SiitAddressTranslator : IAddressTranslator
{
    readonly IAddressTranslator[] _chain;

    /// <summary>Builds a translator that consults <paramref name="translators"/> in order (e.g. EAM then RFC 6052).</summary>
    public SiitAddressTranslator(params IAddressTranslator[] translators)
    {
        if (translators is null) throw new ArgumentNullException(nameof(translators));
        if (translators.Length == 0) throw new ArgumentException("At least one translator is required.", nameof(translators));
        _chain = (IAddressTranslator[])translators.Clone();
    }

    /// <inheritdoc/>
    public bool TryTranslate4to6(IPAddress v4, out IPAddress v6)
    {
        foreach (var t in _chain)
            if (t.TryTranslate4to6(v4, out v6)) return true;
        v6 = IPAddress.IPv6None;
        return false;
    }

    /// <inheritdoc/>
    public bool TryTranslate6to4(IPAddress v6, out IPAddress v4)
    {
        foreach (var t in _chain)
            if (t.TryTranslate6to4(v6, out v4)) return true;
        v4 = IPAddress.None;
        return false;
    }
}
