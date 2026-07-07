using System.Net;

namespace TqkLibrary.VpnClient.Siit.Interfaces;

/// <summary>
/// Bidirectional stateless IPv4↔IPv6 address translator used by the SIIT engine (RFC 7915).
/// Implementations map a single address between the two families; a composite may chain several
/// strategies (e.g. RFC 7757 EAM first, then RFC 6052 embedding as fallback).
/// </summary>
public interface IAddressTranslator
{
    /// <summary>Translates an IPv4 address to IPv6. Returns false (and leaves <paramref name="v6"/> unspecified) if it cannot be mapped.</summary>
    bool TryTranslate4to6(IPAddress v4, out IPAddress v6);

    /// <summary>Translates an IPv6 address to IPv4. Returns false (and leaves <paramref name="v4"/> unspecified) if it cannot be mapped.</summary>
    bool TryTranslate6to4(IPAddress v6, out IPAddress v4);
}
