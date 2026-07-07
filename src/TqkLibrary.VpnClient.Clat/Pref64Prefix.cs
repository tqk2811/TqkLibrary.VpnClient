using System.Net;

namespace TqkLibrary.VpnClient.Clat;

/// <summary>
/// A discovered NAT64 prefix (PREF64) — the IPv6 prefix a 464XLAT CLAT (RFC 6877) embeds IPv4 destinations into
/// via RFC 6052. Produced by <see cref="Rfc8781Pref64Option"/> (RA option) or <see cref="Rfc7050WellKnownPrefix"/>
/// (DNS <c>ipv4only.arpa</c>). <paramref name="PrefixLength"/> is one of the RFC 6052 §2.2 lengths (32/40/48/56/64/96).
/// </summary>
/// <param name="Prefix">The NAT64 IPv6 prefix (only the first <paramref name="PrefixLength"/> bits are significant; the rest are zero).</param>
/// <param name="PrefixLength">Prefix length in bits — one of 32/40/48/56/64/96 (RFC 6052 §2.2).</param>
/// <param name="LifetimeSeconds">Valid lifetime in seconds (RFC 8781 Scaled Lifetime × 8); 0 for a DNS-derived prefix that carries no lifetime.</param>
public sealed record Pref64Prefix(IPAddress Prefix, int PrefixLength, int LifetimeSeconds);
