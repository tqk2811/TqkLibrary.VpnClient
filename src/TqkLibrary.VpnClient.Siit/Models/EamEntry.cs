using System.Net;

namespace TqkLibrary.VpnClient.Siit.Models;

/// <summary>
/// One Explicit Address Mapping entry (RFC 7757 §3.1): an IPv4 prefix bound to an IPv6 prefix. During translation
/// the prefix is swapped and the remaining suffix bits are copied. Validated when added to an <see cref="ExplicitAddressMap"/>.
/// </summary>
/// <param name="Ipv4Prefix">The IPv4 prefix address (only the first <paramref name="Ipv4PrefixLength"/> bits are significant).</param>
/// <param name="Ipv4PrefixLength">IPv4 prefix length in bits (0..32).</param>
/// <param name="Ipv6Prefix">The IPv6 prefix address (only the first <paramref name="Ipv6PrefixLength"/> bits are significant).</param>
/// <param name="Ipv6PrefixLength">IPv6 prefix length in bits (0..128).</param>
public sealed record EamEntry(IPAddress Ipv4Prefix, int Ipv4PrefixLength, IPAddress Ipv6Prefix, int Ipv6PrefixLength);
