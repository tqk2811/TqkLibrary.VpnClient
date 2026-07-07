using System.Net;
using TqkLibrary.VpnClient.Siit;

namespace TqkLibrary.VpnClient.Clat;

/// <summary>
/// Extracts a NAT64 prefix from an AAAA record returned for the well-known name <c>ipv4only.arpa</c> (RFC 7050).
/// A NAT64/DNS64 server synthesises AAAA records that embed the well-known IPv4 addresses <c>192.0.0.170</c> /
/// <c>192.0.0.171</c> into its NAT64 prefix per RFC 6052; scanning the six valid RFC 6052 §2.2 embedding positions
/// recovers the prefix and its length. This is the <b>offline parser only</b> — issuing the real DNS query is a
/// separate (live) concern. Reuses <see cref="Rfc6052AddressMapper"/> for the byte layout instead of re-deriving it.
/// </summary>
public static class Rfc7050WellKnownPrefix
{
    /// <summary>The RFC 7050 §3 well-known IPv4 addresses embedded in the synthesised <c>ipv4only.arpa</c> AAAA records.</summary>
    static readonly byte[][] WellKnownIpv4 =
    {
        new byte[] { 0xC0, 0x00, 0x00, 0xAA }, // 192.0.0.170
        new byte[] { 0xC0, 0x00, 0x00, 0xAB }, // 192.0.0.171
    };

    // RFC 6052 §2.2 allowed prefix lengths, ordered longest-first so a /96 embedding is preferred when ambiguous.
    static readonly int[] AllowedLengths = { 96, 64, 56, 48, 40, 32 };

    /// <summary>
    /// Scans a 16-byte AAAA address for a well-known IPv4 (<c>192.0.0.170</c>/<c>192.0.0.171</c>) at one of the RFC 6052
    /// embedding positions and, on success, yields the NAT64 <paramref name="prefix"/> and <paramref name="prefixLength"/>.
    /// Returns false if the address is not 16 bytes or embeds no well-known IPv4.
    /// </summary>
    public static bool TryExtractNat64Prefix(ReadOnlySpan<byte> aaaaAddress, out IPAddress prefix, out int prefixLength)
    {
        prefix = IPAddress.IPv6None;
        prefixLength = 0;
        if (aaaaAddress.Length != 16) return false;

        byte[] addr = aaaaAddress.ToArray();
        var address = new IPAddress(addr);

        foreach (int len in AllowedLengths)
        {
            // Use the first len bits of the AAAA as the candidate prefix so the RFC 6052 prefix-match always passes;
            // the mapper then validates the u-octet and pulls out the embedded IPv4 at the right positions.
            byte[] prefixBytes = new byte[16];
            Array.Copy(addr, 0, prefixBytes, 0, len / 8);
            var candidatePrefix = new IPAddress(prefixBytes);

            var mapper = new Rfc6052AddressMapper(candidatePrefix, len);
            if (!mapper.TryTranslate6to4(address, out var v4)) continue;

            byte[] v4Bytes = v4.GetAddressBytes();
            if (IsWellKnown(v4Bytes))
            {
                prefix = candidatePrefix;
                prefixLength = len;
                return true;
            }
        }
        return false;
    }

    static bool IsWellKnown(byte[] v4)
    {
        foreach (byte[] wk in WellKnownIpv4)
            if (v4[0] == wk[0] && v4[1] == wk[1] && v4[2] == wk[2] && v4[3] == wk[3])
                return true;
        return false;
    }
}
