using System.Net;
using TqkLibrary.VpnClient.Abstractions.Net;

namespace TqkLibrary.VpnClient.Siit.Helpers;

/// <summary>
/// Transport-checksum fix-ups for SIIT header translation. Because the IPv4 and IPv6 pseudo-headers only differ
/// in the address fields (protocol and upper-layer length contribute the same 16-bit sum), the TCP/UDP checksum
/// can be updated incrementally (RFC 1624) from just the address change — which also works for the first fragment
/// where the whole segment is not available. When the whole datagram is present the checksum can be recomputed.
/// Pure/stateless; builds on <see cref="InternetChecksum"/>.
/// </summary>
public static class SiitChecksum
{
    /// <summary>
    /// RFC 1624 incremental update of a transport checksum when only the pseudo-header addresses change.
    /// Removes the 16-bit words of <paramref name="oldAddresses"/> and adds those of <paramref name="newAddresses"/>
    /// to the ones-complement sum that produced <paramref name="oldChecksum"/>.
    /// </summary>
    public static ushort AdjustForAddressChange(ushort oldChecksum, ReadOnlySpan<byte> oldAddresses, ReadOnlySpan<byte> newAddresses)
    {
        // The folded ones-complement sum that produced the old checksum is ~oldChecksum.
        uint sum = (ushort)~oldChecksum;

        // Subtract each old address word = add its 16-bit ones-complement.
        for (int i = 0; i + 1 < oldAddresses.Length; i += 2)
        {
            ushort word = (ushort)((oldAddresses[i] << 8) | oldAddresses[i + 1]);
            sum += (ushort)~word;
        }

        // Add each new address word.
        for (int i = 0; i + 1 < newAddresses.Length; i += 2)
            sum += (uint)((newAddresses[i] << 8) | newAddresses[i + 1]);

        return InternetChecksum.Finish(sum);
    }

    /// <summary>
    /// Recomputes a TCP/UDP checksum over the whole <paramref name="segment"/> (its checksum field must already be
    /// zeroed by the caller) using a fresh pseudo-header for <paramref name="source"/>/<paramref name="destination"/>.
    /// </summary>
    public static ushort ComputeTransport(IPAddress source, IPAddress destination, byte protocol, ReadOnlySpan<byte> segment)
    {
        uint sum = InternetChecksum.PseudoHeaderSum(source, destination, protocol, segment.Length);
        sum = InternetChecksum.AddData(sum, segment);
        return InternetChecksum.Finish(sum);
    }
}
