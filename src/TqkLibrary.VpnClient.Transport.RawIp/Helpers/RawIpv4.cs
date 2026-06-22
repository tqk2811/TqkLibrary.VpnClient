using System.Net;

namespace TqkLibrary.VpnClient.Transport.RawIp.Helpers
{
    /// <summary>
    /// Pure IPv4 header helpers for the raw-IP receive path. A raw IPv4 socket delivers each inbound datagram with its
    /// 20-to-60-byte IPv4 header still attached (both Windows and Linux), so the transport must locate the protocol
    /// payload (e.g. the ESP packet), reject malformed/truncated headers, and drop IP fragments — which a raw socket
    /// surfaces un-reassembled. Send adds no header (the OS does) and IPv6 raw delivers no header, so this is receive-only/v4-only.
    /// </summary>
    public static class RawIpv4
    {
        /// <summary>Minimum IPv4 header length in bytes (no options).</summary>
        public const int MinHeaderLength = 20;

        /// <summary>
        /// Returns the byte offset of the protocol payload (IHL × 4), or -1 if <paramref name="datagram"/> is not a
        /// well-formed, complete IPv4 header: version ≠ 4, IHL &lt; 5, or the datagram shorter than its own header.
        /// </summary>
        public static int PayloadOffset(ReadOnlySpan<byte> datagram)
        {
            if (datagram.Length < MinHeaderLength) return -1;
            int version = datagram[0] >> 4;
            if (version != 4) return -1;
            int ihl = (datagram[0] & 0x0F) * 4;
            if (ihl < MinHeaderLength || datagram.Length < ihl) return -1;
            return ihl;
        }

        /// <summary>The IP protocol number from the header (byte 9), or -1 if the header is too short.</summary>
        public static int Protocol(ReadOnlySpan<byte> datagram)
            => datagram.Length >= MinHeaderLength ? datagram[9] : -1;

        /// <summary>
        /// True if the datagram is an IPv4 fragment — the More-Fragments flag is set or the fragment offset is non-zero
        /// (RFC 791). A raw socket may surface fragments un-reassembled; the protocol payload of a fragment is incomplete.
        /// </summary>
        public static bool IsFragment(ReadOnlySpan<byte> datagram)
        {
            if (datagram.Length < MinHeaderLength) return false;
            // Bytes 6-7: 3 flag bits + 13-bit fragment offset. MF = 0x2000, offset mask = 0x1FFF.
            int flagsAndOffset = (datagram[6] << 8) | datagram[7];
            return (flagsAndOffset & 0x2000) != 0 || (flagsAndOffset & 0x1FFF) != 0;
        }

        /// <summary>The source IPv4 address from the header (bytes 12-15), or null if the header is too short.</summary>
        public static IPAddress? SourceAddress(ReadOnlySpan<byte> datagram)
        {
            if (datagram.Length < MinHeaderLength) return null;
#if NET6_0_OR_GREATER
            return new IPAddress(datagram.Slice(12, 4));
#else
            return new IPAddress(datagram.Slice(12, 4).ToArray());
#endif
        }
    }
}
