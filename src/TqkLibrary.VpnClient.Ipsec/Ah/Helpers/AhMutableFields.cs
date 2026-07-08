namespace TqkLibrary.VpnClient.Ipsec.Ah.Helpers
{
    /// <summary>
    /// Zeroes the IP-header fields that RFC 4302 §3.3.3.1 classifies as <b>mutable</b> (may change in transit) before the
    /// AH Integrity Check Value is computed or verified. These helpers must operate on a <b>copy</b> of the packet used
    /// only for the ICV computation — the datagram actually put on the wire keeps its real TTL / checksum / etc.
    /// <para>
    /// Immutable fields are left as-is so both peers hash the same bytes; mutable fields are treated as zero because a
    /// router legitimately rewrites them (TTL decrement, ECN, fragmentation, checksum) without invalidating the ICV.
    /// </para>
    /// </summary>
    public static class AhMutableFields
    {
        /// <summary>
        /// Zeroes the mutable fields of a 20-byte IPv4 header (RFC 4302 §3.3.3.1.1.1): <b>byte 1</b> (DSCP + ECN / Type
        /// of Service), <b>bytes 6–7</b> (Flags + Fragment Offset), <b>byte 8</b> (TTL) and <b>bytes 10–11</b> (Header
        /// Checksum). Version+IHL, Total Length, Identification, Protocol and the source/destination addresses are
        /// immutable and left untouched. Only IHL=5 (no options) is handled here — IPv4 options (§3.3.3.1.1.2) are not
        /// supported, so this must be called on a header without options.
        /// </summary>
        public static void ZeroMutableIpv4(Span<byte> ipHeader)
        {
            ipHeader[1] = 0;  // DSCP + ECN (legacy Type of Service)
            ipHeader[6] = 0;  // Flags (3 bits) + Fragment Offset high bits
            ipHeader[7] = 0;  // Fragment Offset low bits
            ipHeader[8] = 0;  // Time To Live
            ipHeader[10] = 0; // Header Checksum high byte
            ipHeader[11] = 0; // Header Checksum low byte
        }

        /// <summary>
        /// Zeroes the mutable fields of a 40-byte IPv6 base header (RFC 4302 §3.3.3.1.2): the <b>Traffic Class</b>
        /// (DSCP + ECN) and <b>Flow Label</b> — i.e. the low 28 bits of the first 4 bytes, keeping only the 4-bit
        /// Version — plus the <b>Hop Limit</b> (byte 7). Payload Length, Next Header and the source/destination
        /// addresses are immutable and left untouched. IPv6 extension headers (§3.3.3.1.2.1) are not handled — only the
        /// fixed base header is zeroed.
        /// </summary>
        public static void ZeroMutableIpv6(Span<byte> ipHeader)
        {
            ipHeader[0] &= 0xF0; // keep the 4-bit Version, zero the Traffic Class high nibble
            ipHeader[1] = 0;     // Traffic Class low nibble + Flow Label high bits
            ipHeader[2] = 0;     // Flow Label
            ipHeader[3] = 0;     // Flow Label
            ipHeader[7] = 0;     // Hop Limit
        }
    }
}
