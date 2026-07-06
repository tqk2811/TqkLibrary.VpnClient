using System;

namespace TqkLibrary.VpnClient.Drivers.VxlanGpe
{
    /// <summary>
    /// The VXLAN-GPE (Generic Protocol Extension, draft-ietf-nvo3-vxlan-gpe) encapsulation codec — pure, stateless.
    /// VXLAN-GPE is a superset of VXLAN (RFC 7348): the same 8-byte header + 24-bit VNI, but the flags byte gains a
    /// P (Next-Protocol-present) bit and the fourth header byte carries an explicit Next Protocol so a single UDP port
    /// (default dst 4790) can multiplex Ethernet / IPv4 / IPv6 / NSH payloads. The header is:
    /// <code>
    /// byte0   = flags: R R Ver(2) I P B O  — I (VNI present) = 0x08, P (Next-Protocol present) = 0x04,
    ///           B (BUM) = 0x02, O (OAM) = 0x01, Ver (2 bits) = (byte0 >> 4) &amp; 0x03. A client emits I|P, Ver 0 ⇒ 0x0C.
    /// byte1-2 = Reserved = 0x00 0x00
    /// byte3   = Next Protocol (0x01 IPv4, 0x02 IPv6, 0x03 Ethernet, 0x04 NSH)
    /// byte4-6 = VNI (24-bit, big-endian: byte4 = VNI[23:16], byte5 = [15:8], byte6 = [7:0])
    /// byte7   = Reserved = 0x00
    /// </code>
    /// Everything after the 8-byte header is the encapsulated payload named by <c>Next Protocol</c> (a full Ethernet frame
    /// when Next Protocol is Ethernet). There is no control plane, keepalive, registration or encryption — the header is the
    /// whole protocol. The sibling of <c>VxlanCodec</c>: VXLAN uses flags 0x08 with three reserved bytes after the flags,
    /// VXLAN-GPE sets the P bit too and replaces the first reserved byte before the VNI with the Next Protocol.
    /// </summary>
    public static class VxlanGpeHeader
    {
        /// <summary>The default VXLAN-GPE destination UDP port (draft-ietf-nvo3-vxlan-gpe, IANA-assigned).</summary>
        public const int DefaultPort = 4790;

        /// <summary>The VXLAN-GPE header length in bytes (identical to VXLAN's).</summary>
        public const int HeaderLength = 8;

        /// <summary>The flags-byte I bit — the VNI field is valid (must be set).</summary>
        public const byte FlagVniPresent = 0x08;

        /// <summary>The flags-byte P bit — the Next Protocol field is present (must be set in VXLAN-GPE).</summary>
        public const byte FlagNextProtocolPresent = 0x04;

        /// <summary>The flags-byte B bit — the frame is a Broadcast/Unknown-unicast/Multicast (BUM) replication.</summary>
        public const byte FlagBum = 0x02;

        /// <summary>The flags-byte O bit — the frame is an OAM message (its payload is not a tenant frame); such a datagram is dropped.</summary>
        public const byte FlagOam = 0x01;

        /// <summary>Next Protocol 0x01 — the payload is an IPv4 packet.</summary>
        public const byte NextProtocolIpv4 = 0x01;

        /// <summary>Next Protocol 0x02 — the payload is an IPv6 packet.</summary>
        public const byte NextProtocolIpv6 = 0x02;

        /// <summary>Next Protocol 0x03 — the payload is a full Ethernet frame (the L2 data plane).</summary>
        public const byte NextProtocolEthernet = 0x03;

        /// <summary>Next Protocol 0x04 — the payload is an NSH (Network Service Header) frame.</summary>
        public const byte NextProtocolNsh = 0x04;

        /// <summary>The largest value a 24-bit VNI can hold (2^24 − 1).</summary>
        public const uint MaxVni = 0xFFFFFF;

        /// <summary>
        /// Encapsulates <paramref name="payload"/> in a VXLAN-GPE datagram: an 8-byte header (flags I|P set = 0x0C, Ver 0,
        /// the given <paramref name="nextProtocol"/> in byte 3, the 24-bit <paramref name="vni"/> big-endian, reserved
        /// bytes zero) followed by the payload verbatim. A client in L2 mode passes <see cref="NextProtocolEthernet"/> and
        /// an Ethernet frame.
        /// </summary>
        /// <exception cref="ArgumentOutOfRangeException"><paramref name="vni"/> exceeds 24 bits.</exception>
        public static byte[] EncodeVxlanGpe(uint vni, byte nextProtocol, ReadOnlySpan<byte> payload)
        {
            if (vni > MaxVni)
                throw new ArgumentOutOfRangeException(nameof(vni), vni, "A VXLAN-GPE VNI is a 24-bit value (0..0xFFFFFF).");

            byte[] datagram = new byte[HeaderLength + payload.Length];
            datagram[0] = FlagVniPresent | FlagNextProtocolPresent; // I | P, Ver 0, all other flags 0 (0x0C)
            // datagram[1..2] reserved = 0 (already zero-initialised)
            datagram[3] = nextProtocol;                 // Next Protocol
            datagram[4] = (byte)(vni >> 16);            // VNI[23:16]
            datagram[5] = (byte)(vni >> 8);             // VNI[15:8]
            datagram[6] = (byte)vni;                    // VNI[7:0]
            // datagram[7] reserved = 0
            payload.CopyTo(datagram.AsSpan(HeaderLength));
            return datagram;
        }

        /// <summary>
        /// Decodes a VXLAN-GPE datagram: verifies the length (≥ 8), that the version is 0, that both the I (VNI-present) and
        /// P (Next-Protocol-present) bits are set, and that the O (OAM) bit is clear; then extracts the 8-bit
        /// <paramref name="nextProtocol"/>, the 24-bit <paramref name="vni"/> and slices out the encapsulated
        /// <paramref name="payload"/> (the bytes after the header). Returns false for a runt, an unknown version, a datagram
        /// missing the I or P bit, or an OAM datagram (which carries no tenant payload). The caller decides what to do with
        /// <paramref name="nextProtocol"/> — the L2 data plane accepts only <see cref="NextProtocolEthernet"/>.
        /// </summary>
        public static bool TryDecodeVxlanGpe(ReadOnlySpan<byte> datagram, out uint vni, out byte nextProtocol, out ReadOnlyMemory<byte> payload)
        {
            vni = 0;
            nextProtocol = 0;
            payload = default;
            if (datagram.Length < HeaderLength)
                return false;                            // too short to hold a VXLAN-GPE header

            byte flags = datagram[0];
            if (((flags >> 4) & 0x03) != 0)
                return false;                            // unknown version — drop (Ver must be 0)
            if ((flags & FlagVniPresent) == 0)
                return false;                            // the I (VNI-present) bit is not set
            if ((flags & FlagNextProtocolPresent) == 0)
                return false;                            // the P (Next-Protocol-present) bit is not set — not VXLAN-GPE
            if ((flags & FlagOam) != 0)
                return false;                            // OAM datagram — carries no tenant payload, drop

            nextProtocol = datagram[3];
            vni = ((uint)datagram[4] << 16) | ((uint)datagram[5] << 8) | datagram[6];
            payload = datagram.Slice(HeaderLength).ToArray();
            return true;
        }
    }
}
