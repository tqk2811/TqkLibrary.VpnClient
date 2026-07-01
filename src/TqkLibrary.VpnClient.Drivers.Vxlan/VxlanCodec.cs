using System;

namespace TqkLibrary.VpnClient.Drivers.Vxlan
{
    /// <summary>
    /// The VXLAN encapsulation codec (RFC 7348 §5) — pure, stateless. VXLAN carries a full Ethernet frame behind an
    /// 8-byte header over UDP (default dst port 4789). The header is:
    /// <code>
    /// byte0   = flags: the I bit (VNI valid) = 0x08; the other flag bits (R) MUST be 0 ⇒ byte0 = 0x08
    /// byte1-3 = Reserved = 0x00 0x00 0x00
    /// byte4-6 = VNI (24-bit, big-endian: byte4 = VNI[23:16], byte5 = [15:8], byte6 = [7:0])
    /// byte7   = Reserved = 0x00
    /// </code>
    /// Everything after the 8-byte header is the encapsulated Ethernet frame (14-byte L2 header + payload) verbatim.
    /// There is no control plane, keepalive, registration or encryption — the header is the whole protocol.
    /// </summary>
    public static class VxlanCodec
    {
        /// <summary>The default VXLAN destination UDP port (RFC 7348 §5, IANA-assigned).</summary>
        public const int DefaultPort = 4789;

        /// <summary>The VXLAN header length in bytes.</summary>
        public const int HeaderLength = 8;

        /// <summary>The flags byte value with the I (VNI-present) bit set and every other flag bit clear.</summary>
        public const byte FlagVniPresent = 0x08;

        /// <summary>The largest value a 24-bit VNI can hold (2^24 − 1).</summary>
        public const uint MaxVni = 0xFFFFFF;

        /// <summary>
        /// Encapsulates <paramref name="ethernetFrame"/> in a VXLAN datagram: an 8-byte header (flags 0x08, the 24-bit
        /// <paramref name="vni"/> big-endian, reserved bytes zero) followed by the frame verbatim.
        /// </summary>
        /// <exception cref="ArgumentOutOfRangeException"><paramref name="vni"/> exceeds 24 bits.</exception>
        public static byte[] EncodeVxlan(uint vni, ReadOnlySpan<byte> ethernetFrame)
        {
            if (vni > MaxVni)
                throw new ArgumentOutOfRangeException(nameof(vni), vni, "A VXLAN VNI is a 24-bit value (0..0xFFFFFF).");

            byte[] datagram = new byte[HeaderLength + ethernetFrame.Length];
            datagram[0] = FlagVniPresent;               // I bit set, all other flags 0
            // datagram[1..3] reserved = 0 (already zero-initialised)
            datagram[4] = (byte)(vni >> 16);            // VNI[23:16]
            datagram[5] = (byte)(vni >> 8);             // VNI[15:8]
            datagram[6] = (byte)vni;                    // VNI[7:0]
            // datagram[7] reserved = 0
            ethernetFrame.CopyTo(datagram.AsSpan(HeaderLength));
            return datagram;
        }

        /// <summary>
        /// Decodes a VXLAN datagram: verifies the length (≥ 8) and that the flags byte carries the I bit (0x08), then
        /// extracts the 24-bit <paramref name="vni"/> and slices out the encapsulated Ethernet <paramref name="ethernetFrame"/>
        /// (the bytes after the header). Returns false for a runt or a datagram whose flags byte lacks the I bit.
        /// </summary>
        public static bool TryDecodeVxlan(ReadOnlySpan<byte> datagram, out uint vni, out ReadOnlyMemory<byte> ethernetFrame)
        {
            vni = 0;
            ethernetFrame = default;
            if (datagram.Length < HeaderLength)
                return false;                            // too short to hold a VXLAN header
            if ((datagram[0] & FlagVniPresent) == 0)
                return false;                            // the I (VNI-present) bit is not set — not a VXLAN datagram we accept

            vni = ((uint)datagram[4] << 16) | ((uint)datagram[5] << 8) | datagram[6];
            ethernetFrame = datagram.Slice(HeaderLength).ToArray();
            return true;
        }
    }
}
