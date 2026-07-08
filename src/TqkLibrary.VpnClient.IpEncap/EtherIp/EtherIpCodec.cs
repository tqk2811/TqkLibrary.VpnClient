using System;

namespace TqkLibrary.VpnClient.IpEncap.EtherIp
{
    /// <summary>
    /// Stateless codec for EtherIP (RFC 3378) — Ethernet-in-IP, IP protocol 97. EtherIP prepends a fixed 2-byte header to a
    /// complete Ethernet frame and carries the result natively over IP, building an L2-over-IP bridge. Unlike GRE there are
    /// no optional fields: the whole header is <c>Version(4 bits)=3</c> in the high nibble of byte 0 plus 12 Reserved bits
    /// (the low nibble of byte 0 and all of byte 1) that a compliant sender leaves zero — so a well-formed header is exactly
    /// <c>0x30 0x00</c> followed by the Ethernet frame (dst MAC ‖ src MAC ‖ EtherType ‖ payload).
    /// <para>
    /// Header layout (RFC 3378 §2):
    /// </para>
    /// <list type="bullet">
    ///   <item>Byte 0 high nibble = Version, MUST be 3.</item>
    ///   <item>Byte 0 low nibble + Byte 1 = 12 Reserved bits, SHOULD be 0.</item>
    ///   <item>Then the encapsulated Ethernet frame.</item>
    /// </list>
    /// <para>
    /// This codec owns only the EtherIP header + Ethernet-frame passthrough. Wrapping/stripping the outer IP header and
    /// sending it over a raw-IP proto-97 pipe is the transport layer's job (see <see cref="EtherIpTunnelChannel"/>).
    /// </para>
    /// </summary>
    public static class EtherIpCodec
    {
        /// <summary>The IANA IP protocol number carrying EtherIP natively over IP (RFC 3378) — 97.</summary>
        public const int ProtocolNumber = 97;

        /// <summary>The fixed EtherIP header length in bytes: <c>Version(4) + Reserved(12)</c> = 2 bytes.</summary>
        public const int HeaderSize = 2;

        /// <summary>The EtherIP version (RFC 3378 §2), carried in the high nibble of byte 0. MUST be 3.</summary>
        public const int Version = 3;

        /// <summary>Byte 0 of a compliant header: Version 3 in the high nibble, Reserved 0 in the low nibble.</summary>
        public const byte VersionByte = 0x30;

        /// <summary>
        /// The minimum size of a full Ethernet II frame — its 14-byte header (6 dst MAC + 6 src MAC + 2 EtherType) with an
        /// empty payload. A decapsulated payload shorter than this cannot be a valid Ethernet frame, so it is rejected.
        /// </summary>
        public const int EthernetHeaderLength = 14;

        /// <summary>
        /// Encapsulates <paramref name="ethernetFrame"/> into a fresh EtherIP datagram: the 2-byte header <c>0x30 0x00</c>
        /// (Version 3, Reserved 0) followed by the frame verbatim. The returned buffer is the IP payload for proto-97.
        /// </summary>
        public static byte[] Encapsulate(ReadOnlySpan<byte> ethernetFrame)
        {
            byte[] packet = new byte[HeaderSize + ethernetFrame.Length];
            packet[0] = VersionByte; // Version = 3 (high nibble), Reserved = 0 (low nibble)
            packet[1] = 0x00;        // Reserved (bits 8..15)
            ethernetFrame.CopyTo(packet.AsSpan(HeaderSize));
            return packet;
        }

        /// <summary>
        /// Decapsulates one EtherIP datagram. Returns <c>false</c> (with a null <paramref name="ethernetFrame"/>) when the
        /// buffer is too short for the 2-byte header, when the Version nibble is not 3, or when the recovered payload is
        /// shorter than a full Ethernet II header (<see cref="EthernetHeaderLength"/> bytes). The 12 Reserved bits are
        /// accepted-and-ignored — some implementations do not zero them — so a non-zero Reserved value does not drop the
        /// packet (mirroring the GRE codec's Reserved0 leniency); only the Version is significant.
        /// </summary>
        public static bool TryDecapsulate(ReadOnlySpan<byte> etheripPacket, out byte[] ethernetFrame)
        {
            ethernetFrame = Array.Empty<byte>();
            if (etheripPacket.Length < HeaderSize) return false;          // no room for the fixed EtherIP header

            int version = etheripPacket[0] >> 4;                          // high nibble of byte 0
            if (version != Version) return false;                         // RFC 3378: version MUST be 3
            // The low nibble of byte 0 + byte 1 are the 12 Reserved bits — accepted and ignored (lenient interop).

            ReadOnlySpan<byte> frame = etheripPacket.Slice(HeaderSize);
            if (frame.Length < EthernetHeaderLength) return false;        // not a full Ethernet II frame

            ethernetFrame = frame.ToArray();
            return true;
        }
    }
}
