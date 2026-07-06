using System;

namespace TqkLibrary.VpnClient.Drivers.Geneve
{
    /// <summary>
    /// The Geneve encapsulation codec (RFC 8926 §3) — pure, stateless. Geneve carries a payload (a full Ethernet frame
    /// when the protocol type is Transparent Ethernet Bridging) behind an 8-byte base header, optionally followed by a
    /// variable-length block of TLV options, over UDP (default dst port 6081). The base header is:
    /// <code>
    /// byte0   = Ver (2 bits, MUST be 0) | OptLen (6 bits): options length in 4-byte units
    /// byte1   = O (1 bit, OAM) | C (1 bit, critical options present) | Rsvd (6 bits, MUST be 0)
    /// byte2-3 = Protocol Type (16-bit, big-endian: 0x6558 = Transparent Ethernet Bridging, 0x0800 IPv4, 0x86DD IPv6)
    /// byte4-6 = VNI (24-bit, big-endian: byte4 = VNI[23:16], byte5 = [15:8], byte6 = [7:0])
    /// byte7   = Reserved = 0x00
    /// </code>
    /// The base header is followed by <c>OptLen * 4</c> bytes of options, each a TLV
    /// (<c>Option Class 16 | Type 8 (high bit = Critical) | Rsvd 3 | Length 5 (data length in 4-byte units) | data</c>),
    /// then the payload. There is no control plane, keepalive, registration or encryption — the header is the whole
    /// protocol. The sibling of <c>VxlanCodec</c>: VXLAN is a fixed 8-byte header with no options, Geneve adds a variable
    /// options block and an explicit protocol type.
    /// </summary>
    public static class GeneveCodec
    {
        /// <summary>The default Geneve destination UDP port (RFC 8926 §3.3, IANA-assigned).</summary>
        public const int DefaultPort = 6081;

        /// <summary>The Geneve base header length in bytes (without options).</summary>
        public const int BaseHeaderLength = 8;

        /// <summary>The length unit (in bytes) of the base-header OptLen field and of every per-option Length field.</summary>
        public const int OptionLengthUnit = 4;

        /// <summary>The minimum bytes needed to read one option's fixed header (Option Class 2 + Type 1 + Rsvd/Length 1).</summary>
        public const int OptionHeaderLength = 4;

        /// <summary>Protocol Type 0x6558 — Transparent Ethernet Bridging (the payload is a full Ethernet frame).</summary>
        public const ushort ProtocolTypeTransparentEthernet = 0x6558;

        /// <summary>Protocol Type 0x0800 — the payload is an IPv4 packet.</summary>
        public const ushort ProtocolTypeIpv4 = 0x0800;

        /// <summary>Protocol Type 0x86DD — the payload is an IPv6 packet.</summary>
        public const ushort ProtocolTypeIpv6 = 0x86DD;

        /// <summary>The high bit of an option's Type octet: when set the option is Critical (RFC 8926 §3.5).</summary>
        public const byte CriticalOptionTypeBit = 0x80;

        /// <summary>The largest value a 24-bit VNI can hold (2^24 − 1).</summary>
        public const uint MaxVni = 0xFFFFFF;

        /// <summary>
        /// Encapsulates <paramref name="payload"/> in a Geneve datagram with <b>no options</b> (OptLen 0, Ver 0, O/C clear):
        /// an 8-byte base header (the given <paramref name="protocolType"/>, the 24-bit <paramref name="vni"/> big-endian,
        /// reserved bytes zero) followed by the payload verbatim. A client in L2 mode passes
        /// <see cref="ProtocolTypeTransparentEthernet"/> and an Ethernet frame.
        /// </summary>
        /// <exception cref="ArgumentOutOfRangeException"><paramref name="vni"/> exceeds 24 bits.</exception>
        public static byte[] EncodeGeneve(uint vni, ushort protocolType, ReadOnlySpan<byte> payload)
        {
            if (vni > MaxVni)
                throw new ArgumentOutOfRangeException(nameof(vni), vni, "A Geneve VNI is a 24-bit value (0..0xFFFFFF).");

            byte[] datagram = new byte[BaseHeaderLength + payload.Length];
            datagram[0] = 0x00;                          // Ver 0, OptLen 0 (no options)
            datagram[1] = 0x00;                          // O = 0 (not OAM), C = 0 (no critical options), reserved 0
            datagram[2] = (byte)(protocolType >> 8);     // Protocol Type high byte
            datagram[3] = (byte)protocolType;            // Protocol Type low byte
            datagram[4] = (byte)(vni >> 16);             // VNI[23:16]
            datagram[5] = (byte)(vni >> 8);              // VNI[15:8]
            datagram[6] = (byte)vni;                     // VNI[7:0]
            // datagram[7] reserved = 0
            payload.CopyTo(datagram.AsSpan(BaseHeaderLength));
            return datagram;
        }

        /// <summary>
        /// Decodes a Geneve datagram: verifies the length (≥ 8) and Ver == 0, extracts the 16-bit
        /// <paramref name="protocolType"/> and the 24-bit <paramref name="vni"/>, <b>skips the options block</b> (OptLen × 4
        /// bytes) and slices out the encapsulated <paramref name="payload"/> (the bytes after the options). Returns false
        /// for a runt, an unknown version, a truncated / malformed options block, or a datagram that carries a
        /// <b>critical option</b> — because this endpoint understands no options, any critical option MUST cause the
        /// datagram to be dropped (RFC 8926 §3.5).
        /// </summary>
        public static bool TryDecodeGeneve(ReadOnlySpan<byte> datagram, out uint vni, out ushort protocolType, out ReadOnlyMemory<byte> payload)
        {
            vni = 0;
            protocolType = 0;
            payload = default;
            if (datagram.Length < BaseHeaderLength)
                return false;                            // too short to hold a Geneve base header
            if ((datagram[0] >> 6) != 0)
                return false;                            // unknown version — drop (RFC 8926 §3.1)

            int optionsLength = (datagram[0] & 0x3F) * OptionLengthUnit;
            int payloadOffset = BaseHeaderLength + optionsLength;
            if (datagram.Length < payloadOffset)
                return false;                            // options run past the end of the datagram

            protocolType = (ushort)((datagram[2] << 8) | datagram[3]);
            vni = ((uint)datagram[4] << 16) | ((uint)datagram[5] << 8) | datagram[6];

            ReadOnlySpan<byte> options = datagram.Slice(BaseHeaderLength, optionsLength);
            if (!TryScanOptions(options, out bool hasCriticalOption))
                return false;                            // a TLV runs past the options block — malformed
            if (hasCriticalOption)
                return false;                            // critical option we cannot process — drop (RFC 8926 §3.5)

            payload = datagram.Slice(payloadOffset).ToArray();
            return true;
        }

        /// <summary>
        /// Walks the TLV options block, validating each option's declared length fits and reporting whether any option
        /// has the Critical bit set. Returns false only when a TLV is truncated (its data would run past the block).
        /// </summary>
        static bool TryScanOptions(ReadOnlySpan<byte> options, out bool hasCriticalOption)
        {
            hasCriticalOption = false;
            int offset = 0;
            while (offset < options.Length)
            {
                if (offset + OptionHeaderLength > options.Length)
                    return false;                        // not enough bytes for the option's fixed header
                byte type = options[offset + 2];
                int dataLength = (options[offset + 3] & 0x1F) * OptionLengthUnit;
                int totalLength = OptionHeaderLength + dataLength;
                if (offset + totalLength > options.Length)
                    return false;                        // the option's data runs past the block
                if ((type & CriticalOptionTypeBit) != 0)
                    hasCriticalOption = true;
                offset += totalLength;
            }
            return true;
        }
    }
}
