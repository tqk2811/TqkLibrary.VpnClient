using System;
using TqkLibrary.VpnClient.IpEncap.Gre;

namespace TqkLibrary.VpnClient.Drivers.EoGre
{
    /// <summary>
    /// The EoGRE / NVGRE encapsulation codec — a thin, pure/stateless wrapper over the <b>reused</b> standard GRE codec
    /// (<see cref="GreCodec"/> in <c>TqkLibrary.VpnClient.IpEncap.Gre</c>, RFC 2784 base + RFC 2890 Key/Sequence). It does
    /// not re-implement the GRE header — it only fixes the Protocol Type to <see cref="ProtocolTypeTransparentEthernet"/>
    /// (0x6558, Transparent Ethernet Bridging) and, for NVGRE (RFC 7637), packs a 24-bit Virtual Subnet ID (VSID) plus an
    /// 8-bit FlowID into the RFC 2890 Key field.
    /// <para>
    /// A GRE-in-UDP datagram (RFC 8086) carries this GRE packet inside a UDP payload (default dst port 4754). The layout,
    /// in field order (RFC 2784 §2.1, RFC 2890 §2), is:
    /// </para>
    /// <list type="bullet">
    ///   <item>Byte 0 = <c>C R0 K S s Recur(3)</c> flags (bit 0 = Checksum present, bit 2 = Key present, bit 3 = Sequence present).</item>
    ///   <item>Byte 1 = <c>Reserved0(5) Version(3)</c> — Version must be 0.</item>
    ///   <item>Bytes 2-3 = Protocol Type = <see cref="ProtocolTypeTransparentEthernet"/> (0x6558).</item>
    ///   <item>If C: Checksum(2) + Reserved1(2).</item>
    ///   <item>If K: Key(4) — for NVGRE this is <c>VSID(24) &lt;&lt; 8 | FlowID(8)</c>.</item>
    ///   <item>If S: Sequence Number(4).</item>
    ///   <item>Then the payload = a complete Ethernet frame.</item>
    /// </list>
    /// </summary>
    public static class EoGreCodec
    {
        /// <summary>The default GRE-in-UDP destination UDP port (RFC 8086 §3.1, IANA "GRE-in-UDP"): 4754.</summary>
        public const int DefaultPort = 4754;

        /// <summary>GRE Protocol Type 0x6558 — Transparent Ethernet Bridging (the payload is a full Ethernet frame).</summary>
        public const ushort ProtocolTypeTransparentEthernet = 0x6558;

        /// <summary>The largest value a 24-bit NVGRE Virtual Subnet ID (VSID) can hold (2^24 − 1).</summary>
        public const uint MaxVsid = 0x00FFFFFF;

        /// <summary>The bit position of the VSID within the 32-bit GRE Key (RFC 7637): the low 8 bits hold the FlowID.</summary>
        public const int VsidShift = 8;

        /// <summary>
        /// Packs an NVGRE GRE Key (RFC 7637 §3.1): the 24-bit <paramref name="vsid"/> in the high 24 bits and the 8-bit
        /// <paramref name="flowId"/> in the low 8 bits (<c>VSID &lt;&lt; 8 | FlowID</c>).
        /// </summary>
        /// <exception cref="ArgumentOutOfRangeException"><paramref name="vsid"/> exceeds 24 bits.</exception>
        public static uint PackKey(uint vsid, byte flowId)
        {
            if (vsid > MaxVsid)
                throw new ArgumentOutOfRangeException(nameof(vsid), vsid, "An NVGRE VSID is a 24-bit value (0..0xFFFFFF).");
            return (vsid << VsidShift) | flowId;
        }

        /// <summary>Unpacks an NVGRE GRE Key into its 24-bit <paramref name="vsid"/> and 8-bit <paramref name="flowId"/> parts.</summary>
        public static void UnpackKey(uint key, out uint vsid, out byte flowId)
        {
            vsid = key >> VsidShift;
            flowId = (byte)(key & 0xFF);
        }

        /// <summary>
        /// Encapsulates <paramref name="ethernetFrame"/> in a GRE packet with Protocol Type 0x6558. When
        /// <paramref name="vsid"/> is non-null the K bit is set and the Key carries <c>VSID &lt;&lt; 8 | FlowID</c> (NVGRE,
        /// RFC 7637); when null no Key is emitted (plain GRETAP). <paramref name="includeChecksum"/> requests an RFC 2784
        /// Checksum (C bit); <paramref name="sequenceNumber"/>, when non-null, emits an RFC 2890 Sequence Number (S bit).
        /// </summary>
        /// <exception cref="ArgumentOutOfRangeException"><paramref name="vsid"/> exceeds 24 bits.</exception>
        public static byte[] EncodeEoGre(ReadOnlySpan<byte> ethernetFrame, uint? vsid = null, byte flowId = 0,
            bool includeChecksum = false, uint? sequenceNumber = null)
        {
            uint? key = vsid.HasValue ? PackKey(vsid.Value, flowId) : (uint?)null;
            var packet = new GrePacket
            {
                ProtocolType = ProtocolTypeTransparentEthernet,
                Key = key,
                SequenceNumber = sequenceNumber,
                IncludeChecksum = includeChecksum,
                Payload = ethernetFrame.ToArray(),
            };
            return GreCodec.Encode(packet);
        }

        /// <summary>
        /// Decodes one GRE-in-UDP datagram by delegating the whole GRE header parse to the reused <see cref="GreCodec"/>:
        /// returns false for any malformed GRE (runt, non-zero Version, a header field declared by a flag but absent, or a
        /// bad checksum when the C bit is set). On success it surfaces the <paramref name="protocolType"/> (the caller
        /// verifies it is 0x6558), the recovered Ethernet <paramref name="ethernetFrame"/>, and the optional
        /// <paramref name="key"/> (for NVGRE, unpack via <see cref="UnpackKey"/>) and <paramref name="sequenceNumber"/>.
        /// </summary>
        public static bool TryDecodeEoGre(ReadOnlySpan<byte> datagram, out ushort protocolType,
            out ReadOnlyMemory<byte> ethernetFrame, out uint? key, out uint? sequenceNumber)
        {
            protocolType = 0;
            ethernetFrame = default;
            key = null;
            sequenceNumber = null;
            if (!GreCodec.TryDecode(datagram, out GrePacket? packet) || packet is null)
                return false;
            protocolType = packet.ProtocolType;
            ethernetFrame = packet.Payload;
            key = packet.Key;
            sequenceNumber = packet.SequenceNumber;
            return true;
        }
    }
}
