using System;
using TqkLibrary.VpnClient.Drivers.Geneve;
using Xunit;

namespace TqkLibrary.VpnClient.Drivers.Geneve.Tests
{
    /// <summary>Unit tests for the pure Geneve encapsulation codec (RFC 8926 §3) — no transport, no fabric.</summary>
    public class GeneveCodecTests
    {
        // Builds a Geneve datagram by hand with one TLV option, so the decoder's option-skip / critical-bit paths can be
        // exercised without a helper in the production codec (which only ever emits OptLen 0).
        static byte[] BuildWithOption(uint vni, ushort protocolType, ushort optionClass, byte type, byte[] optionData, byte[] payload)
        {
            if (optionData.Length % GeneveCodec.OptionLengthUnit != 0)
                throw new ArgumentException("option data must be a multiple of 4 bytes", nameof(optionData));
            int optionLen = GeneveCodec.OptionHeaderLength + optionData.Length;
            int optLenUnits = optionLen / GeneveCodec.OptionLengthUnit;

            byte[] datagram = new byte[GeneveCodec.BaseHeaderLength + optionLen + payload.Length];
            datagram[0] = (byte)(optLenUnits & 0x3F);            // Ver 0, OptLen in 4-byte units
            datagram[1] = 0x00;                                  // O/C/reserved
            datagram[2] = (byte)(protocolType >> 8);
            datagram[3] = (byte)protocolType;
            datagram[4] = (byte)(vni >> 16);
            datagram[5] = (byte)(vni >> 8);
            datagram[6] = (byte)vni;
            int i = GeneveCodec.BaseHeaderLength;
            datagram[i++] = (byte)(optionClass >> 8);
            datagram[i++] = (byte)optionClass;
            datagram[i++] = type;
            datagram[i++] = (byte)((optionData.Length / GeneveCodec.OptionLengthUnit) & 0x1F); // Length in 4-byte units
            Array.Copy(optionData, 0, datagram, i, optionData.Length);
            i += optionData.Length;
            Array.Copy(payload, 0, datagram, i, payload.Length);
            return datagram;
        }

        [Fact]
        public void Encode_ThenDecode_RoundTripsVniProtocolTypeAndFrame()
        {
            uint vni = 0x123456;
            byte[] frame = new byte[20];
            for (int i = 0; i < frame.Length; i++) frame[i] = (byte)(i + 1);

            byte[] datagram = GeneveCodec.EncodeGeneve(vni, GeneveCodec.ProtocolTypeTransparentEthernet, frame);

            Assert.Equal(GeneveCodec.BaseHeaderLength + frame.Length, datagram.Length);
            Assert.True(GeneveCodec.TryDecodeGeneve(datagram, out uint decodedVni, out ushort protocolType, out ReadOnlyMemory<byte> decodedFrame));
            Assert.Equal(vni, decodedVni);
            Assert.Equal(GeneveCodec.ProtocolTypeTransparentEthernet, protocolType);
            Assert.Equal(frame, decodedFrame.ToArray());
        }

        [Fact]
        public void Encode_ProducesRfc8926BaseHeader_VerOptLenProtocolTypeAndBigEndianVni()
        {
            byte[] datagram = GeneveCodec.EncodeGeneve(0x123456, GeneveCodec.ProtocolTypeTransparentEthernet, new byte[14]);

            Assert.Equal(0x00, datagram[0]);          // Ver 0, OptLen 0 (no options)
            Assert.Equal(0x00, datagram[1]);          // O = 0, C = 0, reserved 0
            Assert.Equal(0x65, datagram[2]);          // Protocol Type 0x6558 high byte
            Assert.Equal(0x58, datagram[3]);          // Protocol Type low byte
            Assert.Equal(0x12, datagram[4]);          // VNI[23:16] big-endian
            Assert.Equal(0x34, datagram[5]);          // VNI[15:8]
            Assert.Equal(0x56, datagram[6]);          // VNI[7:0]
            Assert.Equal(0x00, datagram[7]);          // reserved
        }

        [Theory]
        [InlineData((ushort)0x6558)]                  // Transparent Ethernet Bridging
        [InlineData((ushort)0x0800)]                  // IPv4
        [InlineData((ushort)0x86DD)]                  // IPv6
        public void Decode_PreservesProtocolType(ushort protocolType)
        {
            byte[] datagram = GeneveCodec.EncodeGeneve(0x00ABCD, protocolType, new byte[8]);
            Assert.True(GeneveCodec.TryDecodeGeneve(datagram, out _, out ushort decoded, out _));
            Assert.Equal(protocolType, decoded);
        }

        [Fact]
        public void Decode_Rejects_RuntShorterThanBaseHeader()
        {
            Assert.False(GeneveCodec.TryDecodeGeneve(new byte[7], out _, out _, out _));
        }

        [Fact]
        public void Decode_Rejects_UnknownVersion()
        {
            byte[] datagram = GeneveCodec.EncodeGeneve(0x000001, GeneveCodec.ProtocolTypeTransparentEthernet, new byte[14]);
            datagram[0] = 0x40;                        // Ver = 1 (top two bits), OptLen 0
            Assert.False(GeneveCodec.TryDecodeGeneve(datagram, out _, out _, out _));
        }

        [Fact]
        public void Decode_AcceptsHeaderOnly_ReturnsEmptyPayload()
        {
            byte[] datagram = GeneveCodec.EncodeGeneve(0x00ABCD, GeneveCodec.ProtocolTypeTransparentEthernet, ReadOnlySpan<byte>.Empty);
            Assert.True(GeneveCodec.TryDecodeGeneve(datagram, out uint vni, out _, out ReadOnlyMemory<byte> payload));
            Assert.Equal(0x00ABCDu, vni);
            Assert.Equal(0, payload.Length);
        }

        [Fact]
        public void Decode_SkipsNonCriticalOption_ByOptLen_AndReturnsPayload()
        {
            byte[] payload = { 0xAA, 0xBB, 0xCC, 0xDD };
            byte[] optionData = { 0x01, 0x02, 0x03, 0x04 };
            // type 0x21: high bit clear ⇒ non-critical.
            byte[] datagram = BuildWithOption(0x0F0F0F, GeneveCodec.ProtocolTypeTransparentEthernet, 0x0102, 0x21, optionData, payload);

            Assert.True(GeneveCodec.TryDecodeGeneve(datagram, out uint vni, out ushort protocolType, out ReadOnlyMemory<byte> decoded));
            Assert.Equal(0x0F0F0Fu, vni);
            Assert.Equal(GeneveCodec.ProtocolTypeTransparentEthernet, protocolType);
            Assert.Equal(payload, decoded.ToArray());   // options skipped by OptLen, payload recovered verbatim
        }

        [Fact]
        public void Decode_Drops_WhenCriticalOptionPresent()
        {
            byte[] payload = { 0xAA, 0xBB, 0xCC, 0xDD };
            byte[] optionData = { 0x01, 0x02, 0x03, 0x04 };
            // type 0x80: Critical bit set ⇒ an endpoint that cannot process it MUST drop the datagram (RFC 8926 §3.5).
            byte[] datagram = BuildWithOption(0x0F0F0F, GeneveCodec.ProtocolTypeTransparentEthernet, 0x0102, 0x80, optionData, payload);

            Assert.False(GeneveCodec.TryDecodeGeneve(datagram, out _, out _, out _));
        }

        [Fact]
        public void Decode_Rejects_TruncatedOptions()
        {
            // OptLen claims 2 units (8 bytes of options) but the datagram only carries the base header.
            byte[] datagram = new byte[GeneveCodec.BaseHeaderLength];
            datagram[0] = 0x02;                        // Ver 0, OptLen 2 ⇒ 8 bytes of options that are not present
            Assert.False(GeneveCodec.TryDecodeGeneve(datagram, out _, out _, out _));
        }

        [Fact]
        public void Encode_Throws_WhenVniExceeds24Bits()
        {
            Assert.Throws<ArgumentOutOfRangeException>(
                () => GeneveCodec.EncodeGeneve(0x1000000, GeneveCodec.ProtocolTypeTransparentEthernet, new byte[14]));
        }

        [Fact]
        public void Constants_MatchRfc8926()
        {
            Assert.Equal(6081, GeneveCodec.DefaultPort);
            Assert.Equal(8, GeneveCodec.BaseHeaderLength);
            Assert.Equal(4, GeneveCodec.OptionLengthUnit);
            Assert.Equal(0x6558, GeneveCodec.ProtocolTypeTransparentEthernet);
            Assert.Equal(0x80, GeneveCodec.CriticalOptionTypeBit);
            Assert.Equal(0xFFFFFFu, GeneveCodec.MaxVni);
        }
    }
}
