using System;
using TqkLibrary.VpnClient.Drivers.EoGre;
using Xunit;

namespace TqkLibrary.VpnClient.Drivers.EoGre.Tests
{
    /// <summary>
    /// Unit tests for the pure EoGRE / NVGRE codec (a thin wrapper over the reused RFC 2784/2890 GRE codec) — no transport,
    /// no fabric.
    /// </summary>
    public class EoGreCodecTests
    {
        const byte BitChecksum = 0x80;   // GRE byte 0, C
        const byte BitKey = 0x20;        // GRE byte 0, K
        const byte BitSequence = 0x10;   // GRE byte 0, S

        static byte[] SampleFrame(int length = 20)
        {
            byte[] frame = new byte[length];
            for (int i = 0; i < frame.Length; i++) frame[i] = (byte)(i + 1);
            return frame;
        }

        [Fact]
        public void Encode_ThenDecode_RoundTripsProtocolTypeAndFrame_NoKey()
        {
            byte[] frame = SampleFrame();

            byte[] datagram = EoGreCodec.EncodeEoGre(frame);

            Assert.True(EoGreCodec.TryDecodeEoGre(datagram, out ushort protocolType, out ReadOnlyMemory<byte> decoded, out uint? key, out uint? seq));
            Assert.Equal(EoGreCodec.ProtocolTypeTransparentEthernet, protocolType);
            Assert.Equal(frame, decoded.ToArray());
            Assert.Null(key);
            Assert.Null(seq);
        }

        [Fact]
        public void Encode_ProducesGreHeader_VerZeroProtocolType0x6558_NoFlags()
        {
            byte[] datagram = EoGreCodec.EncodeEoGre(SampleFrame(14));

            Assert.Equal(0x00, datagram[0]);          // no C/K/S flags
            Assert.Equal(0x00, datagram[1]);          // Reserved0 = 0, Version = 0
            Assert.Equal(0x65, datagram[2]);          // Protocol Type 0x6558 high byte
            Assert.Equal(0x58, datagram[3]);          // Protocol Type low byte
        }

        [Fact]
        public void Encode_WithVsid_SetsKeyBit_AndPacksVsidFlowIdIntoKey()
        {
            uint vsid = 0x123456;
            byte flowId = 0x9A;
            byte[] frame = SampleFrame();

            byte[] datagram = EoGreCodec.EncodeEoGre(frame, vsid, flowId);

            Assert.Equal(BitKey, datagram[0] & BitKey);   // K bit set
            Assert.True(EoGreCodec.TryDecodeEoGre(datagram, out ushort protocolType, out ReadOnlyMemory<byte> decoded, out uint? key, out _));
            Assert.Equal(EoGreCodec.ProtocolTypeTransparentEthernet, protocolType);
            Assert.Equal(frame, decoded.ToArray());
            Assert.True(key.HasValue);
            Assert.Equal((vsid << 8) | flowId, key!.Value);
            EoGreCodec.UnpackKey(key.Value, out uint decodedVsid, out byte decodedFlow);
            Assert.Equal(vsid, decodedVsid);
            Assert.Equal(flowId, decodedFlow);
        }

        [Theory]
        [InlineData(0x000000u, (byte)0x00)]
        [InlineData(0xFFFFFFu, (byte)0xFF)]
        [InlineData(0x0ABCDEu, (byte)0x42)]
        public void PackKey_UnpackKey_RoundTripsVsid24BitAndFlowId(uint vsid, byte flowId)
        {
            uint key = EoGreCodec.PackKey(vsid, flowId);
            EoGreCodec.UnpackKey(key, out uint decodedVsid, out byte decodedFlow);
            Assert.Equal(vsid, decodedVsid);
            Assert.Equal(flowId, decodedFlow);
        }

        [Fact]
        public void PackKey_Throws_WhenVsidExceeds24Bits()
        {
            Assert.Throws<ArgumentOutOfRangeException>(() => EoGreCodec.PackKey(0x1000000, 0));
        }

        [Fact]
        public void Encode_WithChecksum_SetsChecksumBit_AndDecodeValidatesIt()
        {
            byte[] frame = SampleFrame();

            byte[] datagram = EoGreCodec.EncodeEoGre(frame, includeChecksum: true);

            Assert.Equal(BitChecksum, datagram[0] & BitChecksum);   // C bit set
            Assert.True(EoGreCodec.TryDecodeEoGre(datagram, out ushort protocolType, out ReadOnlyMemory<byte> decoded, out _, out _));
            Assert.Equal(EoGreCodec.ProtocolTypeTransparentEthernet, protocolType);
            Assert.Equal(frame, decoded.ToArray());

            // Corrupt a payload byte ⇒ the one's-complement checksum no longer sums to zero ⇒ decode rejects the datagram.
            datagram[datagram.Length - 1] ^= 0xFF;
            Assert.False(EoGreCodec.TryDecodeEoGre(datagram, out _, out _, out _, out _));
        }

        [Fact]
        public void Encode_WithSequence_SetsSequenceBit_AndRoundTrips()
        {
            byte[] frame = SampleFrame();

            byte[] datagram = EoGreCodec.EncodeEoGre(frame, sequenceNumber: 0x00C0FFEE);

            Assert.Equal(BitSequence, datagram[0] & BitSequence);   // S bit set
            Assert.True(EoGreCodec.TryDecodeEoGre(datagram, out _, out ReadOnlyMemory<byte> decoded, out _, out uint? seq));
            Assert.Equal(frame, decoded.ToArray());
            Assert.Equal(0x00C0FFEEu, seq);
        }

        [Fact]
        public void Encode_WithAllFlags_CKS_RoundTripsEverything()
        {
            uint vsid = 0x0000AB;
            byte flowId = 0xCD;
            byte[] frame = SampleFrame(28);

            byte[] datagram = EoGreCodec.EncodeEoGre(frame, vsid, flowId, includeChecksum: true, sequenceNumber: 7);

            Assert.Equal(BitChecksum | BitKey | BitSequence, datagram[0] & (BitChecksum | BitKey | BitSequence));
            Assert.True(EoGreCodec.TryDecodeEoGre(datagram, out ushort protocolType, out ReadOnlyMemory<byte> decoded, out uint? key, out uint? seq));
            Assert.Equal(EoGreCodec.ProtocolTypeTransparentEthernet, protocolType);
            Assert.Equal(frame, decoded.ToArray());
            Assert.Equal((vsid << 8) | flowId, key);
            Assert.Equal(7u, seq);
        }

        [Fact]
        public void Decode_PreservesNonEthernetProtocolType_SoCallerCanReject()
        {
            // Build a GRE datagram whose protocol type is IPv4 (0x0800), not TEB (0x6558): the codec still decodes but
            // surfaces the protocol type unchanged, letting the connection drop it.
            byte[] datagram = new byte[8];
            datagram[0] = 0x00;                   // no flags
            datagram[1] = 0x00;                   // Version 0
            datagram[2] = 0x08; datagram[3] = 0x00; // Protocol Type 0x0800 (IPv4)
            Assert.True(EoGreCodec.TryDecodeEoGre(datagram, out ushort protocolType, out _, out _, out _));
            Assert.NotEqual(EoGreCodec.ProtocolTypeTransparentEthernet, protocolType);
            Assert.Equal((ushort)0x0800, protocolType);
        }

        [Fact]
        public void Decode_Rejects_NonZeroVersion()
        {
            byte[] datagram = EoGreCodec.EncodeEoGre(SampleFrame());
            datagram[1] = 0x01;                   // GRE version 1 (Enhanced GRE) ⇒ rejected by the standard codec
            Assert.False(EoGreCodec.TryDecodeEoGre(datagram, out _, out _, out _, out _));
        }

        [Fact]
        public void Decode_Rejects_RuntShorterThanGreBaseHeader()
        {
            Assert.False(EoGreCodec.TryDecodeEoGre(new byte[3], out _, out _, out _, out _));
        }

        [Fact]
        public void Decode_Rejects_TruncatedOptionalKey()
        {
            // K bit set but the datagram carries only the 4-byte base header — the declared Key field is absent.
            byte[] datagram = new byte[4];
            datagram[0] = BitKey;                 // K present
            datagram[2] = 0x65; datagram[3] = 0x58;
            Assert.False(EoGreCodec.TryDecodeEoGre(datagram, out _, out _, out _, out _));
        }

        [Fact]
        public void Constants_MatchStandards()
        {
            Assert.Equal(4754, EoGreCodec.DefaultPort);
            Assert.Equal(0x6558, EoGreCodec.ProtocolTypeTransparentEthernet);
            Assert.Equal(0xFFFFFFu, EoGreCodec.MaxVsid);
            Assert.Equal(8, EoGreCodec.VsidShift);
        }
    }
}
