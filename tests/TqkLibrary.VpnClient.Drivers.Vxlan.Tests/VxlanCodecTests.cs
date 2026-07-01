using System;
using TqkLibrary.VpnClient.Drivers.Vxlan;
using Xunit;

namespace TqkLibrary.VpnClient.Drivers.Vxlan.Tests
{
    /// <summary>Unit tests for the pure VXLAN encapsulation codec (RFC 7348 §5) — no transport, no fabric.</summary>
    public class VxlanCodecTests
    {
        [Fact]
        public void Encode_ThenDecode_RoundTripsVniAndFrame()
        {
            uint vni = 0x123456;
            byte[] frame = new byte[20];
            for (int i = 0; i < frame.Length; i++) frame[i] = (byte)(i + 1);

            byte[] datagram = VxlanCodec.EncodeVxlan(vni, frame);

            Assert.Equal(VxlanCodec.HeaderLength + frame.Length, datagram.Length);
            Assert.True(VxlanCodec.TryDecodeVxlan(datagram, out uint decodedVni, out ReadOnlyMemory<byte> decodedFrame));
            Assert.Equal(vni, decodedVni);
            Assert.Equal(frame, decodedFrame.ToArray());
        }

        [Fact]
        public void Encode_ProducesRfc7348Header_FlagsAndBigEndianVni()
        {
            byte[] datagram = VxlanCodec.EncodeVxlan(0x123456, new byte[14]);

            Assert.Equal(0x08, datagram[0]);          // I bit (VNI valid), all other flags 0
            Assert.Equal(0x00, datagram[1]);
            Assert.Equal(0x00, datagram[2]);
            Assert.Equal(0x00, datagram[3]);
            Assert.Equal(0x12, datagram[4]);          // VNI[23:16] big-endian
            Assert.Equal(0x34, datagram[5]);          // VNI[15:8]
            Assert.Equal(0x56, datagram[6]);          // VNI[7:0]
            Assert.Equal(0x00, datagram[7]);          // reserved
        }

        [Fact]
        public void Decode_Rejects_RuntShorterThanHeader()
        {
            Assert.False(VxlanCodec.TryDecodeVxlan(new byte[7], out _, out _));
        }

        [Fact]
        public void Decode_Rejects_DatagramWithoutVniPresentBit()
        {
            byte[] datagram = VxlanCodec.EncodeVxlan(0x000001, new byte[14]);
            datagram[0] = 0x00;                        // clear the I bit
            Assert.False(VxlanCodec.TryDecodeVxlan(datagram, out _, out _));
        }

        [Fact]
        public void Decode_AcceptsHeaderOnly_ReturnsEmptyFrame()
        {
            byte[] datagram = VxlanCodec.EncodeVxlan(0x00ABCD, ReadOnlySpan<byte>.Empty);
            Assert.True(VxlanCodec.TryDecodeVxlan(datagram, out uint vni, out ReadOnlyMemory<byte> frame));
            Assert.Equal(0x00ABCDu, vni);
            Assert.Equal(0, frame.Length);
        }

        [Fact]
        public void Encode_Throws_WhenVniExceeds24Bits()
        {
            Assert.Throws<ArgumentOutOfRangeException>(() => VxlanCodec.EncodeVxlan(0x1000000, new byte[14]));
        }

        [Fact]
        public void Constants_MatchRfc7348()
        {
            Assert.Equal(4789, VxlanCodec.DefaultPort);
            Assert.Equal(8, VxlanCodec.HeaderLength);
            Assert.Equal(0x08, VxlanCodec.FlagVniPresent);
            Assert.Equal(0xFFFFFFu, VxlanCodec.MaxVni);
        }
    }
}
