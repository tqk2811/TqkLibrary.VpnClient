using System;
using TqkLibrary.VpnClient.Drivers.VxlanGpe;
using Xunit;

namespace TqkLibrary.VpnClient.Drivers.VxlanGpe.Tests
{
    /// <summary>Unit tests for the pure VXLAN-GPE encapsulation codec (draft-ietf-nvo3-vxlan-gpe) — no transport, no fabric.</summary>
    public class VxlanGpeHeaderTests
    {
        [Fact]
        public void Encode_ThenDecode_RoundTripsVniNextProtocolAndFrame()
        {
            uint vni = 0x123456;
            byte[] frame = new byte[20];
            for (int i = 0; i < frame.Length; i++) frame[i] = (byte)(i + 1);

            byte[] datagram = VxlanGpeHeader.EncodeVxlanGpe(vni, VxlanGpeHeader.NextProtocolEthernet, frame);

            Assert.Equal(VxlanGpeHeader.HeaderLength + frame.Length, datagram.Length);
            Assert.True(VxlanGpeHeader.TryDecodeVxlanGpe(datagram, out uint decodedVni, out byte nextProtocol, out ReadOnlyMemory<byte> decodedFrame));
            Assert.Equal(vni, decodedVni);
            Assert.Equal(VxlanGpeHeader.NextProtocolEthernet, nextProtocol);
            Assert.Equal(frame, decodedFrame.ToArray());
        }

        [Fact]
        public void Encode_ProducesGpeHeader_FlagsNextProtoAndBigEndianVni()
        {
            byte[] datagram = VxlanGpeHeader.EncodeVxlanGpe(0x123456, VxlanGpeHeader.NextProtocolEthernet, new byte[14]);

            Assert.Equal(0x0C, datagram[0]);          // I bit (0x08) | P bit (0x04), Ver 0, all other flags 0
            Assert.Equal(0x00, datagram[1]);          // reserved
            Assert.Equal(0x00, datagram[2]);          // reserved
            Assert.Equal(0x03, datagram[3]);          // Next Protocol = Ethernet
            Assert.Equal(0x12, datagram[4]);          // VNI[23:16] big-endian
            Assert.Equal(0x34, datagram[5]);          // VNI[15:8]
            Assert.Equal(0x56, datagram[6]);          // VNI[7:0]
            Assert.Equal(0x00, datagram[7]);          // reserved
        }

        [Theory]
        [InlineData(0x01)]  // IPv4
        [InlineData(0x02)]  // IPv6
        [InlineData(0x03)]  // Ethernet
        [InlineData(0x04)]  // NSH
        public void Decode_ReadsEachNextProtocol(byte nextProtocol)
        {
            byte[] datagram = VxlanGpeHeader.EncodeVxlanGpe(0x00ABCD, nextProtocol, new byte[8]);
            Assert.Equal(nextProtocol, datagram[3]);
            Assert.True(VxlanGpeHeader.TryDecodeVxlanGpe(datagram, out uint vni, out byte decoded, out _));
            Assert.Equal(0x00ABCDu, vni);
            Assert.Equal(nextProtocol, decoded);
        }

        [Fact]
        public void Decode_Rejects_RuntShorterThanHeader()
        {
            Assert.False(VxlanGpeHeader.TryDecodeVxlanGpe(new byte[7], out _, out _, out _));
        }

        [Fact]
        public void Decode_Rejects_DatagramWithoutVniPresentBit()
        {
            byte[] datagram = VxlanGpeHeader.EncodeVxlanGpe(0x000001, VxlanGpeHeader.NextProtocolEthernet, new byte[14]);
            datagram[0] &= unchecked((byte)~VxlanGpeHeader.FlagVniPresent);   // clear the I bit (keep P)
            Assert.False(VxlanGpeHeader.TryDecodeVxlanGpe(datagram, out _, out _, out _));
        }

        [Fact]
        public void Decode_Rejects_DatagramWithoutNextProtocolBit()
        {
            byte[] datagram = VxlanGpeHeader.EncodeVxlanGpe(0x000001, VxlanGpeHeader.NextProtocolEthernet, new byte[14]);
            datagram[0] &= unchecked((byte)~VxlanGpeHeader.FlagNextProtocolPresent);   // clear the P bit (keep I)
            Assert.False(VxlanGpeHeader.TryDecodeVxlanGpe(datagram, out _, out _, out _));
        }

        [Fact]
        public void Decode_Rejects_NonZeroVersion()
        {
            byte[] datagram = VxlanGpeHeader.EncodeVxlanGpe(0x000001, VxlanGpeHeader.NextProtocolEthernet, new byte[14]);
            datagram[0] |= 0x10;              // Ver bit (bit 4) set ⇒ version 1
            Assert.False(VxlanGpeHeader.TryDecodeVxlanGpe(datagram, out _, out _, out _));
        }

        [Fact]
        public void Decode_Rejects_OamDatagram()
        {
            byte[] datagram = VxlanGpeHeader.EncodeVxlanGpe(0x000001, VxlanGpeHeader.NextProtocolEthernet, new byte[14]);
            datagram[0] |= VxlanGpeHeader.FlagOam;   // set the O (OAM) bit
            Assert.False(VxlanGpeHeader.TryDecodeVxlanGpe(datagram, out _, out _, out _));
        }

        [Fact]
        public void Decode_AcceptsHeaderOnly_ReturnsEmptyFrame()
        {
            byte[] datagram = VxlanGpeHeader.EncodeVxlanGpe(0x00ABCD, VxlanGpeHeader.NextProtocolEthernet, ReadOnlySpan<byte>.Empty);
            Assert.True(VxlanGpeHeader.TryDecodeVxlanGpe(datagram, out uint vni, out byte nextProtocol, out ReadOnlyMemory<byte> frame));
            Assert.Equal(0x00ABCDu, vni);
            Assert.Equal(VxlanGpeHeader.NextProtocolEthernet, nextProtocol);
            Assert.Equal(0, frame.Length);
        }

        [Fact]
        public void Encode_Throws_WhenVniExceeds24Bits()
        {
            Assert.Throws<ArgumentOutOfRangeException>(() => VxlanGpeHeader.EncodeVxlanGpe(0x1000000, VxlanGpeHeader.NextProtocolEthernet, new byte[14]));
        }

        [Fact]
        public void Constants_MatchDraft()
        {
            Assert.Equal(4790, VxlanGpeHeader.DefaultPort);
            Assert.Equal(8, VxlanGpeHeader.HeaderLength);
            Assert.Equal(0x08, VxlanGpeHeader.FlagVniPresent);
            Assert.Equal(0x04, VxlanGpeHeader.FlagNextProtocolPresent);
            Assert.Equal(0x01, VxlanGpeHeader.FlagOam);
            Assert.Equal(0x03, VxlanGpeHeader.NextProtocolEthernet);
            Assert.Equal(0xFFFFFFu, VxlanGpeHeader.MaxVni);
        }
    }
}
