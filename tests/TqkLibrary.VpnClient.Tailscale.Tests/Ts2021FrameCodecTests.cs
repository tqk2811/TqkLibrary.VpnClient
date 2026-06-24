using System;
using TqkLibrary.VpnClient.Tailscale.Control.Noise;
using Xunit;

namespace TqkLibrary.VpnClient.Tailscale.Tests
{
    public class Ts2021FrameCodecTests
    {
        [Fact]
        public void Initiation_Header_5Bytes_VersionTypeLength()
        {
            byte[] noise = new byte[96];
            for (int i = 0; i < noise.Length; i++) noise[i] = (byte)i;
            byte[] frame = Ts2021FrameCodec.EncodeInitiation(1, noise);

            Assert.Equal(Ts2021FrameCodec.InitiationHeaderLength + noise.Length, frame.Length);
            Assert.Equal(0x00, frame[0]); // version high
            Assert.Equal(0x01, frame[1]); // version low
            Assert.Equal((byte)Ts2021FrameType.Initiation, frame[2]);
            Assert.Equal((byte)(noise.Length >> 8), frame[3]); // length BE high
            Assert.Equal((byte)(noise.Length & 0xFF), frame[4]); // length BE low
        }

        [Fact]
        public void Frame_Header_3Bytes_TypeLength_BigEndian()
        {
            byte[] payload = new byte[300]; // > 255 to exercise the high length byte
            byte[] frame = Ts2021FrameCodec.EncodeFrame(Ts2021FrameType.Record, payload);

            Assert.Equal((byte)Ts2021FrameType.Record, frame[0]);
            Assert.Equal((byte)(300 >> 8), frame[1]);
            Assert.Equal((byte)(300 & 0xFF), frame[2]);

            Assert.True(Ts2021FrameCodec.TryDecodeHeader(frame, out Ts2021FrameType type, out int len));
            Assert.Equal(Ts2021FrameType.Record, type);
            Assert.Equal(300, len);
        }

        [Fact]
        public void EncodeFrame_RejectsInitiationType()
        {
            Assert.Throws<ArgumentException>(() => Ts2021FrameCodec.EncodeFrame(Ts2021FrameType.Initiation, Array.Empty<byte>()));
        }

        [Fact]
        public void TryDecodeHeader_ShortBuffer_False()
        {
            Assert.False(Ts2021FrameCodec.TryDecodeHeader(new byte[2], out _, out _));
        }
    }
}
