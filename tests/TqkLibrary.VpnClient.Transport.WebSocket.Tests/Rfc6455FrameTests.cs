using System;
using TqkLibrary.VpnClient.Transport.WebSocket;
using Xunit;

namespace TqkLibrary.VpnClient.Transport.WebSocket.Tests
{
    /// <summary>
    /// Tests for the RFC 6455 §5 frame codec: masked client-frame encode ↔ decode round-trip across all three length
    /// encodings (7-bit &lt; 126, 16-bit for 126, 64-bit for &gt; 65535), the exact mask XOR, unmasked server frames,
    /// partial-buffer handling, and the streaming reassembler.
    /// </summary>
    public class Rfc6455FrameTests
    {
        static byte[] Pattern(int length, byte seed)
        {
            byte[] b = new byte[length];
            for (int i = 0; i < length; i++) b[i] = (byte)(seed + i * 7);
            return b;
        }

        static readonly byte[] Mask = { 0x37, 0xFA, 0x21, 0x3D };

        [Theory]
        [InlineData(0)]       // empty payload
        [InlineData(5)]       // tiny
        [InlineData(125)]     // largest 7-bit length
        [InlineData(126)]     // smallest 16-bit extended length
        [InlineData(1400)]    // typical MTU-ish, 16-bit length
        [InlineData(65535)]   // largest 16-bit length
        [InlineData(65536)]   // smallest 64-bit extended length
        [InlineData(70000)]   // 64-bit length
        public void EncodeClientFrame_Decode_RoundTrips(int size)
        {
            byte[] payload = Pattern(size, 0x11);
            byte[] frame = Rfc6455Frame.EncodeClientFrame(Rfc6455Opcode.Binary, payload, Mask);

            Assert.True(Rfc6455Frame.TryDecodeFrame(frame, out bool fin, out Rfc6455Opcode opcode, out byte[] decoded, out int consumed));
            Assert.True(fin);
            Assert.Equal(Rfc6455Opcode.Binary, opcode);
            Assert.Equal(payload, decoded);
            Assert.Equal(frame.Length, consumed);
        }

        [Fact]
        public void EncodeClientFrame_SetsFinAndMaskBit()
        {
            byte[] frame = Rfc6455Frame.EncodeClientFrame(Rfc6455Opcode.Binary, Pattern(10, 0x01), Mask);
            Assert.Equal(0x82, frame[0]);            // FIN=1, RSV=0, opcode=0x2 (binary)
            Assert.Equal(0x80 | 10, frame[1]);       // MASK=1, len=10
        }

        [Fact]
        public void EncodeClientFrame_MasksPayload_WithXorFormula()
        {
            byte[] payload = Pattern(20, 0x40);
            byte[] frame = Rfc6455Frame.EncodeClientFrame(Rfc6455Opcode.Binary, payload, Mask);

            // header for len=20 is 2 bytes + 4-byte mask key; payload begins at offset 6.
            int payloadStart = 2 + 4;
            for (int i = 0; i < payload.Length; i++)
                Assert.Equal((byte)(payload[i] ^ Mask[i % 4]), frame[payloadStart + i]);
        }

        [Fact]
        public void EncodeServerFrame_IsUnmasked_AndDecodesVerbatim()
        {
            byte[] payload = Pattern(50, 0x22);
            byte[] frame = Rfc6455Frame.EncodeServerFrame(Rfc6455Opcode.Binary, payload);

            Assert.Equal(0, frame[1] & 0x80);        // MASK bit clear
            // unmasked ⇒ payload copied verbatim right after the 2-byte header
            for (int i = 0; i < payload.Length; i++)
                Assert.Equal(payload[i], frame[2 + i]);

            Assert.True(Rfc6455Frame.TryDecodeFrame(frame, out _, out Rfc6455Opcode opcode, out byte[] decoded, out _));
            Assert.Equal(Rfc6455Opcode.Binary, opcode);
            Assert.Equal(payload, decoded);
        }

        [Fact]
        public void EncodeServerFrame_NonFinal_ClearsFinBit()
        {
            byte[] frame = Rfc6455Frame.EncodeServerFrame(Rfc6455Opcode.Binary, Pattern(4, 1), fin: false);
            Assert.Equal(0, frame[0] & 0x80);        // FIN bit clear
            Assert.True(Rfc6455Frame.TryDecodeFrame(frame, out bool fin, out _, out _, out _));
            Assert.False(fin);
        }

        [Fact]
        public void TryDecodeFrame_ReturnsFalse_WhenBufferIncomplete()
        {
            byte[] frame = Rfc6455Frame.EncodeClientFrame(Rfc6455Opcode.Binary, Pattern(200, 0x05), Mask);
            // every strict prefix of a whole frame must decode to "not yet".
            for (int cut = 0; cut < frame.Length; cut++)
            {
                Assert.False(Rfc6455Frame.TryDecodeFrame(frame.AsSpan(0, cut), out _, out _, out _, out int consumed));
                Assert.Equal(0, consumed);
            }
            Assert.True(Rfc6455Frame.TryDecodeFrame(frame, out _, out _, out _, out _));
        }

        [Fact]
        public void EncodeClientFrame_Throws_OnWrongMaskKeyLength()
        {
            Assert.Throws<ArgumentException>(() =>
                Rfc6455Frame.EncodeClientFrame(Rfc6455Opcode.Binary, new byte[] { 1 }, new byte[] { 1, 2, 3 }));
        }

        [Fact]
        public void EncodeServerFrame_Throws_OnOversizedControlPayload()
        {
            Assert.Throws<ArgumentException>(() =>
                Rfc6455Frame.EncodeServerFrame(Rfc6455Opcode.Ping, new byte[126]));
        }

        [Fact]
        public void Reassembler_SplitsFramesAcrossByteBoundaries()
        {
            byte[] f1 = Rfc6455Frame.EncodeServerFrame(Rfc6455Opcode.Binary, Pattern(130, 0x01)); // 16-bit length
            byte[] f2 = Rfc6455Frame.EncodeServerFrame(Rfc6455Opcode.Ping, Pattern(4, 0x09));
            var reassembler = new Rfc6455FrameReassembler();

            // feed both frames one byte at a time.
            foreach (byte b in f1) reassembler.Append(new[] { b });
            foreach (byte b in f2) reassembler.Append(new[] { b });

            Assert.True(reassembler.TryReadFrame(out bool fin1, out Rfc6455Opcode op1, out byte[] p1));
            Assert.True(fin1);
            Assert.Equal(Rfc6455Opcode.Binary, op1);
            Assert.Equal(Pattern(130, 0x01), p1);

            Assert.True(reassembler.TryReadFrame(out _, out Rfc6455Opcode op2, out byte[] p2));
            Assert.Equal(Rfc6455Opcode.Ping, op2);
            Assert.Equal(Pattern(4, 0x09), p2);

            Assert.False(reassembler.TryReadFrame(out _, out _, out _));
            Assert.False(reassembler.HasBufferedData);
        }

        [Fact]
        public void Reassembler_HandlesMultipleFramesInOneAppend()
        {
            byte[] f1 = Rfc6455Frame.EncodeServerFrame(Rfc6455Opcode.Binary, Pattern(10, 0x02));
            byte[] f2 = Rfc6455Frame.EncodeServerFrame(Rfc6455Opcode.Binary, Pattern(20, 0x03));
            byte[] both = new byte[f1.Length + f2.Length];
            Array.Copy(f1, 0, both, 0, f1.Length);
            Array.Copy(f2, 0, both, f1.Length, f2.Length);

            var reassembler = new Rfc6455FrameReassembler();
            reassembler.Append(both);

            Assert.True(reassembler.TryReadFrame(out _, out _, out byte[] p1));
            Assert.Equal(Pattern(10, 0x02), p1);
            Assert.True(reassembler.TryReadFrame(out _, out _, out byte[] p2));
            Assert.Equal(Pattern(20, 0x03), p2);
            Assert.False(reassembler.TryReadFrame(out _, out _, out _));
        }
    }
}
