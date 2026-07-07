using System;
using System.Buffers.Binary;
using System.Collections.Generic;
using System.Linq;
using Xunit;

namespace TqkLibrary.VpnClient.Transport.IpsecTcp.Tests
{
    /// <summary>
    /// Byte-exact tests for the stateless RFC 8229 framing (<see cref="Rfc8229Framing"/>) and the streaming
    /// reassembler (<see cref="Rfc8229Reassembler"/>): Length framing, stream-prefix handling, and reassembly across
    /// arbitrary read boundaries.
    /// </summary>
    public class Rfc8229FramingTests
    {
        static byte[] Pattern(int length, byte seed)
        {
            byte[] b = new byte[length];
            for (int i = 0; i < length; i++) b[i] = (byte)(seed + i);
            return b;
        }

        [Theory]
        [InlineData(0)]
        [InlineData(1)]
        [InlineData(2)]
        [InlineData(16)]
        [InlineData(1500)]
        [InlineData(65533)]   // MaxMessageLength — total 65535 fits the 16-bit Length exactly
        public void Frame_PrependsLengthIncludingItself(int messageLength)
        {
            byte[] message = Pattern(messageLength, 0x40);

            byte[] frame = Rfc8229Framing.Frame(message);

            Assert.Equal(messageLength + Rfc8229Framing.LengthFieldSize, frame.Length);
            int declared = BinaryPrimitives.ReadUInt16BigEndian(frame.AsSpan(0, 2));
            Assert.Equal(messageLength + Rfc8229Framing.LengthFieldSize, declared);   // Length counts itself (§2)
            Assert.Equal(message, frame.AsSpan(2).ToArray());
        }

        [Fact]
        public void Frame_ThrowsWhenMessageExceedsMaximum()
        {
            byte[] tooBig = new byte[Rfc8229Framing.MaxMessageLength + 1];
            Assert.Throws<ArgumentOutOfRangeException>(() => Rfc8229Framing.Frame(tooBig));
        }

        [Fact]
        public void StreamPrefix_IsIketcpAscii()
        {
            Assert.Equal(6, Rfc8229Framing.StreamPrefixLength);
            Assert.Equal(new byte[] { 0x49, 0x4B, 0x45, 0x54, 0x43, 0x50 }, Rfc8229Framing.StreamPrefix.ToArray());
            Assert.Equal("IKETCP", System.Text.Encoding.ASCII.GetString(Rfc8229Framing.StreamPrefix.ToArray()));
        }

        // Feeds a byte stream into a reassembler in fixed-size chunks and collects every recovered message.
        static List<byte[]> FeedInChunks(Rfc8229Reassembler reassembler, byte[] stream, int chunkSize)
        {
            var messages = new List<byte[]>();
            for (int offset = 0; offset < stream.Length; offset += chunkSize)
            {
                int n = Math.Min(chunkSize, stream.Length - offset);
                reassembler.Append(stream.AsSpan(offset, n));
                while (reassembler.TryReadMessage(out byte[] message)) messages.Add(message);
            }
            return messages;
        }

        [Theory]
        [InlineData(1)]        // one byte at a time — cuts through every Length field and every message
        [InlineData(2)]
        [InlineData(3)]        // cuts across Length↔message boundaries at odd offsets
        [InlineData(7)]
        [InlineData(100000)]   // whole stream (all messages) in a single chunk
        public void Reassembler_RoundTripsMessages_AcrossChunkSizes(int chunkSize)
        {
            byte[][] originals =
            {
                Pattern(1, 0x10),
                Pattern(20, 0x20),
                Array.Empty<byte>(),      // empty message (Length = 2)
                Pattern(255, 0x30),
                Pattern(1400, 0x50),
            };
            byte[] stream = originals.SelectMany(m => Rfc8229Framing.Frame(m)).ToArray();

            List<byte[]> recovered = FeedInChunks(new Rfc8229Reassembler(), stream, chunkSize);

            Assert.Equal(originals.Length, recovered.Count);
            for (int i = 0; i < originals.Length; i++) Assert.Equal(originals[i], recovered[i]);
        }

        [Fact]
        public void Reassembler_SplitsMultipleMessagesInOneAppend()
        {
            byte[] a = Pattern(10, 0xA0);
            byte[] b = Pattern(11, 0xB0);
            var reassembler = new Rfc8229Reassembler();

            reassembler.Append(Rfc8229Framing.Frame(a).Concat(Rfc8229Framing.Frame(b)).ToArray());

            Assert.True(reassembler.TryReadMessage(out byte[] first));
            Assert.Equal(a, first);
            Assert.True(reassembler.TryReadMessage(out byte[] second));
            Assert.Equal(b, second);
            Assert.False(reassembler.TryReadMessage(out _));
        }

        [Fact]
        public void Reassembler_ReturnsFalseUntilFrameComplete()
        {
            byte[] frame = Rfc8229Framing.Frame(Pattern(5, 0xC0));
            var reassembler = new Rfc8229Reassembler();

            reassembler.Append(frame.AsSpan(0, 1));                 // half a Length field
            Assert.False(reassembler.TryReadMessage(out _));
            reassembler.Append(frame.AsSpan(1, 3));                 // rest of Length + start of message
            Assert.False(reassembler.TryReadMessage(out _));
            reassembler.Append(frame.AsSpan(4));                    // remainder
            Assert.True(reassembler.TryReadMessage(out byte[] message));
            Assert.Equal(Pattern(5, 0xC0), message);
        }

        [Fact]
        public void Reassembler_ConsumesStreamPrefix_WhenExpected()
        {
            byte[] msg = Pattern(12, 0xD0);
            byte[] stream = Rfc8229Framing.StreamPrefix.ToArray().Concat(Rfc8229Framing.Frame(msg)).ToArray();

            // Feed one byte at a time to prove the prefix is stripped even when split from the first frame.
            List<byte[]> recovered = FeedInChunks(new Rfc8229Reassembler(expectStreamPrefix: true), stream, 1);

            Assert.Single(recovered);
            Assert.Equal(msg, recovered[0]);
        }

        [Fact]
        public void Reassembler_ThrowsOnCorruptStreamPrefix()
        {
            byte[] bad = new byte[] { 0x49, 0x4B, 0x45, 0x54, 0x43, 0x00 };   // last byte wrong ("IKETC\0")
            var reassembler = new Rfc8229Reassembler(expectStreamPrefix: true);
            reassembler.Append(bad);

            Assert.Throws<FormatException>(() => reassembler.TryReadMessage(out _));
        }

        [Theory]
        [InlineData(0)]
        [InlineData(1)]
        public void Reassembler_ThrowsOnLengthBelowMinimum(int declaredLength)
        {
            // A Length below the 2-byte field size is a desynced stream; must throw rather than underflow.
            byte[] frame = { (byte)(declaredLength >> 8), (byte)(declaredLength & 0xFF) };
            var reassembler = new Rfc8229Reassembler();
            reassembler.Append(frame);

            Assert.Throws<FormatException>(() => reassembler.TryReadMessage(out _));
        }

        [Fact]
        public void Reassembler_WithoutPrefix_DoesNotStripLeadingBytes()
        {
            // Default reassembler (server→client direction) must NOT treat leading bytes as a prefix: it parses the
            // very first bytes as a Length field.
            byte[] msg = Pattern(4, 0xE0);
            var reassembler = new Rfc8229Reassembler();
            reassembler.Append(Rfc8229Framing.Frame(msg));

            Assert.True(reassembler.TryReadMessage(out byte[] recovered));
            Assert.Equal(msg, recovered);
        }

        [Fact]
        public void HasBufferedData_TracksPartialFrame()
        {
            byte[] frame = Rfc8229Framing.Frame(Pattern(8, 0xF0));
            var reassembler = new Rfc8229Reassembler();

            Assert.False(reassembler.HasBufferedData);
            reassembler.Append(frame.AsSpan(0, 3));     // partial
            Assert.False(reassembler.TryReadMessage(out _));
            Assert.True(reassembler.HasBufferedData);
            reassembler.Append(frame.AsSpan(3));        // complete
            Assert.True(reassembler.TryReadMessage(out _));
            Assert.False(reassembler.HasBufferedData);  // fully drained
        }
    }
}
