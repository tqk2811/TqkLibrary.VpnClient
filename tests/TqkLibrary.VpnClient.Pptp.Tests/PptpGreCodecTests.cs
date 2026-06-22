using System;
using TqkLibrary.VpnClient.Pptp.Gre;
using Xunit;

namespace TqkLibrary.VpnClient.Pptp.Tests
{
    /// <summary>
    /// Offline coverage for the PPTP Enhanced GRE codec (RFC 2637 §4.1): round-trip of data / data+ack / ack-only
    /// packets, exact header-byte layout, and malformed-input rejection.
    /// </summary>
    public class PptpGreCodecTests
    {
        [Fact]
        public void DataPacket_RoundTrips_WithSequence_NoAck()
        {
            byte[] payload = { 0x00, 0x21, 0xDE, 0xAD, 0xBE, 0xEF };
            var packet = new PptpGrePacket { CallId = 0x1234, SequenceNumber = 7, Payload = payload };

            byte[] wire = PptpGreCodec.Encode(packet);

            Assert.True(PptpGreCodec.TryDecode(wire, out PptpGrePacket? decoded));
            Assert.NotNull(decoded);
            Assert.Equal(0x1234, decoded!.CallId);
            Assert.Equal(7u, decoded.SequenceNumber);
            Assert.Null(decoded.AckNumber);
            Assert.Equal(payload, decoded.Payload.ToArray());
        }

        [Fact]
        public void DataPacket_RoundTrips_WithSequence_AndAck()
        {
            byte[] payload = { 0x01, 0x02, 0x03 };
            var packet = new PptpGrePacket { CallId = 0xABCD, SequenceNumber = 42, AckNumber = 41, Payload = payload };

            byte[] wire = PptpGreCodec.Encode(packet);

            Assert.True(PptpGreCodec.TryDecode(wire, out PptpGrePacket? decoded));
            Assert.Equal(42u, decoded!.SequenceNumber);
            Assert.Equal(41u, decoded.AckNumber);
            Assert.Equal(payload, decoded.Payload.ToArray());
        }

        [Fact]
        public void AckOnly_RoundTrips_WithNoPayload()
        {
            var packet = new PptpGrePacket { CallId = 0x0001, AckNumber = 99, Payload = ReadOnlyMemory<byte>.Empty };

            byte[] wire = PptpGreCodec.Encode(packet);

            Assert.True(PptpGreCodec.TryDecode(wire, out PptpGrePacket? decoded));
            Assert.Null(decoded!.SequenceNumber);
            Assert.Equal(99u, decoded.AckNumber);
            Assert.Equal(0, decoded.Payload.Length);
        }

        [Fact]
        public void Header_Bytes_Are_Exact_For_DataPacket()
        {
            byte[] payload = { 0xAA, 0xBB };
            var packet = new PptpGrePacket { CallId = 0x1A2B, SequenceNumber = 5, Payload = payload };

            byte[] wire = PptpGreCodec.Encode(packet);

            // byte0 = K|S = 0x30, byte1 = Ver1 = 0x01, ProtocolType = 0x880B.
            Assert.Equal(0x30, wire[0]);
            Assert.Equal(0x01, wire[1]);
            Assert.Equal(0x88, wire[2]);
            Assert.Equal(0x0B, wire[3]);
            // Key high word = payload length (2), key low word = Call ID (0x1A2B).
            Assert.Equal(0x00, wire[4]);
            Assert.Equal(0x02, wire[5]);
            Assert.Equal(0x1A, wire[6]);
            Assert.Equal(0x2B, wire[7]);
        }

        [Fact]
        public void Header_Bytes_Set_AckBit_When_Ack_Present()
        {
            var packet = new PptpGrePacket { CallId = 1, AckNumber = 3, Payload = ReadOnlyMemory<byte>.Empty };
            byte[] wire = PptpGreCodec.Encode(packet);

            Assert.Equal(0x20, wire[0]); // K set, S clear (no sequence/payload)
            Assert.Equal(0x81, wire[1]); // A set, Ver 1
        }

        [Fact]
        public void TryDecode_Rejects_WrongVersion()
        {
            var packet = new PptpGrePacket { CallId = 1, SequenceNumber = 1, Payload = new byte[] { 9 } };
            byte[] wire = PptpGreCodec.Encode(packet);
            wire[1] = (byte)((wire[1] & 0xF8) | 0x02); // version 2

            Assert.False(PptpGreCodec.TryDecode(wire, out PptpGrePacket? decoded));
            Assert.Null(decoded);
        }

        [Fact]
        public void TryDecode_Rejects_WrongProtocolType()
        {
            var packet = new PptpGrePacket { CallId = 1, SequenceNumber = 1, Payload = new byte[] { 9 } };
            byte[] wire = PptpGreCodec.Encode(packet);
            wire[2] = 0x00; // corrupt protocol type

            Assert.False(PptpGreCodec.TryDecode(wire, out _));
        }

        [Fact]
        public void TryDecode_Rejects_MissingKeyBit()
        {
            var packet = new PptpGrePacket { CallId = 1, SequenceNumber = 1, Payload = new byte[] { 9 } };
            byte[] wire = PptpGreCodec.Encode(packet);
            wire[0] &= 0xDF; // clear K bit

            Assert.False(PptpGreCodec.TryDecode(wire, out _));
        }

        [Fact]
        public void TryDecode_Rejects_Truncated()
        {
            var packet = new PptpGrePacket { CallId = 1, SequenceNumber = 1, Payload = new byte[] { 9, 9, 9 } };
            byte[] wire = PptpGreCodec.Encode(packet);
            byte[] truncated = wire.AsSpan(0, wire.Length - 2).ToArray();

            Assert.False(PptpGreCodec.TryDecode(truncated, out _));
        }

        [Fact]
        public void TryDecode_Rejects_TooShortHeader()
        {
            Assert.False(PptpGreCodec.TryDecode(new byte[] { 0x30, 0x01, 0x88 }, out _));
        }
    }
}
