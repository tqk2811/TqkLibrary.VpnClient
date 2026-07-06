using System;
using TqkLibrary.VpnClient.Drivers.L2tpv3Eth;
using TqkLibrary.VpnClient.Drivers.L2tpv3Eth.Enums;
using Xunit;

namespace TqkLibrary.VpnClient.Drivers.L2tpv3Eth.Tests
{
    /// <summary>Unit tests for the pure L2TPv3 data-message codec (RFC 3931 §4.1 + RFC 4719) — no transport, no fabric.</summary>
    public class L2tpv3DataHeaderTests
    {
        static readonly byte[] NoCookie = Array.Empty<byte>();

        static byte[] Frame(int length, byte tail)
        {
            byte[] frame = new byte[length];
            for (int i = 0; i < frame.Length; i++) frame[i] = (byte)(i + 1);
            if (length > 0) frame[length - 1] = tail;
            return frame;
        }

        [Fact]
        public void Encode_ThenDecode_RoundTripsSessionIdAndFrame_NoCookie_NoSequencing()
        {
            uint sessionId = 0x12345678;
            byte[] frame = Frame(20, 0xAB);

            byte[] datagram = L2tpv3DataHeader.EncodeData(sessionId, NoCookie, sequencing: false, sequenceNumber: 0, frame);

            Assert.Equal(L2tpv3DataHeader.SessionIdLength + frame.Length, datagram.Length);
            Assert.True(L2tpv3DataHeader.TryDecodeData(datagram, sessionId, NoCookie, sequencing: false,
                out uint seq, out ReadOnlyMemory<byte> decoded, out L2tpv3DecodeError error));
            Assert.Equal(L2tpv3DecodeError.None, error);
            Assert.Equal(0u, seq);
            Assert.Equal(frame, decoded.ToArray());
        }

        [Fact]
        public void Encode_WritesSessionId_BigEndian()
        {
            byte[] datagram = L2tpv3DataHeader.EncodeData(0x12345678, NoCookie, sequencing: false, sequenceNumber: 0, new byte[14]);
            Assert.Equal(0x12, datagram[0]);   // Session ID[31:24] big-endian
            Assert.Equal(0x34, datagram[1]);   // [23:16]
            Assert.Equal(0x56, datagram[2]);   // [15:8]
            Assert.Equal(0x78, datagram[3]);   // [7:0]
        }

        [Theory]
        [InlineData(0)]
        [InlineData(4)]
        [InlineData(8)]
        public void Encode_ThenDecode_RoundTripsCookie(int cookieLength)
        {
            uint sessionId = 0x0A0B0C0D;
            byte[] cookie = new byte[cookieLength];
            for (int i = 0; i < cookieLength; i++) cookie[i] = (byte)(0xC0 + i);
            byte[] frame = Frame(16, 0x5E);

            byte[] datagram = L2tpv3DataHeader.EncodeData(sessionId, cookie, sequencing: false, sequenceNumber: 0, frame);

            Assert.Equal(L2tpv3DataHeader.SessionIdLength + cookieLength + frame.Length, datagram.Length);
            // The cookie sits verbatim right after the 4-byte Session ID.
            for (int i = 0; i < cookieLength; i++)
                Assert.Equal(cookie[i], datagram[L2tpv3DataHeader.SessionIdLength + i]);

            Assert.True(L2tpv3DataHeader.TryDecodeData(datagram, sessionId, cookie, sequencing: false, out _, out ReadOnlyMemory<byte> decoded, out L2tpv3DecodeError error));
            Assert.Equal(L2tpv3DecodeError.None, error);
            Assert.Equal(frame, decoded.ToArray());
        }

        [Theory]
        [InlineData(0u)]
        [InlineData(1u)]
        [InlineData(0x00ABCDEFu)]
        [InlineData(0xFFFFFFu)]     // 24-bit max
        public void Encode_ThenDecode_RoundTripsSequenceNumber_WithSublayer(uint sequence)
        {
            uint sessionId = 0x01020304;
            byte[] cookie = { 0xAA, 0xBB, 0xCC, 0xDD };
            byte[] frame = Frame(18, 0x77);

            byte[] datagram = L2tpv3DataHeader.EncodeData(sessionId, cookie, sequencing: true, sequence, frame);

            // Session ID (4) + cookie (4) + 4-byte Default L2-Specific Sublayer + frame.
            int sublayerOffset = L2tpv3DataHeader.SessionIdLength + cookie.Length;
            Assert.Equal(sublayerOffset + L2tpv3DataHeader.L2SpecificSublayerLength + frame.Length, datagram.Length);
            Assert.Equal(L2tpv3DataHeader.SublayerSequenceBit, datagram[sublayerOffset]); // S bit set, other flags 0

            Assert.True(L2tpv3DataHeader.TryDecodeData(datagram, sessionId, cookie, sequencing: true,
                out uint decodedSeq, out ReadOnlyMemory<byte> decoded, out L2tpv3DecodeError error));
            Assert.Equal(L2tpv3DecodeError.None, error);
            Assert.Equal(sequence, decodedSeq);
            Assert.Equal(frame, decoded.ToArray());
        }

        [Fact]
        public void Decode_AcceptsHeaderOnly_ReturnsEmptyPayload()
        {
            byte[] datagram = L2tpv3DataHeader.EncodeData(0x00ABCDEF, NoCookie, sequencing: false, sequenceNumber: 0, ReadOnlySpan<byte>.Empty);
            Assert.True(L2tpv3DataHeader.TryDecodeData(datagram, 0x00ABCDEF, NoCookie, sequencing: false, out _, out ReadOnlyMemory<byte> payload, out L2tpv3DecodeError error));
            Assert.Equal(L2tpv3DecodeError.None, error);
            Assert.Equal(0, payload.Length);
        }

        [Fact]
        public void Decode_Rejects_Runt_ShorterThanSessionId()
        {
            Assert.False(L2tpv3DataHeader.TryDecodeData(new byte[3], 0x01020304, NoCookie, sequencing: false, out _, out _, out L2tpv3DecodeError error));
            Assert.Equal(L2tpv3DecodeError.Runt, error);
        }

        [Fact]
        public void Decode_Rejects_ControlMessage_TBitSet()
        {
            // A control message has the T-bit (top bit of the first octet) set; drop before matching the Session ID.
            byte[] datagram = { 0x80, 0x00, 0x00, 0x01, 0xDE, 0xAD };
            Assert.False(L2tpv3DataHeader.TryDecodeData(datagram, 0x00000001, NoCookie, sequencing: false, out _, out _, out L2tpv3DecodeError error));
            Assert.Equal(L2tpv3DecodeError.ControlMessage, error);
        }

        [Fact]
        public void Decode_Rejects_ZeroSessionId_ControlChannel()
        {
            byte[] datagram = new byte[4 + 14]; // Session ID 0 + a frame-sized tail
            Assert.False(L2tpv3DataHeader.TryDecodeData(datagram, 0x01020304, NoCookie, sequencing: false, out _, out _, out L2tpv3DecodeError error));
            Assert.Equal(L2tpv3DecodeError.ZeroSessionId, error);
        }

        [Fact]
        public void Decode_Rejects_SessionIdMismatch()
        {
            byte[] datagram = L2tpv3DataHeader.EncodeData(0x11111111, NoCookie, sequencing: false, sequenceNumber: 0, new byte[14]);
            Assert.False(L2tpv3DataHeader.TryDecodeData(datagram, 0x22222222, NoCookie, sequencing: false, out _, out _, out L2tpv3DecodeError error));
            Assert.Equal(L2tpv3DecodeError.SessionIdMismatch, error);
        }

        [Fact]
        public void Decode_Rejects_CookieMismatch()
        {
            byte[] cookie = { 0x01, 0x02, 0x03, 0x04 };
            byte[] datagram = L2tpv3DataHeader.EncodeData(0x0A0B0C0D, cookie, sequencing: false, sequenceNumber: 0, new byte[14]);
            byte[] wrong = { 0x01, 0x02, 0x03, 0xFF };
            Assert.False(L2tpv3DataHeader.TryDecodeData(datagram, 0x0A0B0C0D, wrong, sequencing: false, out _, out _, out L2tpv3DecodeError error));
            Assert.Equal(L2tpv3DecodeError.CookieMismatch, error);
        }

        [Fact]
        public void Decode_Rejects_Truncated_WhenCookieRunsPastDatagram()
        {
            // Only a 4-byte Session ID present, but an 8-byte cookie is expected.
            byte[] datagram = L2tpv3DataHeader.EncodeData(0x0A0B0C0D, NoCookie, sequencing: false, sequenceNumber: 0, ReadOnlySpan<byte>.Empty);
            byte[] cookie8 = new byte[8];
            Assert.False(L2tpv3DataHeader.TryDecodeData(datagram, 0x0A0B0C0D, cookie8, sequencing: false, out _, out _, out L2tpv3DecodeError error));
            Assert.Equal(L2tpv3DecodeError.Truncated, error);
        }

        [Fact]
        public void Decode_Rejects_Truncated_WhenSublayerRunsPastDatagram()
        {
            // A data message encoded WITHOUT sequencing, decoded expecting the 4-byte sublayer ⇒ header runs past the payload.
            byte[] datagram = L2tpv3DataHeader.EncodeData(0x0A0B0C0D, NoCookie, sequencing: false, sequenceNumber: 0, new byte[2]);
            Assert.False(L2tpv3DataHeader.TryDecodeData(datagram, 0x0A0B0C0D, NoCookie, sequencing: true, out _, out _, out L2tpv3DecodeError error));
            Assert.Equal(L2tpv3DecodeError.Truncated, error);
        }

        [Fact]
        public void Encode_Throws_WhenSessionIdIsZero()
        {
            Assert.Throws<ArgumentOutOfRangeException>(
                () => L2tpv3DataHeader.EncodeData(0, NoCookie, sequencing: false, sequenceNumber: 0, new byte[14]));
        }

        [Fact]
        public void Encode_Throws_WhenSessionIdHasTopBitSet()
        {
            Assert.Throws<ArgumentOutOfRangeException>(
                () => L2tpv3DataHeader.EncodeData(0x80000001, NoCookie, sequencing: false, sequenceNumber: 0, new byte[14]));
        }

        [Theory]
        [InlineData(1)]
        [InlineData(2)]
        [InlineData(3)]
        [InlineData(5)]
        [InlineData(16)]
        public void Encode_Throws_WhenCookieLengthInvalid(int cookieLength)
        {
            Assert.Throws<ArgumentOutOfRangeException>(
                () => L2tpv3DataHeader.EncodeData(0x0A0B0C0D, new byte[cookieLength], sequencing: false, sequenceNumber: 0, new byte[14]));
        }

        [Fact]
        public void Encode_Throws_WhenSequenceExceeds24Bits()
        {
            Assert.Throws<ArgumentOutOfRangeException>(
                () => L2tpv3DataHeader.EncodeData(0x0A0B0C0D, NoCookie, sequencing: true, 0x1000000, new byte[14]));
        }

        [Fact]
        public void Constants_MatchRfc3931()
        {
            Assert.Equal(1701, L2tpv3DataHeader.DefaultPort);
            Assert.Equal(4, L2tpv3DataHeader.SessionIdLength);
            Assert.Equal(0x80, L2tpv3DataHeader.ControlMessageBit);
            Assert.Equal(0x7FFFFFFFu, L2tpv3DataHeader.MaxSessionId);
            Assert.Equal(4, L2tpv3DataHeader.L2SpecificSublayerLength);
            Assert.Equal(0x40, L2tpv3DataHeader.SublayerSequenceBit);
            Assert.Equal(0xFFFFFFu, L2tpv3DataHeader.MaxSequenceNumber);
        }
    }
}
