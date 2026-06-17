using TqkLibrary.VpnClient.OpenConnect;
using TqkLibrary.VpnClient.OpenConnect.Enums;
using TqkLibrary.VpnClient.OpenConnect.Models;
using Xunit;

namespace TqkLibrary.VpnClient.OpenConnect.Tests
{
    /// <summary>
    /// Tests the CSTP 8-byte framing codec (V5.a): header layout, round-trip for every packet type, the streaming
    /// reassembler across arbitrary read boundaries, and rejection of malformed frames.
    /// </summary>
    public class CstpFramingTests
    {
        [Theory]
        [InlineData(CstpPacketType.Data)]
        [InlineData(CstpPacketType.DpdRequest)]
        [InlineData(CstpPacketType.DpdResponse)]
        [InlineData(CstpPacketType.Disconnect)]
        [InlineData(CstpPacketType.KeepAlive)]
        [InlineData(CstpPacketType.Compressed)]
        [InlineData(CstpPacketType.Terminate)]
        public void Encode_Decode_RoundTrips_AllTypes(CstpPacketType type)
        {
            byte[] payload = type == CstpPacketType.Data || type == CstpPacketType.Compressed
                ? new byte[] { 0x45, 0x00, 0x00, 0x14, 0xDE, 0xAD, 0xBE, 0xEF }   // a tiny IPv4-ish datagram
                : Array.Empty<byte>();                                            // control packets carry no payload

            byte[] frame = CstpFraming.Encode(type, payload);

            // Header is exactly: 'S' 'T' 'F' 0x01 | len(2 BE) | type | 0x00
            Assert.Equal(CstpFraming.HeaderSize + payload.Length, frame.Length);
            Assert.Equal(new byte[] { 0x53, 0x54, 0x46, 0x01 }, frame.AsSpan(0, 4).ToArray());
            Assert.Equal((byte)(payload.Length >> 8), frame[4]);
            Assert.Equal((byte)(payload.Length & 0xFF), frame[5]);
            Assert.Equal((byte)type, frame[6]);
            Assert.Equal(0x00, frame[7]);

            CstpPacket decoded = CstpFraming.Decode(frame);
            Assert.Equal(type, decoded.Type);
            Assert.Equal(payload, decoded.Payload);
        }

        [Fact]
        public void Encode_PacketOverload_MatchesTypePayloadOverload()
        {
            var packet = new CstpPacket(CstpPacketType.Data, new byte[] { 1, 2, 3 });
            Assert.Equal(CstpFraming.Encode(CstpPacketType.Data, new byte[] { 1, 2, 3 }), CstpFraming.Encode(packet));
        }

        [Fact]
        public void IsData_TrueOnlyForDataAndCompressed()
        {
            Assert.True(new CstpPacket(CstpPacketType.Data, Array.Empty<byte>()).IsData);
            Assert.True(new CstpPacket(CstpPacketType.Compressed, Array.Empty<byte>()).IsData);
            Assert.False(new CstpPacket(CstpPacketType.KeepAlive, Array.Empty<byte>()).IsData);
            Assert.False(new CstpPacket(CstpPacketType.DpdRequest, Array.Empty<byte>()).IsData);
        }

        [Fact]
        public void Streaming_ReassemblesPacketSplitAcrossReads()
        {
            byte[] a = CstpFraming.Encode(CstpPacketType.Data, new byte[] { 10, 20, 30, 40 });
            byte[] b = CstpFraming.Encode(CstpPacketType.DpdRequest, Array.Empty<byte>());
            byte[] wire = Concat(a, b);

            var framing = new CstpFraming();
            var received = new List<CstpPacket>();

            // Feed one byte at a time — the hardest split for the reassembler.
            foreach (byte octet in wire)
            {
                framing.Append(new[] { octet });
                while (framing.TryReadPacket(out CstpPacket p)) received.Add(p);
            }

            Assert.Equal(2, received.Count);
            Assert.Equal(CstpPacketType.Data, received[0].Type);
            Assert.Equal(new byte[] { 10, 20, 30, 40 }, received[0].Payload);
            Assert.Equal(CstpPacketType.DpdRequest, received[1].Type);
            Assert.Empty(received[1].Payload);
        }

        [Fact]
        public void Streaming_CoalescesMultiplePacketsInOneRead()
        {
            byte[] wire = Concat(
                CstpFraming.Encode(CstpPacketType.KeepAlive, Array.Empty<byte>()),
                CstpFraming.Encode(CstpPacketType.Data, new byte[] { 0xAB }),
                CstpFraming.Encode(CstpPacketType.Disconnect, Array.Empty<byte>()));

            var framing = new CstpFraming();
            framing.Append(wire);

            Assert.True(framing.TryReadPacket(out CstpPacket p1));
            Assert.Equal(CstpPacketType.KeepAlive, p1.Type);
            Assert.True(framing.TryReadPacket(out CstpPacket p2));
            Assert.Equal(CstpPacketType.Data, p2.Type);
            Assert.Equal(new byte[] { 0xAB }, p2.Payload);
            Assert.True(framing.TryReadPacket(out CstpPacket p3));
            Assert.Equal(CstpPacketType.Disconnect, p3.Type);
            Assert.False(framing.TryReadPacket(out _));
        }

        [Fact]
        public void Streaming_WaitsForFullPayload()
        {
            byte[] frame = CstpFraming.Encode(CstpPacketType.Data, new byte[] { 1, 2, 3, 4, 5 });
            var framing = new CstpFraming();

            framing.Append(frame.AsSpan(0, frame.Length - 1).ToArray()); // all but the last payload byte
            Assert.False(framing.TryReadPacket(out _));

            framing.Append(frame.AsSpan(frame.Length - 1).ToArray());     // the final byte
            Assert.True(framing.TryReadPacket(out CstpPacket p));
            Assert.Equal(new byte[] { 1, 2, 3, 4, 5 }, p.Payload);
        }

        [Fact]
        public void Decode_RejectsBadMagic()
        {
            byte[] frame = CstpFraming.Encode(CstpPacketType.Data, new byte[] { 1 });
            frame[0] = 0x00; // corrupt the magic
            Assert.Throws<FormatException>(() => CstpFraming.Decode(frame));
        }

        [Fact]
        public void Decode_RejectsLengthMismatch()
        {
            byte[] frame = CstpFraming.Encode(CstpPacketType.Data, new byte[] { 1, 2, 3 });
            byte[] truncated = frame.AsSpan(0, frame.Length - 1).ToArray();
            Assert.Throws<FormatException>(() => CstpFraming.Decode(truncated));
        }

        [Fact]
        public void Decode_RejectsShortFrame()
        {
            Assert.Throws<FormatException>(() => CstpFraming.Decode(new byte[] { 0x53, 0x54, 0x46 }));
        }

        [Fact]
        public void Streaming_ThrowsOnCorruptHeaderMagic()
        {
            var framing = new CstpFraming();
            framing.Append(new byte[] { 0xFF, 0x54, 0x46, 0x01, 0x00, 0x00, 0x00, 0x00 });
            Assert.Throws<FormatException>(() => framing.TryReadPacket(out _));
        }

        static byte[] Concat(params byte[][] parts)
        {
            var list = new List<byte>();
            foreach (byte[] p in parts) list.AddRange(p);
            return list.ToArray();
        }
    }
}
