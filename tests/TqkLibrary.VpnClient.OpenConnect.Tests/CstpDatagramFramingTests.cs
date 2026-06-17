using System;
using TqkLibrary.VpnClient.OpenConnect;
using TqkLibrary.VpnClient.OpenConnect.Enums;
using TqkLibrary.VpnClient.OpenConnect.Models;
using Xunit;

namespace TqkLibrary.VpnClient.OpenConnect.Tests
{
    /// <summary>
    /// Tests the CSTP-over-DTLS datagram framing codec (V5.c): the 1-byte type header (no STF magic, no length prefix),
    /// round-trip for every packet type, and rejection of an empty datagram.
    /// </summary>
    public class CstpDatagramFramingTests
    {
        [Theory]
        [InlineData(CstpPacketType.Data)]
        [InlineData(CstpPacketType.DpdRequest)]
        [InlineData(CstpPacketType.DpdResponse)]
        [InlineData(CstpPacketType.Disconnect)]
        [InlineData(CstpPacketType.KeepAlive)]
        [InlineData(CstpPacketType.Terminate)]
        public void Encode_then_Decode_round_trips(CstpPacketType type)
        {
            byte[] payload = type == CstpPacketType.Data ? new byte[] { 1, 2, 3, 4, 5 } : Array.Empty<byte>();
            byte[] datagram = CstpDatagramFraming.Encode(type, payload);

            Assert.Equal(CstpDatagramFraming.HeaderSize + payload.Length, datagram.Length);
            Assert.Equal((byte)type, datagram[0]); // the single header byte is the packet type

            CstpPacket decoded = CstpDatagramFraming.Decode(datagram);
            Assert.Equal(type, decoded.Type);
            Assert.Equal(payload, decoded.Payload);
        }

        [Fact]
        public void Decode_empty_datagram_throws()
        {
            Assert.Throws<FormatException>(() => CstpDatagramFraming.Decode(ReadOnlySpan<byte>.Empty));
        }

        [Fact]
        public void Data_payload_is_the_rest_of_the_datagram()
        {
            byte[] ip = new byte[] { 0x45, 0x00, 0x00, 0x14, 0xde, 0xad };
            byte[] datagram = CstpDatagramFraming.Encode(CstpPacketType.Data, ip);
            CstpPacket decoded = CstpDatagramFraming.Decode(datagram);
            Assert.Equal(CstpPacketType.Data, decoded.Type);
            Assert.Equal(ip, decoded.Payload);
        }
    }
}
