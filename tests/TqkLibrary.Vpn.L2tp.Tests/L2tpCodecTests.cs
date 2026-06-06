using TqkLibrary.Vpn.L2tp;
using TqkLibrary.Vpn.L2tp.Enums;
using TqkLibrary.Vpn.L2tp.Models;
using Xunit;

namespace TqkLibrary.Vpn.L2tp.Tests
{
    public class L2tpCodecTests
    {
        [Fact]
        public void Sccrq_RoundTrips_WithAvps()
        {
            var message = L2tpControlMessage.Create(L2tpMessageType.StartControlConnectionRequest, tunnelId: 0)
                .With(L2tpAvp.UInt16(L2tpAvpType.ProtocolVersion, 0x0100))
                .With(L2tpAvp.UInt32(L2tpAvpType.FramingCapabilities, 3))
                .With(L2tpAvp.Text(L2tpAvpType.HostName, "anonymous"))
                .With(L2tpAvp.UInt16(L2tpAvpType.AssignedTunnelId, 0x1234))
                .With(L2tpAvp.UInt16(L2tpAvpType.ReceiveWindowSize, 4));
            message.Ns = 0;
            message.Nr = 0;

            byte[] wire = L2tpCodec.EncodeControl(message);
            Assert.True(L2tpCodec.IsControl(wire));

            L2tpControlMessage decoded = L2tpCodec.DecodeControl(wire);
            Assert.Equal(L2tpMessageType.StartControlConnectionRequest, decoded.MessageType);
            Assert.Equal(0x0100, decoded.Find(L2tpAvpType.ProtocolVersion)!.AsUInt16());
            Assert.Equal(3u, decoded.Find(L2tpAvpType.FramingCapabilities)!.AsUInt32());
            Assert.Equal("anonymous", System.Text.Encoding.ASCII.GetString(decoded.Find(L2tpAvpType.HostName)!.Value));
            Assert.Equal(0x1234, decoded.Find(L2tpAvpType.AssignedTunnelId)!.AsUInt16());
        }

        [Fact]
        public void Control_HeaderFields_RoundTrip()
        {
            var message = L2tpControlMessage.Create(L2tpMessageType.IncomingCallRequest, tunnelId: 0xBEEF);
            message.SessionId = 0xCAFE;
            message.Ns = 7;
            message.Nr = 3;

            L2tpControlMessage decoded = L2tpCodec.DecodeControl(L2tpCodec.EncodeControl(message));
            Assert.Equal(0xBEEF, decoded.TunnelId);
            Assert.Equal(0xCAFE, decoded.SessionId);
            Assert.Equal(7, decoded.Ns);
            Assert.Equal(3, decoded.Nr);
        }

        [Fact]
        public void ZeroLengthBody_HasNoAvps()
        {
            var ack = L2tpControlMessage.Ack(tunnelId: 0x20);
            ack.Nr = 5;

            byte[] wire = L2tpCodec.EncodeControl(ack);
            L2tpControlMessage decoded = L2tpCodec.DecodeControl(wire);

            Assert.True(decoded.IsZeroLengthBody);
            Assert.Empty(decoded.Avps);
            Assert.Equal(5, decoded.Nr);
            Assert.Equal(0x20, decoded.TunnelId);
        }

        [Fact]
        public void Data_Framing_RoundTrips()
        {
            byte[] ppp = { 0xFF, 0x03, 0x00, 0x21, 0x45, 0x00, 0x00, 0x28 }; // ACFC + IP protocol + IP header start
            byte[] wire = L2tpCodec.EncodeData(tunnelId: 0x11, sessionId: 0x22, ppp);

            Assert.False(L2tpCodec.IsControl(wire));
            Assert.True(L2tpCodec.TryDecodeData(wire, out ushort tunnelId, out ushort sessionId, out byte[] frame));
            Assert.Equal(0x11, tunnelId);
            Assert.Equal(0x22, sessionId);
            Assert.Equal(ppp, frame);
        }

        [Fact]
        public void Avp_MandatoryFlag_IsPreserved()
        {
            byte[] wire = L2tpCodec.EncodeControl(
                L2tpControlMessage.Create(L2tpMessageType.Hello, 1).With(L2tpAvp.Text(L2tpAvpType.VendorName, "tqk", mandatory: false)));
            L2tpAvp vendor = L2tpCodec.DecodeControl(wire).Find(L2tpAvpType.VendorName)!;
            Assert.False(vendor.Mandatory);
        }
    }
}
