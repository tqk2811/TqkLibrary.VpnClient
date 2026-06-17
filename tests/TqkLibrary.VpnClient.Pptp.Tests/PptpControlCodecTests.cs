using System;
using TqkLibrary.VpnClient.Pptp;
using TqkLibrary.VpnClient.Pptp.Enums;
using TqkLibrary.VpnClient.Pptp.Interfaces;
using TqkLibrary.VpnClient.Pptp.Models;
using Xunit;

namespace TqkLibrary.VpnClient.Pptp.Tests
{
    /// <summary>
    /// Round-trip + wire-shape tests for the PPTP control-message codec (RFC 2637 §2): every control message
    /// encodes to the documented length, carries the magic cookie, and decodes back to equal field values.
    /// </summary>
    public class PptpControlCodecTests
    {
        [Fact]
        public void Sccrq_RoundTrips_And_Is_156_Bytes()
        {
            var msg = new StartControlConnectionRequest
            {
                ProtocolVersion = 0x0100,
                FramingCapabilities = PptpFramingCapability.Asynchronous | PptpFramingCapability.Synchronous,
                BearerCapabilities = PptpBearerCapability.Digital,
                MaximumChannels = 4,
                FirmwareRevision = 0x0203,
                HostName = "client-host",
                VendorName = "TqkLibrary.VpnClient",
            };

            byte[] wire = PptpControlCodec.Encode(msg);

            Assert.Equal(156, wire.Length);                     // 12 header + 144 body (RFC 2637 §2.1)
            Assert.Equal(156, (wire[0] << 8) | wire[1]);        // Length field (big-endian)
            Assert.Equal((ushort)PptpMessageType.Control, (ushort)((wire[2] << 8) | wire[3]));
            Assert.Equal(PptpControlHeader.MagicCookie, (uint)((wire[4] << 24) | (wire[5] << 16) | (wire[6] << 8) | wire[7]));
            Assert.Equal((ushort)PptpControlMessageType.StartControlConnectionRequest, (ushort)((wire[8] << 8) | wire[9]));

            var back = (StartControlConnectionRequest)PptpControlCodec.Decode(wire);
            Assert.Equal(msg.ProtocolVersion, back.ProtocolVersion);
            Assert.Equal(msg.FramingCapabilities, back.FramingCapabilities);
            Assert.Equal(msg.BearerCapabilities, back.BearerCapabilities);
            Assert.Equal(msg.MaximumChannels, back.MaximumChannels);
            Assert.Equal(msg.FirmwareRevision, back.FirmwareRevision);
            Assert.Equal(msg.HostName, back.HostName);
            Assert.Equal(msg.VendorName, back.VendorName);
        }

        [Fact]
        public void Sccrp_RoundTrips_With_ResultCode()
        {
            var msg = new StartControlConnectionReply
            {
                ProtocolVersion = 0x0100,
                ResultCode = PptpResultCode.Successful,
                ErrorCode = 0,
                FramingCapabilities = PptpFramingCapability.Synchronous,
                BearerCapabilities = PptpBearerCapability.Analog | PptpBearerCapability.Digital,
                MaximumChannels = 100,
                FirmwareRevision = 1,
                HostName = "pptp-server",
                VendorName = "linux",
            };

            byte[] wire = PptpControlCodec.Encode(msg);
            Assert.Equal(156, wire.Length);

            var back = (StartControlConnectionReply)PptpControlCodec.Decode(wire);
            Assert.Equal(msg.ResultCode, back.ResultCode);
            Assert.Equal(msg.FramingCapabilities, back.FramingCapabilities);
            Assert.Equal(msg.BearerCapabilities, back.BearerCapabilities);
            Assert.Equal(msg.MaximumChannels, back.MaximumChannels);
            Assert.Equal(msg.HostName, back.HostName);
            Assert.Equal(msg.VendorName, back.VendorName);
        }

        [Fact]
        public void Ocrq_RoundTrips_And_Is_168_Bytes()
        {
            var msg = new OutgoingCallRequest
            {
                CallId = 0x1234,
                CallSerialNumber = 0x5678,
                MinBps = 2400,
                MaxBps = 10000000,
                BearerType = 3,
                FramingType = 3,
                PacketRecvWindowSize = 64,
                PacketProcessingDelay = 0,
                PhoneNumber = "",
                Subaddress = "",
            };

            byte[] wire = PptpControlCodec.Encode(msg);
            Assert.Equal(168, wire.Length);                     // 12 header + 156 body (RFC 2637 §2.7)

            var back = (OutgoingCallRequest)PptpControlCodec.Decode(wire);
            Assert.Equal(msg.CallId, back.CallId);
            Assert.Equal(msg.CallSerialNumber, back.CallSerialNumber);
            Assert.Equal(msg.MinBps, back.MinBps);
            Assert.Equal(msg.MaxBps, back.MaxBps);
            Assert.Equal(msg.BearerType, back.BearerType);
            Assert.Equal(msg.FramingType, back.FramingType);
            Assert.Equal(msg.PacketRecvWindowSize, back.PacketRecvWindowSize);
        }

        [Fact]
        public void Ocrp_RoundTrips_And_Is_32_Bytes()
        {
            var msg = new OutgoingCallReply
            {
                CallId = 0xABCD,
                PeerCallId = 0x1234,
                ResultCode = PptpResultCode.Successful,
                ErrorCode = 0,
                CauseCode = 0,
                ConnectSpeed = 100000,
                PacketRecvWindowSize = 32,
                PacketProcessingDelay = 0,
                PhysicalChannelId = 0xDEADBEEF,
            };

            byte[] wire = PptpControlCodec.Encode(msg);
            Assert.Equal(32, wire.Length);                      // 12 header + 20 body (RFC 2637 §2.8)

            var back = (OutgoingCallReply)PptpControlCodec.Decode(wire);
            Assert.Equal(msg.CallId, back.CallId);
            Assert.Equal(msg.PeerCallId, back.PeerCallId);
            Assert.Equal(msg.ResultCode, back.ResultCode);
            Assert.Equal(msg.ConnectSpeed, back.ConnectSpeed);
            Assert.Equal(msg.PacketRecvWindowSize, back.PacketRecvWindowSize);
            Assert.Equal(msg.PhysicalChannelId, back.PhysicalChannelId);
        }

        [Fact]
        public void Echo_Request_And_Reply_RoundTrip()
        {
            var req = new EchoRequest { Identifier = 0x01020304 };
            byte[] reqWire = PptpControlCodec.Encode(req);
            Assert.Equal(16, reqWire.Length);                   // 12 header + 4 body (RFC 2637 §2.5)
            var reqBack = (EchoRequest)PptpControlCodec.Decode(reqWire);
            Assert.Equal(req.Identifier, reqBack.Identifier);

            var reply = new EchoReply { Identifier = 0x01020304, ResultCode = PptpResultCode.Successful };
            byte[] replyWire = PptpControlCodec.Encode(reply);
            Assert.Equal(20, replyWire.Length);                 // 12 header + 8 body (RFC 2637 §2.6)
            var replyBack = (EchoReply)PptpControlCodec.Decode(replyWire);
            Assert.Equal(reply.Identifier, replyBack.Identifier);
            Assert.Equal(reply.ResultCode, replyBack.ResultCode);
        }

        [Fact]
        public void SetLinkInfo_RoundTrips_And_Is_24_Bytes()
        {
            var msg = new SetLinkInfo { PeerCallId = 0x4242, SendAccm = 0x000A0000, ReceiveAccm = 0xFFFFFFFF };
            byte[] wire = PptpControlCodec.Encode(msg);
            Assert.Equal(24, wire.Length);                      // 12 header + 12 body (RFC 2637 §2.15)

            var back = (SetLinkInfo)PptpControlCodec.Decode(wire);
            Assert.Equal(msg.PeerCallId, back.PeerCallId);
            Assert.Equal(msg.SendAccm, back.SendAccm);
            Assert.Equal(msg.ReceiveAccm, back.ReceiveAccm);
        }

        [Fact]
        public void CallClearRequest_RoundTrips_And_Is_16_Bytes()
        {
            var msg = new CallClearRequest { CallId = 0x00FF };
            byte[] wire = PptpControlCodec.Encode(msg);
            Assert.Equal(16, wire.Length);                      // 12 header + 4 body (RFC 2637 §2.12)
            var back = (CallClearRequest)PptpControlCodec.Decode(wire);
            Assert.Equal(msg.CallId, back.CallId);
        }

        [Fact]
        public void CallDisconnectNotify_RoundTrips_And_Is_148_Bytes()
        {
            var msg = new CallDisconnectNotify
            {
                CallId = 0x0001,
                ResultCode = (PptpResultCode)4, // 4 = "request"
                ErrorCode = 0,
                CauseCode = 0,
                CallStatistics = "tx=10 rx=20",
            };
            byte[] wire = PptpControlCodec.Encode(msg);
            Assert.Equal(148, wire.Length);                     // 12 header + 136 body (RFC 2637 §2.13)
            var back = (CallDisconnectNotify)PptpControlCodec.Decode(wire);
            Assert.Equal(msg.CallId, back.CallId);
            Assert.Equal(msg.ResultCode, back.ResultCode);
            Assert.Equal(msg.CallStatistics, back.CallStatistics);
        }

        [Fact]
        public void StopControlConnection_Request_And_Reply_RoundTrip()
        {
            var req = new StopControlConnectionRequest { Reason = 1 };
            byte[] reqWire = PptpControlCodec.Encode(req);
            Assert.Equal(16, reqWire.Length);
            Assert.Equal(req.Reason, ((StopControlConnectionRequest)PptpControlCodec.Decode(reqWire)).Reason);

            var reply = new StopControlConnectionReply { ResultCode = PptpResultCode.Successful };
            byte[] replyWire = PptpControlCodec.Encode(reply);
            Assert.Equal(16, replyWire.Length);
            Assert.Equal(reply.ResultCode, ((StopControlConnectionReply)PptpControlCodec.Decode(replyWire)).ResultCode);
        }

        [Fact]
        public void Decode_Rejects_Bad_Magic_Cookie()
        {
            byte[] wire = PptpControlCodec.Encode(new EchoRequest { Identifier = 1 });
            wire[4] ^= 0xFF; // corrupt the magic cookie
            Assert.Throws<FormatException>(() => PptpControlCodec.Decode(wire));
        }

        [Fact]
        public void Decode_Rejects_Length_Mismatch()
        {
            byte[] wire = PptpControlCodec.Encode(new EchoRequest { Identifier = 1 });
            byte[] truncated = new byte[wire.Length - 1];
            Array.Copy(wire, truncated, truncated.Length);
            Assert.Throws<FormatException>(() => PptpControlCodec.Decode(truncated));
        }

        [Fact]
        public void HostName_Longer_Than_Field_Is_Truncated_To_64()
        {
            var msg = new StartControlConnectionRequest { HostName = new string('a', 100) };
            byte[] wire = PptpControlCodec.Encode(msg);
            var back = (StartControlConnectionRequest)PptpControlCodec.Decode(wire);
            Assert.Equal(64, back.HostName.Length); // field is exactly 64 bytes, no NUL terminator inside → full 64 chars
        }

        [Fact]
        public void Reassembler_Reconstructs_Messages_Across_Read_Boundaries()
        {
            byte[] a = PptpControlCodec.Encode(new StartControlConnectionReply { HostName = "srv" });
            byte[] b = PptpControlCodec.Encode(new EchoRequest { Identifier = 7 });
            byte[] c = PptpControlCodec.Encode(new OutgoingCallReply { CallId = 5, PeerCallId = 9, ResultCode = PptpResultCode.Successful });

            // Concatenate the three packets then feed them in awkward 5-byte chunks.
            byte[] stream = new byte[a.Length + b.Length + c.Length];
            Buffer.BlockCopy(a, 0, stream, 0, a.Length);
            Buffer.BlockCopy(b, 0, stream, a.Length, b.Length);
            Buffer.BlockCopy(c, 0, stream, a.Length + b.Length, c.Length);

            var codec = new PptpControlCodec();
            var decoded = new System.Collections.Generic.List<IPptpControlMessage>();
            for (int i = 0; i < stream.Length; i += 5)
            {
                int n = Math.Min(5, stream.Length - i);
                codec.Append(stream.AsSpan(i, n));
                while (codec.TryReadMessage(out IPptpControlMessage m)) decoded.Add(m);
            }

            Assert.Equal(3, decoded.Count);
            Assert.IsType<StartControlConnectionReply>(decoded[0]);
            Assert.IsType<EchoRequest>(decoded[1]);
            Assert.IsType<OutgoingCallReply>(decoded[2]);
            Assert.Equal(7u, ((EchoRequest)decoded[1]).Identifier);
            Assert.Equal((ushort)9, ((OutgoingCallReply)decoded[2]).PeerCallId);
        }
    }
}
