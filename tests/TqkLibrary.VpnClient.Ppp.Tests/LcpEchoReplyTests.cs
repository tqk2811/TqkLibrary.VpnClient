using System.Linq;
using TqkLibrary.VpnClient.Ppp;
using TqkLibrary.VpnClient.Ppp.Enums;
using TqkLibrary.VpnClient.Ppp.Models;
using Xunit;

namespace TqkLibrary.VpnClient.Ppp.Tests
{
    /// <summary>
    /// The LCP layer must answer the peer's Echo-Request (its link keepalive, RFC 1661 §5.8) with an Echo-Reply
    /// carrying our Magic-Number. A gateway probing liveness (e.g. pppd lcp-echo-interval/lcp-echo-failure) otherwise
    /// sees no reply and tears the L2TP/PPP session down after a couple of minutes (observed live as a ~126s reconnect).
    /// </summary>
    public class LcpEchoReplyTests
    {
        [Fact]
        public void EchoRequest_IsAnsweredWithEchoReply_CarryingOurMagic()
        {
            const uint magic = 0x12345678;
            var sent = new List<byte[]>();
            using var lcp = new LcpNegotiator(p => sent.Add(p), magic);

            // Peer (server) Echo-Request: identifier 0x42, data = the peer's own magic (echoed back is not required).
            byte[] peerMagic = { 0xAA, 0xBB, 0xCC, 0xDD };
            lcp.HandlePacket(PppControlCodec.Build((byte)PppCode.EchoRequest, 0x42, peerMagic));

            byte[]? reply = sent.SingleOrDefault(p => p.Length >= 1 && p[0] == (byte)PppCode.EchoReply);
            Assert.NotNull(reply);
            PppControlPacket parsed = PppControlCodec.Parse(reply!);
            Assert.Equal((byte)PppCode.EchoReply, parsed.Code);
            Assert.Equal(0x42, parsed.Identifier);                              // identifier copied from the request
            Assert.Equal(new byte[] { 0x12, 0x34, 0x56, 0x78 }, parsed.Data);   // our Magic-Number, big-endian
        }

        [Fact]
        public void EchoReply_FromPeer_IsIgnored_NoResponse()
        {
            const uint magic = 0x12345678;
            var sent = new List<byte[]>();
            using var lcp = new LcpNegotiator(p => sent.Add(p), magic);

            // An inbound Echo-Reply (and any other non-Configure code we do not handle) needs no response.
            lcp.HandlePacket(PppControlCodec.Build((byte)PppCode.EchoReply, 0x07, new byte[] { 1, 2, 3, 4 }));

            Assert.Empty(sent);
        }
    }
}
