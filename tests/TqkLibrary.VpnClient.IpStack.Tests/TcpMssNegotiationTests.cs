using System.Net;
using TqkLibrary.VpnClient.IpStack;
using TqkLibrary.VpnClient.IpStack.Tcp;
using TqkLibrary.VpnClient.IpStack.Tcp.Enums;
using Xunit;

namespace TqkLibrary.VpnClient.IpStack.Tests
{
    /// <summary>
    /// The TCP send MSS is derived from the link MTU (no longer a hard-coded 1360) and clamped to the peer's
    /// advertised MSS, so segments always fit the path and never have to be fragmented by <c>SendIp</c>.
    /// </summary>
    public class TcpMssNegotiationTests
    {
        static readonly IPAddress ClientIp = IPAddress.Parse("10.0.0.1");
        static readonly IPAddress ServerIp = IPAddress.Parse("8.8.8.8");
        const ushort ClientPort = 50000, ServerPort = 80;

        [Fact]
        public void Syn_AdvertisesMss_DerivedFromLinkMtu()
        {
            var sent = new List<byte[]>();
            using var conn = new TcpConnection(ClientIp, ClientPort, ServerIp, ServerPort, sent.Add, linkMtu: 600);
            conn.StartConnect();

            byte[] synIp = Assert.Single(sent);
            ReadOnlySpan<byte> syn = Ipv4.Payload(synIp).Span;
            Assert.True((TcpSegment.Flags(syn) & TcpFlags.Syn) != 0);
            Assert.Equal((ushort)560, TcpSegment.MaxSegmentSize(syn)); // 600 − 20 (IP) − 20 (TCP)
        }

        [Fact]
        public void DefaultLinkMtu_StillAdvertises1360()
        {
            var sent = new List<byte[]>();
            using var conn = new TcpConnection(ClientIp, ClientPort, ServerIp, ServerPort, sent.Add); // default MTU 1400
            conn.StartConnect();

            Assert.Equal((ushort)1360, TcpSegment.MaxSegmentSize(Ipv4.Payload(sent[0]).Span));
        }

        [Fact]
        public void SendSegments_AreCappedByPeerAdvertisedMss()
        {
            var sent = new List<byte[]>();
            using var conn = new TcpConnection(ClientIp, ClientPort, ServerIp, ServerPort, sent.Add, linkMtu: 1400); // localMss 1360
            conn.StartConnect();
            uint clientIss = TcpSegment.Sequence(Ipv4.Payload(sent[0]).Span);
            sent.Clear();

            // Peer's SYN-ACK advertises a smaller MSS (500) with a generous window.
            conn.OnSegment(BuildSegment(serverSeq: 9000, ack: clientIss + 1, TcpFlags.Syn | TcpFlags.Ack, window: 65535, mss: 500));
            sent.Clear(); // drop the client's handshake ACK

            conn.Enqueue(new byte[2000]);

            // Every data segment must fit the negotiated MSS (min(1360, 500) = 500); at least one rides right at it.
            Assert.NotEmpty(sent);
            foreach (byte[] ip in sent)
                Assert.True(PayloadLength(ip) <= 500, $"segment payload {PayloadLength(ip)} exceeds negotiated MSS 500");
            Assert.Contains(sent, ip => PayloadLength(ip) == 500);
        }

        [Fact]
        public void NoPeerMssOption_FallsBackTo536()
        {
            var sent = new List<byte[]>();
            using var conn = new TcpConnection(ClientIp, ClientPort, ServerIp, ServerPort, sent.Add, linkMtu: 1400); // localMss 1360
            conn.StartConnect();
            uint clientIss = TcpSegment.Sequence(Ipv4.Payload(sent[0]).Span);
            sent.Clear();

            // SYN-ACK without an MSS option → RFC 1122 says assume a 536-byte send MSS.
            conn.OnSegment(BuildSegment(serverSeq: 9000, ack: clientIss + 1, TcpFlags.Syn | TcpFlags.Ack, window: 65535));
            sent.Clear();

            conn.Enqueue(new byte[2000]);

            Assert.NotEmpty(sent);
            foreach (byte[] ip in sent)
                Assert.True(PayloadLength(ip) <= 536, $"segment payload {PayloadLength(ip)} exceeds assumed MSS 536");
            Assert.Contains(sent, ip => PayloadLength(ip) == 536);
        }

        [Fact]
        public void MaxSegmentSize_ParsesOption_AndReturnsZeroWhenAbsent()
        {
            byte[] withMss = TcpSegment.Build(ClientIp, ServerIp, 1, 2, 0, 0, TcpFlags.Syn, 65535, ReadOnlySpan<byte>.Empty, mss: 1460);
            Assert.Equal((ushort)1460, TcpSegment.MaxSegmentSize(withMss));

            byte[] noOption = TcpSegment.Build(ClientIp, ServerIp, 1, 2, 0, 0, TcpFlags.Ack, 65535, ReadOnlySpan<byte>.Empty);
            Assert.Equal((ushort)0, TcpSegment.MaxSegmentSize(noOption));
        }

        static int PayloadLength(byte[] ip)
        {
            ReadOnlyMemory<byte> tcp = Ipv4.Payload(ip);
            return tcp.Length - TcpSegment.DataOffset(tcp.Span);
        }

        static byte[] BuildSegment(uint serverSeq, uint ack, TcpFlags flags, ushort window, ushort mss = 0)
            => TcpSegment.Build(ServerIp, ClientIp, ServerPort, ClientPort, serverSeq, ack, flags, window, ReadOnlySpan<byte>.Empty, mss);
    }
}
