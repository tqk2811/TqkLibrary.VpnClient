using System.Linq;
using System.Net;
using TqkLibrary.Vpn.IpStack;
using TqkLibrary.Vpn.IpStack.Tcp;
using TqkLibrary.Vpn.IpStack.Tcp.Enums;
using Xunit;

namespace TqkLibrary.Vpn.IpStack.Tests
{
    /// <summary>
    /// TCP window scaling (RFC 7323): the SYN carries a Window Scale option, and once the peer also offers one its
    /// advertised window is shifted up — letting more than 64 KB ride in flight on the send path.
    /// </summary>
    public class TcpWindowScalingTests
    {
        static readonly IPAddress ClientIp = IPAddress.Parse("10.0.0.1");
        static readonly IPAddress ServerIp = IPAddress.Parse("8.8.8.8");
        const ushort ClientPort = 50000, ServerPort = 80;

        [Fact]
        public void Syn_AdvertisesWindowScaleAndMssOptions()
        {
            var sent = new List<byte[]>();
            using var conn = new TcpConnection(ClientIp, ClientPort, ServerIp, ServerPort, sent.Add, linkMtu: 1400);
            conn.StartConnect();

            ReadOnlySpan<byte> syn = Ipv4.Payload(Assert.Single(sent)).Span;
            Assert.Equal((byte)2, TcpSegment.WindowScale(syn));        // RcvWScale = 2
            Assert.Equal((ushort)1360, TcpSegment.MaxSegmentSize(syn)); // MSS option still present alongside WS
        }

        [Fact]
        public void PeerWindowScale_RaisesSendWindowAbove16Bit()
        {
            var sent = new List<byte[]>();
            using var conn = new TcpConnection(ClientIp, ClientPort, ServerIp, ServerPort, sent.Add, linkMtu: 1400);
            uint clientIss = DoHandshake(conn, sent, peerWindowScale: 4); // peer scales its window by ×16 → 5000 ≡ 80000

            // Congestion control caps the first burst at the initial cwnd (≪ 64 KB). Drive send/ACK rounds — ACKing
            // each segment so slow start opens cwnd — until a burst plateaus at the peer's (scaled) window. That a burst
            // reaches 80000 (5000 ≪ 4) proves the negotiated send window exceeds the 65535 unscaled ceiling.
            conn.Send(new byte[400000]);
            uint ackNo = clientIss + 1;
            int maxBurst = 0;
            for (int round = 0; round < 12; round++)
            {
                List<byte[]> burst = sent.ToList();
                sent.Clear();
                int burstBytes = burst.Sum(PayloadLength);
                if (burstBytes == 0) break;
                maxBurst = Math.Max(maxBurst, burstBytes);
                foreach (byte[] ip in burst) // one cumulative ACK per segment → slow start grows cwnd by ~1 MSS each
                {
                    ackNo += (uint)PayloadLength(ip);
                    conn.OnSegment(Peer(seq: 9001, ack: ackNo, TcpFlags.Ack, window: 5000));
                }
            }
            Assert.Equal(80000, maxBurst); // send window capped at the scaled 80000, well above the 64 KB ceiling
        }

        [Fact]
        public void NoPeerWindowScale_SendWindowStaysUnscaled()
        {
            var sent = new List<byte[]>();
            using var conn = new TcpConnection(ClientIp, ClientPort, ServerIp, ServerPort, sent.Add, linkMtu: 1400);
            // Peer omits the Window Scale option → scaling disabled both ways (RFC 7323), backward-compatible.
            uint clientIss = DoHandshake(conn, sent, peerWindowScale: TcpSegment.NoWindowScale);

            conn.OnSegment(Peer(seq: 9001, ack: clientIss + 1, TcpFlags.Ack, window: 5000));
            sent.Clear();

            conn.Send(new byte[100000]);
            Assert.Equal(5000, sent.Sum(PayloadLength)); // window field used as-is, no shift
        }

        [Fact]
        public void WindowScale_ParsesOption_AndReturnsSentinelWhenAbsent()
        {
            byte[] withWs = TcpSegment.Build(ClientIp, ServerIp, 1, 2, 0, 0, TcpFlags.Syn, 65535, ReadOnlySpan<byte>.Empty, mss: 1460, windowScale: 7);
            Assert.Equal((byte)7, TcpSegment.WindowScale(withWs));
            Assert.Equal((ushort)1460, TcpSegment.MaxSegmentSize(withWs)); // coexists with the MSS option

            byte[] noWs = TcpSegment.Build(ClientIp, ServerIp, 1, 2, 0, 0, TcpFlags.Ack, 65535, ReadOnlySpan<byte>.Empty);
            Assert.Equal(TcpSegment.NoWindowScale, TcpSegment.WindowScale(noWs));
        }

        // Drives StartConnect → SYN-ACK and returns the client's ISS, leaving the connection Established and `sent` empty.
        static uint DoHandshake(TcpConnection conn, List<byte[]> sent, byte peerWindowScale, ushort synAckWindow = 1)
        {
            conn.StartConnect();
            uint clientIss = TcpSegment.Sequence(Ipv4.Payload(sent[0]).Span);
            sent.Clear();
            conn.OnSegment(Peer(seq: 9000, ack: clientIss + 1, TcpFlags.Syn | TcpFlags.Ack, synAckWindow, mss: 1360, windowScale: peerWindowScale));
            sent.Clear(); // drop the client's handshake ACK
            return clientIss;
        }

        static int PayloadLength(byte[] ip)
        {
            ReadOnlyMemory<byte> tcp = Ipv4.Payload(ip);
            return tcp.Length - TcpSegment.DataOffset(tcp.Span);
        }

        static byte[] Peer(uint seq, uint ack, TcpFlags flags, ushort window, ushort mss = 0, byte windowScale = TcpSegment.NoWindowScale)
            => TcpSegment.Build(ServerIp, ClientIp, ServerPort, ClientPort, seq, ack, flags, window, ReadOnlySpan<byte>.Empty, mss, windowScale);
    }
}
