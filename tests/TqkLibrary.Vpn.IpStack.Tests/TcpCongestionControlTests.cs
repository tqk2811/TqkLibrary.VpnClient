using System.Linq;
using System.Net;
using TqkLibrary.Vpn.IpStack;
using TqkLibrary.Vpn.IpStack.Tcp;
using TqkLibrary.Vpn.IpStack.Tcp.Enums;
using Xunit;

namespace TqkLibrary.Vpn.IpStack.Tests
{
    /// <summary>
    /// TCP congestion control (RFC 5681 + NewReno RFC 6582): the send rate is bounded by a congestion window that
    /// starts at the RFC 6928 initial window, grows in slow start, and reacts to loss via 3-duplicate-ACK fast
    /// retransmit + fast recovery. Driven entirely by injected ACKs (no real timers).
    /// </summary>
    public class TcpCongestionControlTests
    {
        static readonly IPAddress ClientIp = IPAddress.Parse("10.0.0.1");
        static readonly IPAddress ServerIp = IPAddress.Parse("8.8.8.8");
        const ushort ClientPort = 50000, ServerPort = 80;
        const int InitialWindow = 13600; // RFC 6928: min(10·1360, max(2·1360, 14600)) for MSS 1360

        [Fact]
        public void SlowStart_FirstBurstIsInitialWindow_ThenGrows()
        {
            var sent = new List<byte[]>();
            using var conn = new TcpConnection(ClientIp, ClientPort, ServerIp, ServerPort, sent.Add, linkMtu: 1400);
            uint iss = Handshake(conn, sent, window: 65535); // ample flow-control window so cwnd is the binding limit

            conn.Send(new byte[400000]);
            List<byte[]> burst1 = Drain(sent);
            Assert.Equal(InitialWindow, burst1.Sum(PayloadLength)); // congestion window, not the 65535 flow window, caps it

            uint ack = iss + 1;
            AckEach(conn, burst1, ref ack, window: 65535); // one ACK per segment → slow start opens cwnd ~exponentially
            Assert.True(Drain(sent).Sum(PayloadLength) > InitialWindow, "slow start should enlarge the congestion window");
        }

        [Fact]
        public void ThreeDuplicateAcks_TriggerFastRetransmit_WithoutWaitingForRto()
        {
            var sent = new List<byte[]>();
            using var conn = new TcpConnection(ClientIp, ClientPort, ServerIp, ServerPort, sent.Add, linkMtu: 1400);
            uint iss = Handshake(conn, sent, window: 65535);

            conn.Send(new byte[400000]);
            List<byte[]> burst = Drain(sent);
            uint lostSeq = Seq(burst[0]);          // the oldest unacked segment (== _sndUna)
            Assert.True(burst.Count >= 3);

            for (int i = 0; i < 3; i++)            // 3 duplicate ACKs: ack frozen, window unchanged, no data
                conn.OnSegment(Peer(seq: 9001, ack: lostSeq, TcpFlags.Ack, window: 65535));

            Assert.Contains(sent, ip => Seq(ip) == lostSeq && PayloadLength(ip) > 0); // lost segment resent at once
        }

        [Fact]
        public void FastRecovery_FurtherDuplicateAcks_InflateWindowAndSendNewData()
        {
            var sent = new List<byte[]>();
            using var conn = new TcpConnection(ClientIp, ClientPort, ServerIp, ServerPort, sent.Add, linkMtu: 1400);
            uint iss = Handshake(conn, sent, window: 65535);

            conn.Send(new byte[400000]);
            uint una = Seq(Drain(sent)[0]);        // _sndUna; InitialWindow bytes now in flight
            uint nextNew = una + InitialWindow;    // first byte not yet sent (_sndNxt)

            for (int i = 0; i < 3; i++)            // enter fast recovery (cwnd = ssthresh + 3·MSS) + fast retransmit
                conn.OnSegment(Peer(seq: 9001, ack: una, TcpFlags.Ack, window: 65535));
            Drain(sent);                           // discard the fast retransmit

            for (int i = 0; i < 4; i++)            // each further dup ACK inflates cwnd; once it passes flight, new data flows
                conn.OnSegment(Peer(seq: 9001, ack: una, TcpFlags.Ack, window: 65535));

            Assert.Contains(sent, ip => Seq(ip) == nextNew && PayloadLength(ip) > 0); // a brand-new segment was emitted
        }

        static uint Handshake(TcpConnection conn, List<byte[]> sent, ushort window)
        {
            conn.StartConnect();
            uint clientIss = Seq(sent[0]);
            sent.Clear();
            conn.OnSegment(Peer(seq: 9000, ack: clientIss + 1, TcpFlags.Syn | TcpFlags.Ack, window, mss: 1360));
            sent.Clear(); // drop the client's handshake ACK
            return clientIss;
        }

        static void AckEach(TcpConnection conn, List<byte[]> segments, ref uint ackNo, ushort window)
        {
            foreach (byte[] ip in segments)
            {
                ackNo += (uint)PayloadLength(ip);
                conn.OnSegment(Peer(seq: 9001, ack: ackNo, TcpFlags.Ack, window));
            }
        }

        static List<byte[]> Drain(List<byte[]> sent)
        {
            List<byte[]> copy = sent.ToList();
            sent.Clear();
            return copy;
        }

        static uint Seq(byte[] ip) => TcpSegment.Sequence(Ipv4.Payload(ip).Span);

        static int PayloadLength(byte[] ip)
        {
            ReadOnlyMemory<byte> tcp = Ipv4.Payload(ip);
            return tcp.Length - TcpSegment.DataOffset(tcp.Span);
        }

        static byte[] Peer(uint seq, uint ack, TcpFlags flags, ushort window, ushort mss = 0)
            => TcpSegment.Build(ServerIp, ClientIp, ServerPort, ClientPort, seq, ack, flags, window, ReadOnlySpan<byte>.Empty, mss);
    }
}
