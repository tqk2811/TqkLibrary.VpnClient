using System.Linq;
using System.Net;
using TqkLibrary.Vpn.IpStack;
using TqkLibrary.Vpn.IpStack.Tcp;
using TqkLibrary.Vpn.IpStack.Tcp.Enums;
using Xunit;

namespace TqkLibrary.Vpn.IpStack.Tests
{
    /// <summary>
    /// Selective Acknowledgment (RFC 2018 / 6675): SACK-Permitted is negotiated on the SYN exchange, the receive path
    /// reports buffered out-of-order blocks, and the send path retransmits only the missing holes (not NewReno
    /// go-back-from-the-first-hole) while the SACKed segments stay put. Driven entirely by injected ACKs (no timers).
    /// </summary>
    public class TcpSackTests
    {
        static readonly IPAddress ClientIp = IPAddress.Parse("10.0.0.1");
        static readonly IPAddress ServerIp = IPAddress.Parse("8.8.8.8");
        const ushort ClientPort = 50000, ServerPort = 80;

        [Fact]
        public void Syn_AdvertisesSackPermitted()
        {
            var sent = new List<byte[]>();
            using var conn = new TcpConnection(ClientIp, ClientPort, ServerIp, ServerPort, sent.Add, linkMtu: 1400);
            conn.StartConnect();

            byte[] syn = Assert.Single(sent);
            Assert.True(TcpSegment.SackPermitted(Ipv4.Payload(syn).Span)); // the SYN offers SACK
        }

        [Fact]
        public void Receiver_BuffersOutOfOrderData_AcksWithSackBlock()
        {
            var sent = new List<byte[]>();
            using var conn = new TcpConnection(ClientIp, ClientPort, ServerIp, ServerPort, sent.Add, linkMtu: 1400);
            uint iss = Handshake(conn, sent, window: 65535, sack: true); // _rcvNxt = 9001 (peer ISS 9000 + 1)

            // A segment 200 bytes past _rcvNxt → buffered out of order, ACK carries a SACK block for it.
            conn.OnSegment(PeerData(seq: 9201, ack: iss + 1, window: 65535, payload: new byte[100]));

            byte[] ackIp = sent.Last();
            Span<uint> blocks = stackalloc uint[8];
            int n = TcpSegment.ReadSackBlocks(Ipv4.Payload(ackIp).Span, blocks);
            Assert.Equal(1, n);
            Assert.Equal(9201u, blocks[0]); // left edge
            Assert.Equal(9301u, blocks[1]); // right edge (9201 + 100)
        }

        [Fact]
        public void Receiver_WithoutSackNegotiated_AcksWithoutSackBlock()
        {
            var sent = new List<byte[]>();
            using var conn = new TcpConnection(ClientIp, ClientPort, ServerIp, ServerPort, sent.Add, linkMtu: 1400);
            uint iss = Handshake(conn, sent, window: 65535, sack: false); // peer did NOT offer SACK-Permitted

            conn.OnSegment(PeerData(seq: 9201, ack: iss + 1, window: 65535, payload: new byte[100]));

            byte[] ackIp = sent.Last();
            Span<uint> blocks = stackalloc uint[8];
            Assert.Equal(0, TcpSegment.ReadSackBlocks(Ipv4.Payload(ackIp).Span, blocks)); // NewReno fallback: no SACK option
        }

        [Fact]
        public void Sender_RetransmitsOnlyTheHole_LeavingSackedSegmentsUntouched()
        {
            var sent = new List<byte[]>();
            using var conn = new TcpConnection(ClientIp, ClientPort, ServerIp, ServerPort, sent.Add, linkMtu: 1400);
            uint iss = Handshake(conn, sent, window: 65535, sack: true);

            conn.Send(new byte[400000]);
            List<byte[]> burst = Drain(sent);
            Assert.True(burst.Count >= 4);
            uint hole = Seq(burst[0]);                                   // first segment lost; everything after it arrives
            uint sackLeft = Seq(burst[1]);
            uint sackRight = Seq(burst[^1]) + (uint)PayloadLength(burst[^1]);

            for (int i = 0; i < 3; i++)                                  // 3 dup ACKs that SACK burst[1..] but not burst[0]
                conn.OnSegment(PeerSack(seq: 9001, ack: hole, window: 65535, sackLeft, sackRight));

            Assert.Contains(sent, ip => Seq(ip) == hole && PayloadLength(ip) > 0);       // the hole is retransmitted...
            Assert.DoesNotContain(sent, ip => Seq(ip) == sackLeft);                      // ...but a SACKed segment is not
        }

        [Fact]
        public void Sender_SecondHoleExposedBySack_RetransmitsBothHolesOnly()
        {
            var sent = new List<byte[]>();
            using var conn = new TcpConnection(ClientIp, ClientPort, ServerIp, ServerPort, sent.Add, linkMtu: 1400);
            uint iss = Handshake(conn, sent, window: 65535, sack: true);

            conn.Send(new byte[400000]);
            List<byte[]> burst = Drain(sent);
            Assert.True(burst.Count >= 5);
            uint hole0 = Seq(burst[0]);                                  // two holes: burst[0] and burst[2]
            uint hole2 = Seq(burst[2]);
            // SACK block 1 = burst[1]; SACK block 2 = burst[3..] → both holes sit below SACKed data, hence "lost".
            uint b1L = Seq(burst[1]), b1R = Seq(burst[1]) + (uint)PayloadLength(burst[1]);
            uint b2L = Seq(burst[3]), b2R = Seq(burst[^1]) + (uint)PayloadLength(burst[^1]);

            for (int i = 0; i < 3; i++)
                conn.OnSegment(PeerSack(seq: 9001, ack: hole0, window: 65535, b1L, b1R, b2L, b2R));

            Assert.Contains(sent, ip => Seq(ip) == hole0 && PayloadLength(ip) > 0);      // both holes retransmitted...
            Assert.Contains(sent, ip => Seq(ip) == hole2 && PayloadLength(ip) > 0);
            Assert.DoesNotContain(sent, ip => Seq(ip) == b1L);                           // ...SACKed segments are not
            Assert.DoesNotContain(sent, ip => Seq(ip) == b2L);
        }

        static uint Handshake(TcpConnection conn, List<byte[]> sent, ushort window, bool sack)
        {
            conn.StartConnect();
            uint clientIss = Seq(sent[0]);
            sent.Clear();
            conn.OnSegment(Peer(seq: 9000, ack: clientIss + 1, TcpFlags.Syn | TcpFlags.Ack, window, mss: 1360, sackPermitted: sack));
            sent.Clear(); // drop the client's handshake ACK
            return clientIss;
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

        static byte[] Peer(uint seq, uint ack, TcpFlags flags, ushort window, ushort mss = 0, bool sackPermitted = false)
            => TcpSegment.Build(ServerIp, ClientIp, ServerPort, ClientPort, seq, ack, flags, window,
                ReadOnlySpan<byte>.Empty, mss, TcpSegment.NoWindowScale, sackPermitted);

        static byte[] PeerData(uint seq, uint ack, ushort window, byte[] payload)
            => TcpSegment.Build(ServerIp, ClientIp, ServerPort, ClientPort, seq, ack, TcpFlags.Psh | TcpFlags.Ack, window, payload);

        static byte[] PeerSack(uint seq, uint ack, ushort window, params uint[] sackBlocks)
            => TcpSegment.Build(ServerIp, ClientIp, ServerPort, ClientPort, seq, ack, TcpFlags.Ack, window,
                ReadOnlySpan<byte>.Empty, 0, TcpSegment.NoWindowScale, false, sackBlocks);
    }
}
