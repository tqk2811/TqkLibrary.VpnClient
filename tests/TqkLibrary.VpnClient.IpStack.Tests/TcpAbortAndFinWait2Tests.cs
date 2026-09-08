using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net;
using System.Threading.Tasks;
using TqkLibrary.VpnClient.IpStack;
using TqkLibrary.VpnClient.IpStack.Tcp;
using TqkLibrary.VpnClient.IpStack.Tcp.Enums;
using Xunit;

namespace TqkLibrary.VpnClient.IpStack.Tests
{
    /// <summary>
    /// The two ways a connection can stop waiting on a peer that is not going to answer.
    /// </summary>
    /// <remarks>
    /// A close handshake needs both halves, and only one of them is ours. Sending a FIN says we are
    /// done sending; a peer with nothing more to say has no reason to reply with its own, so the
    /// connection sits in FIN-WAIT-2 keeping a port and a receive queue for as long as the tunnel
    /// lives. Inside a userspace stack those are not free — nobody reaps them, and a client that
    /// cancels requests (a browser closing tabs) produces one every time. Abort covers the case
    /// where the caller already knows it is finished; the FIN-WAIT-2 timeout covers the case where
    /// it politely half-closed and the peer went quiet.
    /// </remarks>
    public class TcpAbortAndFinWait2Tests
    {
        static readonly IPAddress ClientIp = IPAddress.Parse("10.0.0.1");
        static readonly IPAddress ServerIp = IPAddress.Parse("8.8.8.8");
        const ushort ClientPort = 50000, ServerPort = 443;

        [Fact]
        public void Abort_SendsRst_AndClosesTheConnection()
        {
            var sent = new List<byte[]>();
            using var conn = new TcpConnection(ClientIp, ClientPort, ServerIp, ServerPort, sent.Add, linkMtu: 1400);
            Handshake(conn, sent);

            conn.Abort();

            Assert.Contains(Drain(sent), ip => HasFlag(ip, TcpFlags.Rst));
            Assert.Equal(TcpState.Closed, conn.State);
        }

        [Fact]
        public void Abort_TellsThePeer_WhereClosingTheStreamOnlyHalfClosesIt()
        {
            var closed = new List<byte[]>();
            using (var polite = new TcpConnection(ClientIp, ClientPort, ServerIp, ServerPort, closed.Add, linkMtu: 1400))
            {
                Handshake(polite, closed);
                polite.CloseSend();

                // A FIN leaves the connection alive and waiting: this is exactly the state that used
                // to be permanent.
                Assert.Contains(Drain(closed), ip => HasFlag(ip, TcpFlags.Fin));
                Assert.NotEqual(TcpState.Closed, polite.State);
            }

            var aborted = new List<byte[]>();
            using var abrupt = new TcpConnection(ClientIp, ClientPort, ServerIp, ServerPort, aborted.Add, linkMtu: 1400);
            Handshake(abrupt, aborted);
            abrupt.Abort();

            Assert.Equal(TcpState.Closed, abrupt.State);
        }

        [Fact]
        public void Abort_IsIdempotent_AndSafeAfterTheConnectionIsAlreadyGone()
        {
            var sent = new List<byte[]>();
            using var conn = new TcpConnection(ClientIp, ClientPort, ServerIp, ServerPort, sent.Add, linkMtu: 1400);
            Handshake(conn, sent);

            conn.Abort();
            int afterFirst = Drain(sent).Count;
            conn.Abort();

            // The second call has no connection left to reset, and must not put a second RST on the
            // wire for a flow the peer has already forgotten.
            Assert.NotEqual(0, afterFirst);
            Assert.Empty(sent);
            Assert.Equal(TcpState.Closed, conn.State);
        }

        [Fact]
        public async Task FinWait2_DoesNotWaitForever_WhenThePeerNeverSendsItsFin()
        {
            var sent = new List<byte[]>();
            // Long enough that a loaded machine cannot get here late and find the timer already
            // fired, short enough that the test does not sit waiting for it.
            var options = new TcpRetransmitOptions(finWait2: TimeSpan.FromMilliseconds(750));
            using var conn = new TcpConnection(ClientIp, ClientPort, ServerIp, ServerPort, sent.Add, options, linkMtu: 1400);
            uint peerNext = Handshake(conn, sent);

            conn.CloseSend();
            uint finSeq = SequenceOf(Drain(sent).First(ip => HasFlag(ip, TcpFlags.Fin)));

            // The peer acknowledges our FIN and then says nothing more — the shape of a server that
            // is simply not finished with its side of the connection.
            conn.OnSegment(Segment(peerNext, finSeq + 1, TcpFlags.Ack));
            Assert.Equal(TcpState.FinWait2, conn.State);

            await WaitForClosedAsync(conn, TimeSpan.FromSeconds(30));

            Assert.Equal(TcpState.Closed, conn.State);
            Assert.Contains(Drain(sent), ip => HasFlag(ip, TcpFlags.Rst));
        }

        [Fact]
        public async Task FinWait2_EndsNormally_WhenThePeerDoesSendItsFin()
        {
            var sent = new List<byte[]>();
            // The FIN-WAIT-2 bound is deliberately far away here: this test is about the ordinary
            // close, and a short one would let a stalled machine reset the connection before the
            // peer's FIN was delivered — a failure of the test harness, not of the code.
            var options = new TcpRetransmitOptions(
                finWait2: TimeSpan.FromMinutes(5), timeWait: TimeSpan.FromMilliseconds(50));
            using var conn = new TcpConnection(ClientIp, ClientPort, ServerIp, ServerPort, sent.Add, options, linkMtu: 1400);
            uint peerNext = Handshake(conn, sent);

            conn.CloseSend();
            uint finSeq = SequenceOf(Drain(sent).First(ip => HasFlag(ip, TcpFlags.Fin)));
            conn.OnSegment(Segment(peerNext, finSeq + 1, TcpFlags.Ack));

            conn.OnSegment(Segment(peerNext, finSeq + 1, TcpFlags.Fin | TcpFlags.Ack));

            await WaitForClosedAsync(conn, TimeSpan.FromSeconds(5));

            // Closed through TIME-WAIT, not by the timeout: the ordinary path must not start
            // resetting connections now that the bound exists.
            Assert.Equal(TcpState.Closed, conn.State);
            Assert.DoesNotContain(Drain(sent), ip => HasFlag(ip, TcpFlags.Rst));
        }

        // Drives the client through a three-way handshake, leaving only post-handshake output in
        // `sent`. Returns the peer's next sequence number.
        static uint Handshake(TcpConnection conn, List<byte[]> sent)
        {
            const uint peerIss = 9000;
            conn.StartConnect();
            uint clientIss = TcpSegment.Sequence(Ipv4.Payload(sent[0]).Span);
            sent.Clear();
            byte[] synAck = TcpSegment.Build(ServerIp, ClientIp, ServerPort, ClientPort, peerIss, clientIss + 1,
                TcpFlags.Syn | TcpFlags.Ack, 64240, ReadOnlySpan<byte>.Empty, mss: 1360);
            conn.OnSegment(synAck);
            sent.Clear();   // drop the client's handshake ACK
            return peerIss + 1;
        }

        static byte[] Segment(uint seq, uint ack, TcpFlags flags)
            => TcpSegment.Build(ServerIp, ClientIp, ServerPort, ClientPort, seq, ack, flags, 64240, ReadOnlySpan<byte>.Empty);

        static async Task WaitForClosedAsync(TcpConnection conn, TimeSpan within)
        {
            DateTime deadline = DateTime.UtcNow + within;
            while (conn.State != TcpState.Closed && DateTime.UtcNow < deadline)
                await Task.Delay(10).ConfigureAwait(false);
        }

        static List<byte[]> Drain(List<byte[]> sent)
        {
            List<byte[]> copy = sent.ToList();
            sent.Clear();
            return copy;
        }

        static bool HasFlag(byte[] ip, TcpFlags flag)
            => (TcpSegment.Flags(Ipv4.Payload(ip).Span) & flag) != 0;

        static uint SequenceOf(byte[] ip) => TcpSegment.Sequence(Ipv4.Payload(ip).Span);
    }
}
