using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using TqkLibrary.VpnClient.IpStack.Tcp;
using TqkLibrary.VpnClient.IpStack.Tcp.Enums;
using Xunit;

namespace TqkLibrary.VpnClient.IpStack.Tests
{
    /// <summary>
    /// The send window a SYN-ACK establishes (RFC 9293 §3.10.7.3, SYN-SENT step 5: SND.WND = SEG.WND, SND.WL1 = SEG.SEQ,
    /// SND.WL2 = SEG.ACK). What makes this worth pinning is the half of the sequence space that used to be broken: the
    /// window-update rule applied to every later segment is a signed comparison against SND.WL1, so seeding it from the
    /// SYN-ACK is what stops a peer whose initial sequence number happens to sit at 2^31 or above from leaving the send
    /// window at zero forever. A connection in that state still opens, and still acknowledges — it just dribbles the
    /// request out one zero-window persist byte at a time, which reads from the outside as a server that went silent.
    /// Peers pick their ISN at random, so the failure was a coin flip per connection.
    /// </summary>
    public class TcpSendWindowSeedTests
    {
        static readonly IPAddress ClientIp = IPAddress.Parse("10.0.0.1");
        static readonly IPAddress ServerIp = IPAddress.Parse("8.8.8.8");
        const ushort ClientPort = 50000, ServerPort = 443;

        // Both halves of the sequence space, plus the two edges of the signed comparison that used to decide the outcome.
        [Theory]
        [InlineData(9000u)]              // low ISN — worked even before the window was seeded
        [InlineData(0x7FFFFFFFu)]        // last ISN a signed comparison against zero still calls "greater"
        [InlineData(0x80000000u)]        // first one it calls "less" — where the send window used to stick at zero
        [InlineData(0xFFFFFF00u)]        // high ISN, and one that wraps within the first few segments
        public void SynAck_OpensTheSendWindow_WhateverThePeersInitialSequenceNumber(uint peerIss)
        {
            var sent = new List<byte[]>();
            using var conn = new TcpConnection(ClientIp, ClientPort, ServerIp, ServerPort, sent.Add, linkMtu: 1400);
            Handshake(conn, sent, peerIss, window: 64240);

            conn.Send(new byte[1930]);   // a browser's TLS ClientHello: two segments at this MSS, not one

            int delivered = Drain(sent).Sum(PayloadLength);
            Assert.Equal(1930, delivered);
        }

        [Fact]
        public void HighIssPeer_IsNotMistakenForAZeroWindow_AndNeedsNoPersistProbe()
        {
            var sent = new List<byte[]>();
            using var conn = new TcpConnection(ClientIp, ClientPort, ServerIp, ServerPort, sent.Add, linkMtu: 1400);
            Handshake(conn, sent, peerIss: 0xC0000000u, window: 64240);

            conn.Send(new byte[100]);

            // One segment carrying the whole write. A zero send window would have produced a single one-byte probe
            // instead — the shape the tunnel was actually sending before the window was seeded.
            byte[] segment = Assert.Single(Drain(sent).Where(ip => PayloadLength(ip) > 0));
            Assert.Equal(100, PayloadLength(segment));
        }

        [Fact]
        public void PeerAdvertisingAZeroWindow_IsStillHonoured()
        {
            var sent = new List<byte[]>();
            using var conn = new TcpConnection(ClientIp, ClientPort, ServerIp, ServerPort, sent.Add, linkMtu: 1400);
            Handshake(conn, sent, peerIss: 0xC0000000u, window: 0);

            conn.Send(new byte[100]);

            // Seeding the window must not mean ignoring it: a peer that really has no room gets nothing until it
            // reopens (the persist timer, not this path, sends the probe).
            Assert.Empty(Drain(sent).Where(ip => PayloadLength(ip) > 0));
        }

        // Drives the client through a three-way handshake against a peer with the given ISN and advertised window,
        // leaving only the client's post-handshake output in `sent`.
        static void Handshake(TcpConnection conn, List<byte[]> sent, uint peerIss, ushort window)
        {
            conn.StartConnect();
            uint clientIss = TcpSegment.Sequence(Ipv4.Payload(sent[0]).Span);
            sent.Clear();
            byte[] synAck = TcpSegment.Build(ServerIp, ClientIp, ServerPort, ClientPort, peerIss, clientIss + 1,
                TcpFlags.Syn | TcpFlags.Ack, window, ReadOnlySpan<byte>.Empty, mss: 1360);
            conn.OnSegment(synAck);
            sent.Clear();   // drop the client's handshake ACK
        }

        static List<byte[]> Drain(List<byte[]> sent)
        {
            List<byte[]> copy = sent.ToList();
            sent.Clear();
            return copy;
        }

        static int PayloadLength(byte[] ip)
        {
            ReadOnlyMemory<byte> tcp = Ipv4.Payload(ip);
            return tcp.Length - TcpSegment.DataOffset(tcp.Span);
        }
    }
}
