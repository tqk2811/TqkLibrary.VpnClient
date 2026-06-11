using System.Collections.Concurrent;
using System.Linq;
using System.Net;
using TqkLibrary.Vpn.Abstractions.Channels.Enums;
using TqkLibrary.Vpn.Abstractions.Channels.Interfaces;
using TqkLibrary.Vpn.IpStack;
using TqkLibrary.Vpn.IpStack.Tcp;
using TqkLibrary.Vpn.IpStack.Tcp.Enums;
using Xunit;

namespace TqkLibrary.Vpn.IpStack.Tests
{
    /// <summary>
    /// Path MTU Discovery (RFC 1191 IPv4 / RFC 8201 IPv6): an ICMP "fragmentation needed" / ICMPv6 "packet too big" for a
    /// segment we sent lowers the connection's send MSS below the link MTU and re-segments the in-flight retransmission
    /// queue so the dropped data is resent small enough to traverse the path. Driven by injected ICMP/ACKs (no timers).
    /// </summary>
    public class TcpPmtudTests
    {
        static readonly IPAddress ClientIp = IPAddress.Parse("10.0.0.1");
        static readonly IPAddress ServerIp = IPAddress.Parse("8.8.8.8");
        static readonly IPAddress ClientIpV6 = IPAddress.Parse("fd00::1");
        static readonly IPAddress ServerIpV6 = IPAddress.Parse("fd00::2");
        const ushort ClientPort = 50000, ServerPort = 80;

        [Fact]
        public void Icmpv4FragmentationNeeded_LowersSendMss_AndResegmentsInFlight()
        {
            var sent = new List<byte[]>();
            using var conn = new TcpConnection(ClientIp, ClientPort, ServerIp, ServerPort, sent.Add, linkMtu: 1400);
            uint iss = Handshake(conn, sent, ClientIp, ServerIp, window: 65535, peerMss: 1360);
            Assert.Equal(1360, conn.SendMss);                              // link-MTU MSS (1400 − 40) before PMTUD

            conn.Send(new byte[400000]);
            List<byte[]> burst = Drain(sent);
            uint firstSeq = Seq(burst[0]);
            Assert.Contains(burst, ip => PayloadLength(ip) > 560);         // the first burst went out at the full MSS

            conn.OnIcmpPacketTooBig(nextHopMtu: 600, offendingSeq: firstSeq); // a 600-byte path link → MSS 560
            Assert.Equal(560, conn.SendMss);

            List<byte[]> resent = Drain(sent);
            Assert.NotEmpty(resent);
            Assert.All(resent, ip => Assert.True(PayloadLength(ip) <= 560)); // every retransmission now fits the path
            Assert.Contains(resent, ip => Seq(ip) == firstSeq);             // the dropped data is resent from its original seq
        }

        [Fact]
        public void Icmpv6PacketTooBig_LowersSendMss_AndResegmentsInFlight()
        {
            var sent = new List<byte[]>();
            using var conn = new TcpConnection(ClientIpV6, ClientPort, ServerIpV6, ServerPort, sent.Add, linkMtu: 1400);
            uint iss = Handshake(conn, sent, ClientIpV6, ServerIpV6, window: 65535, peerMss: 1340);
            Assert.Equal(1340, conn.SendMss);                              // v6 link-MTU MSS (1400 − 60) before PMTUD

            conn.Send(new byte[400000]);
            List<byte[]> burst = Drain(sent);
            uint firstSeq = Seq(burst[0]);

            conn.OnIcmpPacketTooBig(nextHopMtu: 1280, offendingSeq: firstSeq); // IPv6 minimum link MTU → MSS 1220
            Assert.Equal(1220, conn.SendMss);

            List<byte[]> resent = Drain(sent);
            Assert.NotEmpty(resent);
            Assert.All(resent, ip => Assert.True(PayloadLength(ip) <= 1220));
            Assert.Contains(resent, ip => Seq(ip) == firstSeq);
        }

        [Fact]
        public void Resegmentation_PreservesByteStream_TilingOutstandingContiguously()
        {
            var sent = new List<byte[]>();
            using var conn = new TcpConnection(ClientIp, ClientPort, ServerIp, ServerPort, sent.Add, linkMtu: 1400);
            uint iss = Handshake(conn, sent, ClientIp, ServerIp, window: 65535, peerMss: 1360);

            conn.Send(new byte[400000]);
            List<byte[]> burst = Drain(sent);
            uint firstSeq = Seq(burst[0]);
            int outstanding = burst.Sum(PayloadLength);                    // bytes in flight at the old MSS

            conn.OnIcmpPacketTooBig(nextHopMtu: 600, offendingSeq: firstSeq);

            // The re-sent pieces must tile [firstSeq, firstSeq+outstanding) exactly: no gap, no overlap, each ≤ new MSS.
            var pieces = Drain(sent)
                .Select(ip => (Seq: Seq(ip), Len: PayloadLength(ip)))
                .OrderBy(p => (uint)(p.Seq - firstSeq))
                .ToList();
            uint expected = firstSeq;
            int covered = 0;
            foreach ((uint seq, int len) in pieces)
            {
                Assert.Equal(expected, seq);                              // contiguous with the previous piece
                Assert.True(len <= conn.SendMss);
                expected += (uint)len;
                covered += len;
            }
            Assert.Equal(outstanding, covered);                           // the whole in-flight stream was re-segmented
        }

        [Fact]
        public void IgnoresPathMtu_ThatWouldNotLowerTheMss()
        {
            var sent = new List<byte[]>();
            using var conn = new TcpConnection(ClientIp, ClientPort, ServerIp, ServerPort, sent.Add, linkMtu: 1400);
            uint iss = Handshake(conn, sent, ClientIp, ServerIp, window: 65535, peerMss: 1360);

            conn.Send(new byte[400000]);
            List<byte[]> burst = Drain(sent);
            uint firstSeq = Seq(burst[0]);

            // A reported MTU at/above the link MTU (PMTUD never raises the MSS) and a stale seq are both no-ops.
            conn.OnIcmpPacketTooBig(nextHopMtu: 1400, offendingSeq: firstSeq);
            conn.OnIcmpPacketTooBig(nextHopMtu: 600, offendingSeq: firstSeq - 1000); // not currently outstanding
            Assert.Equal(1360, conn.SendMss);
            Assert.Empty(Drain(sent));                                     // nothing re-segmented or retransmitted
        }

        [Fact]
        public void Icmpv4FragmentationNeeded_RoutedThroughStack_LowersConnectionMss()
        {
            var channel = new CaptureChannel();
            var stack = new TcpIpStack(channel, ClientIp);

            // Drive the 3-way handshake by hand: take the client SYN, answer with a crafted SYN-ACK.
            Task<TcpConnection> connecting = stack.ConnectAsync(ServerIp, ServerPort);
            byte[] syn = channel.TakeOutbound();
            ReadOnlyMemory<byte> synTcp = Ipv4.Payload(syn);
            ushort clientPort = TcpSegment.SourcePort(synTcp.Span);
            uint clientIss = TcpSegment.Sequence(synTcp.Span);
            byte[] synAck = TcpSegment.Build(ServerIp, ClientIp, ServerPort, clientPort, 9000, clientIss + 1,
                TcpFlags.Syn | TcpFlags.Ack, 65535, ReadOnlySpan<byte>.Empty, mss: 1360);
            channel.Inject(Ipv4.Build(ServerIp, ClientIp, Ipv4.ProtocolTcp, synAck, identification: 1));

            TcpConnection conn = connecting.GetAwaiter().GetResult();
            Assert.Equal(1360, conn.SendMss);

            conn.Send(new byte[40000]);
            byte[] dataPacket = TakeData(channel);                        // a captured data segment to quote in the ICMP error

            // A router on the path answers ICMP Fragmentation-Needed (600-byte next hop) quoting that segment.
            byte[] icmp = Icmpv4.BuildFragmentationNeeded(600, dataPacket);
            channel.Inject(Ipv4.Build(ServerIp, ClientIp, Ipv4.ProtocolIcmp, icmp, identification: 2));

            Assert.Equal(560, conn.SendMss);                              // the stack routed the error to the connection
        }

        // ---- helpers --------------------------------------------------------------------------------------

        static uint Handshake(TcpConnection conn, List<byte[]> sent, IPAddress client, IPAddress server, ushort window, ushort peerMss)
        {
            conn.StartConnect();
            uint clientIss = Seq(sent[0]);
            sent.Clear();
            byte[] synAck = TcpSegment.Build(server, client, ServerPort, ClientPort, 9000, clientIss + 1,
                TcpFlags.Syn | TcpFlags.Ack, window, ReadOnlySpan<byte>.Empty, peerMss);
            conn.OnSegment(synAck);
            sent.Clear();   // drop the client's handshake ACK
            return clientIss;
        }

        static byte[] TakeData(CaptureChannel channel)
        {
            for (int i = 0; i < 32; i++)
            {
                byte[] ip = channel.TakeOutbound();
                if (PayloadLength(ip) > 0) return ip;
            }
            throw new Xunit.Sdk.XunitException("no data segment was sent");
        }

        static List<byte[]> Drain(List<byte[]> sent)
        {
            List<byte[]> copy = sent.ToList();
            sent.Clear();
            return copy;
        }

        static ReadOnlyMemory<byte> Tcp(byte[] ip)
        {
            if (IpLayer.Version(ip) == 6)
            {
                Ipv6.TryGetUpperLayer(ip, out byte _, out int offset);
                return ip.AsMemory(offset);
            }
            return Ipv4.Payload(ip);
        }

        static uint Seq(byte[] ip) => TcpSegment.Sequence(Tcp(ip).Span);

        static int PayloadLength(byte[] ip)
        {
            ReadOnlyMemory<byte> tcp = Tcp(ip);
            return tcp.Length - TcpSegment.DataOffset(tcp.Span);
        }

        /// <summary>An in-memory IP channel that records outbound packets and lets the test inject inbound ones.</summary>
        sealed class CaptureChannel : IPacketChannel
        {
            readonly BlockingCollection<byte[]> _outbound = new();

            public LinkMedium Medium => LinkMedium.Ip;
            public int Mtu => 1400;
            public int MaxHeaderLength => 0;
            public bool RequiresLinkAddressResolution => false;
            public event Action<ReadOnlyMemory<byte>>? InboundIpPacket;

            public ValueTask WriteIpPacketAsync(ReadOnlyMemory<byte> ipPacket, CancellationToken cancellationToken = default)
            {
                _outbound.Add(ipPacket.ToArray());
                return default;
            }

            public byte[] TakeOutbound() => _outbound.Take();
            public void Inject(byte[] ipPacket) => InboundIpPacket?.Invoke(ipPacket);

            public ValueTask DisposeAsync() => default;
        }
    }
}
