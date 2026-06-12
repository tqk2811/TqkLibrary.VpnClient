using System.Net;
using System.Threading.Channels;
using TqkLibrary.Vpn.Abstractions.Channels.Enums;
using TqkLibrary.Vpn.Abstractions.Channels.Interfaces;
using TqkLibrary.Vpn.IpStack;
using TqkLibrary.Vpn.IpStack.Udp;
using Xunit;

namespace TqkLibrary.Vpn.IpStack.Tests
{
    /// <summary>
    /// Reassembly of inbound IPv6 datagrams carried in the Fragment extension header (RFC 8200 §4.5): in-order,
    /// out-of-order, whole-packet pass-through, over-cap drop, a Fragment↔reassemble round trip, and an end-to-end
    /// fragmented UDP datagram through two stacks.
    /// </summary>
    public class Ipv6ReassemblyTests
    {
        static readonly IPAddress Src = IPAddress.Parse("fd00::1");
        static readonly IPAddress Dst = IPAddress.Parse("fd00::2");

        [Fact]
        public void WholePacket_PassesThroughUnchanged()
        {
            byte[] whole = Ipv6.Build(Src, Dst, Ipv6.NextHeaderUdp, MakePayload(100));
            var r = new Ipv6Reassembler();
            ReadOnlyMemory<byte>? result = r.Offer(whole);
            Assert.NotNull(result);
            Assert.Equal(whole, result!.Value.ToArray());
            Assert.Equal(0, r.PendingCount);
        }

        [Fact]
        public void InOrderFragments_Reassemble()
        {
            byte[] datagram = Ipv6.Build(Src, Dst, Ipv6.NextHeaderUdp, MakePayload(3000));
            AssertReassembles(datagram, reverse: false);
        }

        [Fact]
        public void OutOfOrderFragments_Reassemble()
        {
            byte[] datagram = Ipv6.Build(Src, Dst, Ipv6.NextHeaderUdp, MakePayload(3000));
            AssertReassembles(datagram, reverse: true);
        }

        [Fact]
        public void DuplicateFragment_IsTolerated()
        {
            byte[] datagram = Ipv6.Build(Src, Dst, Ipv6.NextHeaderUdp, MakePayload(2500));
            var frags = Ipv6.Fragment(datagram, mtu: 1280, identification: 0x55);
            Assert.True(frags.Count > 1);

            var r = new Ipv6Reassembler();
            ReadOnlyMemory<byte>? done = null;
            // Offer the first fragment twice before the rest — must not corrupt or double-count.
            done = r.Offer(frags[0]); Assert.Null(done);
            done = r.Offer(frags[0]); Assert.Null(done);
            for (int i = 1; i < frags.Count; i++)
            {
                ReadOnlyMemory<byte>? res = r.Offer(frags[i]);
                if (res != null) done = res;
            }
            Assert.NotNull(done);
            Assert.Equal(datagram, done!.Value.ToArray());
        }

        [Fact]
        public void OverCapFragment_IsDropped()
        {
            var r = new Ipv6Reassembler(new Ipv6ReassemblyOptions(maxDatagramSize: 100));
            // A single fragment whose payload (200 bytes) already exceeds the 100-byte cap.
            byte[] frag = Ipv6.BuildFragment(Src, Dst, Ipv6.NextHeaderUdp, MakePayload(200), identification: 1, fragmentOffset: 0, moreFragments: true);
            Assert.Null(r.Offer(frag));
            Assert.Equal(0, r.PendingCount);
        }

        [Fact]
        public async Task LargeUdpDatagram_FragmentsOnEgress_AndReassemblesOnPeer()
        {
            var link = new LoopbackPair();
            var client = new TcpIpStack(link.A, Src);
            var server = new TcpIpStack(link.B, Dst);
            UdpConnection serverSocket = server.BindUdp(5353);

            byte[] payload = MakePayload(3000); // 3000 + UDP(8) + IPv6(40) > 1400 MTU → must fragment
            UdpConnection clientSocket = client.BindUdp();

            using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(5));
            clientSocket.SendTo(Dst, 5353, payload);

            UdpReceiveResult got = await serverSocket.ReceiveAsync(cts.Token);
            Assert.Equal(payload, got.Data);
            Assert.Equal(Src, got.RemoteAddress);
            Assert.Equal(clientSocket.LocalPort, got.RemotePort);
        }

        static void AssertReassembles(byte[] datagram, bool reverse)
        {
            var frags = Ipv6.Fragment(datagram, mtu: 1280, identification: 0xABCDEF01);
            Assert.True(frags.Count > 1);

            var r = new Ipv6Reassembler();
            ReadOnlyMemory<byte>? done = null;
            for (int k = 0; k < frags.Count; k++)
            {
                byte[] f = reverse ? frags[frags.Count - 1 - k] : frags[k];
                ReadOnlyMemory<byte>? res = r.Offer(f);
                if (res != null) done = res;
            }
            Assert.NotNull(done);
            Assert.Equal(datagram, done!.Value.ToArray());
            Assert.Equal(0, r.PendingCount);
        }

        static byte[] MakePayload(int length)
        {
            byte[] payload = new byte[length];
            for (int i = 0; i < length; i++) payload[i] = (byte)(i * 13 + 3);
            return payload;
        }

        /// <summary>Two in-memory IP packet channels wired back to back with a serialized async delivery pump.</summary>
        sealed class LoopbackPair
        {
            public LoopbackPair()
            {
                var a = new Chan();
                var b = new Chan();
                a.Peer = b; b.Peer = a;
                A = a; B = b;
            }

            public IPacketChannel A { get; }
            public IPacketChannel B { get; }

            sealed class Chan : IPacketChannel
            {
                readonly Channel<byte[]> _queue = System.Threading.Channels.Channel.CreateUnbounded<byte[]>(
                    new UnboundedChannelOptions { SingleReader = true });

                public Chan() { _ = Task.Run(DrainAsync); }

                public Chan? Peer;
                public LinkMedium Medium => LinkMedium.Ip;
                public int Mtu => 1400;
                public int MaxHeaderLength => 0;
                public bool RequiresLinkAddressResolution => false;
                public event Action<ReadOnlyMemory<byte>>? InboundIpPacket;

                public ValueTask WriteIpPacketAsync(ReadOnlyMemory<byte> ipPacket, CancellationToken cancellationToken = default)
                {
                    Peer?._queue.Writer.TryWrite(ipPacket.ToArray());
                    return default;
                }

                async Task DrainAsync()
                {
                    while (await _queue.Reader.WaitToReadAsync().ConfigureAwait(false))
                        while (_queue.Reader.TryRead(out byte[]? packet))
                            InboundIpPacket?.Invoke(packet);
                }

                public ValueTask DisposeAsync() { _queue.Writer.TryComplete(); return default; }
            }
        }
    }
}
