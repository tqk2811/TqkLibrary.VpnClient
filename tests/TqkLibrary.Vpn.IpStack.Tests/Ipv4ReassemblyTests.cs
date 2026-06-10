using System.Net;
using TqkLibrary.Vpn.Abstractions.Channels.Enums;
using TqkLibrary.Vpn.Abstractions.Channels.Interfaces;
using TqkLibrary.Vpn.IpStack;
using TqkLibrary.Vpn.IpStack.Tcp;
using Xunit;

namespace TqkLibrary.Vpn.IpStack.Tests
{
    public class Ipv4ReassemblyTests
    {
        static readonly IPAddress Src = IPAddress.Parse("8.8.8.8");
        static readonly IPAddress Dst = IPAddress.Parse("10.0.0.1");

        [Fact]
        public void NonFragmented_PassesThrough_Unchanged()
        {
            var reassembler = new Ipv4Reassembler();
            byte[] whole = Ipv4.Build(Src, Dst, Ipv4.ProtocolUdp, MakePayload(40), identification: 0x1234);

            ReadOnlyMemory<byte>? result = reassembler.Offer(whole);

            Assert.NotNull(result);
            Assert.Equal(whole, result!.Value.ToArray());
            Assert.Equal(0, reassembler.PendingCount);
        }

        [Fact]
        public void TwoFragments_InOrder_Reassembled()
        {
            var reassembler = new Ipv4Reassembler();
            byte[] payload = MakePayload(48);
            byte[][] fragments = Fragment(payload, identification: 0x2222, fragmentSize: 24);

            Assert.Null(reassembler.Offer(fragments[0])); // first fragment buffered
            Assert.Equal(1, reassembler.PendingCount);

            ReadOnlyMemory<byte>? done = reassembler.Offer(fragments[1]); // last fragment completes it
            Assert.NotNull(done);

            ReadOnlySpan<byte> span = done!.Value.Span;
            Assert.False(Ipv4.MoreFragments(span));
            Assert.Equal(0, Ipv4.FragmentOffset(span));
            Assert.Equal(payload, Ipv4.Payload(done.Value).ToArray());
            Assert.Equal(0, reassembler.PendingCount);
        }

        [Fact]
        public void Fragments_OutOfOrder_Reassembled()
        {
            var reassembler = new Ipv4Reassembler();
            byte[] payload = MakePayload(48);
            byte[][] fragments = Fragment(payload, identification: 0x3333, fragmentSize: 16); // 3 fragments

            // Deliver last, then middle, then first — reassembly must not depend on arrival order.
            Assert.Null(reassembler.Offer(fragments[2]));
            Assert.Null(reassembler.Offer(fragments[1]));
            ReadOnlyMemory<byte>? done = reassembler.Offer(fragments[0]);

            Assert.NotNull(done);
            Assert.Equal(payload, Ipv4.Payload(done!.Value).ToArray());
            Assert.Equal(0, reassembler.PendingCount);
        }

        [Fact]
        public void DuplicateAndOverlappingFragments_Tolerated()
        {
            var reassembler = new Ipv4Reassembler();
            byte[] payload = MakePayload(32);
            byte[][] fragments = Fragment(payload, identification: 0x4444, fragmentSize: 16);

            Assert.Null(reassembler.Offer(fragments[0]));
            Assert.Null(reassembler.Offer(fragments[0])); // exact duplicate of the first fragment
            ReadOnlyMemory<byte>? done = reassembler.Offer(fragments[1]);

            Assert.NotNull(done);
            Assert.Equal(payload, Ipv4.Payload(done!.Value).ToArray());
            Assert.Equal(0, reassembler.PendingCount);
        }

        [Fact]
        public void IncompleteDatagram_TimesOut_AndIsDiscarded()
        {
            var reassembler = new Ipv4Reassembler(new Ipv4ReassemblyOptions(timeout: TimeSpan.FromMilliseconds(80)));
            byte[] payload = MakePayload(48);
            byte[][] fragments = Fragment(payload, identification: 0x5555, fragmentSize: 24);

            Assert.Null(reassembler.Offer(fragments[0]));
            Assert.Equal(1, reassembler.PendingCount);

            Thread.Sleep(200); // let the partial datagram exceed its 80 ms deadline

            // The completing fragment now finds the partial expired → it cannot finish the datagram.
            Assert.Null(reassembler.Offer(fragments[1]));
            Assert.Equal(1, reassembler.PendingCount); // only the orphaned last fragment remains
        }

        [Fact]
        public void OverCapacity_EvictsOldestDatagram()
        {
            var reassembler = new Ipv4Reassembler(new Ipv4ReassemblyOptions(maxConcurrent: 2));

            reassembler.Offer(FirstFragment(identification: 1));
            reassembler.Offer(FirstFragment(identification: 2));
            Assert.Equal(2, reassembler.PendingCount);

            reassembler.Offer(FirstFragment(identification: 3)); // exceeds cap → oldest (id 1) evicted
            Assert.Equal(2, reassembler.PendingCount);
        }

        [Fact]
        public async Task FragmentedUdp_ReassembledAndDelivered_ThroughStack()
        {
            IPAddress local = IPAddress.Parse("10.0.0.1");
            IPAddress remote = IPAddress.Parse("8.8.8.8");
            var channel = new InjectChannel();
            var stack = new TcpIpStack(channel, local);
            UdpConnection socket = stack.BindUdp(53);

            byte[] data = System.Text.Encoding.ASCII.GetBytes("a-fragmented-dns-response-payload-0123456789");
            byte[] datagram = UdpDatagram.Build(remote, local, sourcePort: 5353, destinationPort: 53, data);

            const int split = 8; // 8-byte boundary: fragment 0 carries the UDP header, fragment 1 the payload
            byte[] f0 = Ipv4.BuildFragment(remote, local, Ipv4.ProtocolUdp, datagram.AsSpan(0, split), identification: 0x6666, fragmentOffset: 0, moreFragments: true);
            byte[] f1 = Ipv4.BuildFragment(remote, local, Ipv4.ProtocolUdp, datagram.AsSpan(split), identification: 0x6666, fragmentOffset: split, moreFragments: false);

            using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(5));
            Task<UdpReceiveResult> receive = socket.ReceiveAsync(cts.Token);

            channel.Inject(f0); // buffered, nothing delivered yet
            channel.Inject(f1); // completes reassembly → datagram delivered to the socket

            UdpReceiveResult result = await receive;
            Assert.Equal(data, result.Data);
            Assert.Equal(remote, result.RemoteAddress);
            Assert.Equal((ushort)5353, result.RemotePort);
        }

        static byte[] MakePayload(int length)
        {
            byte[] payload = new byte[length];
            for (int i = 0; i < length; i++) payload[i] = (byte)(i * 7 + 1);
            return payload;
        }

        static byte[][] Fragment(byte[] payload, ushort identification, int fragmentSize)
        {
            var fragments = new List<byte[]>();
            for (int offset = 0; offset < payload.Length; offset += fragmentSize)
            {
                int length = Math.Min(fragmentSize, payload.Length - offset);
                bool moreFragments = offset + length < payload.Length;
                fragments.Add(Ipv4.BuildFragment(Src, Dst, Ipv4.ProtocolUdp, payload.AsSpan(offset, length), identification, offset, moreFragments));
            }
            return fragments.ToArray();
        }

        static byte[] FirstFragment(ushort identification) =>
            Ipv4.BuildFragment(Src, Dst, Ipv4.ProtocolUdp, MakePayload(24), identification, fragmentOffset: 0, moreFragments: true);

        /// <summary>A channel that delivers injected inbound IP packets and discards outbound writes.</summary>
        sealed class InjectChannel : IPacketChannel
        {
            public LinkMedium Medium => LinkMedium.Ip;
            public int Mtu => 1400;
            public int MaxHeaderLength => 0;
            public bool RequiresLinkAddressResolution => false;
            public event Action<ReadOnlyMemory<byte>>? InboundIpPacket;

            public ValueTask WriteIpPacketAsync(ReadOnlyMemory<byte> ipPacket, CancellationToken cancellationToken = default) => default;
            public void Inject(byte[] ipPacket) => InboundIpPacket?.Invoke(ipPacket);
            public ValueTask DisposeAsync() => default;
        }
    }
}
