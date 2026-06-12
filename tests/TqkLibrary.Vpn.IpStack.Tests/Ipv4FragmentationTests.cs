using System.Net;
using TqkLibrary.Vpn.Abstractions.Channels.Enums;
using TqkLibrary.Vpn.Abstractions.Channels.Interfaces;
using TqkLibrary.Vpn.IpStack;
using TqkLibrary.Vpn.IpStack.Udp;
using Xunit;

namespace TqkLibrary.Vpn.IpStack.Tests
{
    public class Ipv4FragmentationTests
    {
        static readonly IPAddress Src = IPAddress.Parse("10.0.0.1");
        static readonly IPAddress Dst = IPAddress.Parse("8.8.8.8");

        [Fact]
        public void DatagramThatFits_NotFragmented()
        {
            byte[] datagram = Ipv4.Build(Src, Dst, Ipv4.ProtocolUdp, MakePayload(100), identification: 0x1111);

            IReadOnlyList<byte[]> fragments = Ipv4.Fragment(datagram, mtu: 1400);

            byte[] only = Assert.Single(fragments);
            Assert.Equal(datagram, only);
        }

        [Fact]
        public void LargeDatagram_SplitOn8ByteBoundaries_AllUnderMtu()
        {
            const int mtu = 200;
            byte[] datagram = Ipv4.Build(Src, Dst, Ipv4.ProtocolUdp, MakePayload(500), identification: 0x2222);

            IReadOnlyList<byte[]> fragments = Ipv4.Fragment(datagram, mtu);

            Assert.True(fragments.Count > 1);
            int expectedOffset = 0;
            for (int i = 0; i < fragments.Count; i++)
            {
                ReadOnlySpan<byte> f = fragments[i];
                Assert.True(f.Length <= mtu, $"fragment {i} is {f.Length} bytes, exceeds MTU {mtu}");
                Assert.False(Ipv4.DontFragment(f));                       // DF must be cleared so the link may carry it
                Assert.Equal(expectedOffset, Ipv4.FragmentOffset(f));     // contiguous, in arrival-independent order
                Assert.Equal(0x2222, Ipv4.Identification(f));             // all fragments share the datagram id

                int payloadLength = f.Length - Ipv4.HeaderLength(f);
                bool isLast = i == fragments.Count - 1;
                Assert.Equal(!isLast, Ipv4.MoreFragments(f));            // MF set on every fragment but the last
                if (!isLast) Assert.Equal(0, payloadLength % 8);          // non-final offsets must stay 8-byte aligned
                expectedOffset += payloadLength;
            }
        }

        [Fact]
        public void FragmentThenReassemble_RoundTrips()
        {
            byte[] payload = MakePayload(1000);
            byte[] datagram = Ipv4.Build(Src, Dst, Ipv4.ProtocolUdp, payload, identification: 0x3333);

            IReadOnlyList<byte[]> fragments = Ipv4.Fragment(datagram, mtu: 256);

            // The fragmenter is the inverse of the reassembler: feeding its output back must rebuild the payload.
            var reassembler = new Ipv4Reassembler();
            ReadOnlyMemory<byte>? assembled = null;
            foreach (byte[] fragment in fragments)
                assembled = reassembler.Offer(fragment) ?? assembled;

            Assert.NotNull(assembled);
            Assert.Equal(payload, Ipv4.Payload(assembled!.Value).ToArray());
        }

        [Fact]
        public void LargeUdpSend_FragmentedThroughStack_AndReassemblesToOriginal()
        {
            const int mtu = 256;
            IPAddress local = IPAddress.Parse("10.0.0.1");
            IPAddress remote = IPAddress.Parse("8.8.8.8");
            var channel = new CaptureChannel(mtu);
            var stack = new TcpIpStack(channel, local);
            UdpConnection socket = stack.BindUdp(5353);

            byte[] data = MakePayload(700); // larger than one MTU of UDP payload
            socket.SendTo(remote, remotePort: 53, data);

            Assert.True(channel.Written.Count > 1, "oversized UDP datagram should have egressed as multiple fragments");
            Assert.All(channel.Written, f => Assert.True(f.Length <= mtu));

            // Reassemble what actually went on the wire and peel back to the original application payload.
            var reassembler = new Ipv4Reassembler();
            ReadOnlyMemory<byte>? assembled = null;
            foreach (byte[] fragment in channel.Written)
                assembled = reassembler.Offer(fragment) ?? assembled;

            Assert.NotNull(assembled);
            ReadOnlyMemory<byte> udp = Ipv4.Payload(assembled!.Value);
            Assert.Equal((ushort)5353, UdpDatagram.SourcePort(udp.Span));
            Assert.Equal((ushort)53, UdpDatagram.DestinationPort(udp.Span));
            Assert.Equal(data, UdpDatagram.Payload(udp).ToArray());
        }

        static byte[] MakePayload(int length)
        {
            byte[] payload = new byte[length];
            for (int i = 0; i < length; i++) payload[i] = (byte)(i * 7 + 1);
            return payload;
        }

        /// <summary>A channel that records every outbound IP packet and can inject inbound ones.</summary>
        sealed class CaptureChannel : IPacketChannel
        {
            public CaptureChannel(int mtu) => Mtu = mtu;
            public LinkMedium Medium => LinkMedium.Ip;
            public int Mtu { get; }
            public int MaxHeaderLength => 0;
            public bool RequiresLinkAddressResolution => false;
            public event Action<ReadOnlyMemory<byte>>? InboundIpPacket;

            public readonly List<byte[]> Written = new();

            public ValueTask WriteIpPacketAsync(ReadOnlyMemory<byte> ipPacket, CancellationToken cancellationToken = default)
            {
                Written.Add(ipPacket.ToArray());
                return default;
            }

            public void Inject(byte[] ipPacket) => InboundIpPacket?.Invoke(ipPacket);
            public ValueTask DisposeAsync() => default;
        }
    }
}
