using System.Net;
using TqkLibrary.Vpn.Abstractions.Channels.Enums;
using TqkLibrary.Vpn.Abstractions.Channels.Interfaces;
using TqkLibrary.Vpn.IpStack;
using TqkLibrary.Vpn.IpStack.Tcp;
using TqkLibrary.Vpn.IpStack.Tcp.Enums;
using TqkLibrary.Vpn.IpStack.Udp;
using Xunit;

namespace TqkLibrary.Vpn.IpStack.Tests
{
    /// <summary>
    /// IPv6 closed-port responses: a UDP datagram to a port with no socket draws an ICMPv6 Destination Unreachable /
    /// Port Unreachable (RFC 4443 §3.1); a TCP segment to a port with no connection draws a RST (RFC 793); a RST is
    /// answered with silence.
    /// </summary>
    public class ClosedPortResponseV6Tests
    {
        static readonly IPAddress Local = IPAddress.Parse("fd00::1");   // our tunnel address
        static readonly IPAddress Remote = IPAddress.Parse("2001:db8::99"); // the host that sent the packet

        [Fact]
        public void InboundUdp_ToClosedPort_RepliesIcmpv6PortUnreachable()
        {
            var channel = new CaptureChannel();
            _ = new TcpIpStack(channel, Local);

            byte[] inbound = BuildUdp(srcPort: 53, dstPort: 9999, MakePayload(20)); // no socket on 9999
            channel.Inject(inbound);

            byte[] reply = Assert.Single(channel.Written);
            Assert.Equal(6, Ipv6.Version(reply));
            Assert.Equal(Ipv6.NextHeaderIcmpv6, Ipv6.NextHeader(reply));
            Assert.Equal(Local, Ipv6.Source(reply));     // error sourced from us...
            Assert.Equal(Remote, Ipv6.Destination(reply)); // ...back to the sender

            ReadOnlyMemory<byte> icmp = reply.AsMemory(Ipv6.HeaderLength);
            Assert.Equal(Icmpv6.TypeDestinationUnreachable, Icmpv6.Type(icmp.Span));
            Assert.Equal(Icmpv6.CodePortUnreachable, Icmpv6.Code(icmp.Span));
            Assert.True(Icmpv6.VerifyChecksum(icmp.Span, Local, Remote));

            // The whole offending packet is quoted (it is well under the min-MTU quote limit).
            byte[] quoted = Icmpv6.Payload(icmp).ToArray();
            Assert.Equal(inbound, quoted);
        }

        [Fact]
        public async Task InboundUdp_ToOpenPort_IsDelivered_NoIcmpError()
        {
            var channel = new CaptureChannel();
            var stack = new TcpIpStack(channel, Local);
            UdpConnection socket = stack.BindUdp(5353);

            byte[] payload = MakePayload(16);
            channel.Inject(BuildUdp(srcPort: 53, dstPort: 5353, payload));

            Assert.Empty(channel.Written);
            UdpReceiveResult got = await socket.ReceiveAsync(new CancellationTokenSource(TimeSpan.FromSeconds(1)).Token);
            Assert.Equal(payload, got.Data);
            Assert.Equal((ushort)53, got.RemotePort);
            Assert.Equal(Remote, got.RemoteAddress);
        }

        [Fact]
        public void InboundTcpSyn_ToClosedPort_RepliesRstAck()
        {
            var channel = new CaptureChannel();
            _ = new TcpIpStack(channel, Local);

            byte[] syn = BuildTcp(srcPort: 40000, dstPort: 80, sequence: 1000, acknowledgment: 0, TcpFlags.Syn, mss: 1340);
            channel.Inject(syn);

            ReadOnlyMemory<byte> rst = TcpReplyTo(channel);
            Assert.Equal(TcpFlags.Rst | TcpFlags.Ack, TcpSegment.Flags(rst.Span));
            Assert.Equal(0u, TcpSegment.Sequence(rst.Span));
            Assert.Equal(1001u, TcpSegment.Acknowledgment(rst.Span)); // SYN consumes one sequence number
            Assert.Equal((ushort)80, TcpSegment.SourcePort(rst.Span));
            Assert.Equal((ushort)40000, TcpSegment.DestinationPort(rst.Span));
        }

        [Fact]
        public void InboundTcpRst_ToClosedPort_IsSilent()
        {
            var channel = new CaptureChannel();
            _ = new TcpIpStack(channel, Local);

            byte[] rst = BuildTcp(srcPort: 40000, dstPort: 80, sequence: 1000, acknowledgment: 2000, TcpFlags.Rst);
            channel.Inject(rst);

            Assert.Empty(channel.Written); // never answer a RST with a RST
        }

        static ReadOnlyMemory<byte> TcpReplyTo(CaptureChannel channel)
        {
            byte[] reply = Assert.Single(channel.Written);
            Assert.Equal(6, Ipv6.Version(reply));
            Assert.Equal(Ipv6.NextHeaderTcp, Ipv6.NextHeader(reply));
            Assert.Equal(Local, Ipv6.Source(reply));
            Assert.Equal(Remote, Ipv6.Destination(reply));
            return reply.AsMemory(Ipv6.HeaderLength);
        }

        static byte[] BuildUdp(ushort srcPort, ushort dstPort, byte[] payload)
        {
            byte[] udp = UdpDatagram.Build(Remote, Local, srcPort, dstPort, payload);
            return Ipv6.Build(Remote, Local, Ipv6.NextHeaderUdp, udp);
        }

        static byte[] BuildTcp(ushort srcPort, ushort dstPort, uint sequence, uint acknowledgment, TcpFlags flags, ushort mss = 0, byte[]? payload = null)
        {
            byte[] tcp = TcpSegment.Build(Remote, Local, srcPort, dstPort, sequence, acknowledgment, flags, window: 65535, payload ?? ReadOnlySpan<byte>.Empty, mss);
            return Ipv6.Build(Remote, Local, Ipv6.NextHeaderTcp, tcp);
        }

        static byte[] MakePayload(int length)
        {
            byte[] payload = new byte[length];
            for (int i = 0; i < length; i++) payload[i] = (byte)(i * 7 + 1);
            return payload;
        }

        /// <summary>An in-memory IP channel that records outbound packets and injects inbound ones synchronously.</summary>
        sealed class CaptureChannel : IPacketChannel
        {
            public LinkMedium Medium => LinkMedium.Ip;
            public int Mtu => 1400;
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
