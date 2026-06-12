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
    /// Inbound packets aimed at a local port with no socket no longer drop silently: UDP draws an ICMP port
    /// unreachable (RFC 792 / RFC 1122 §3.2.2.1) and TCP draws a RST (RFC 793 p.36).
    /// </summary>
    public class ClosedPortResponseTests
    {
        static readonly IPAddress Local = IPAddress.Parse("10.0.0.1");  // our tunnel address
        static readonly IPAddress Remote = IPAddress.Parse("8.8.8.8");  // the internet host that sent the packet

        [Fact]
        public void InboundUdp_ToClosedPort_RepliesIcmpPortUnreachable()
        {
            var channel = new CaptureChannel();
            _ = new TcpIpStack(channel, Local);

            byte[] inbound = BuildUdp(srcPort: 53, dstPort: 9999, MakePayload(20)); // 9999 has no bound socket
            channel.Inject(inbound);

            byte[] reply = Assert.Single(channel.Written);
            Assert.Equal(Ipv4.ProtocolIcmp, Ipv4.Protocol(reply));
            Assert.Equal(Local, Ipv4.Source(reply));   // error is sourced from us...
            Assert.Equal(Remote, Ipv4.Destination(reply)); // ...back to the sender

            ReadOnlyMemory<byte> icmp = Ipv4.Payload(reply);
            Assert.Equal(Icmpv4.TypeDestinationUnreachable, Icmpv4.Type(icmp.Span));
            Assert.Equal(Icmpv4.CodePortUnreachable, Icmpv4.Code(icmp.Span));
            Assert.True(Icmpv4.VerifyChecksum(icmp.Span));

            // RFC 792: the error quotes the offending IP header (20) + first 8 payload bytes = 28 bytes.
            byte[] quoted = Icmpv4.Payload(icmp).ToArray();
            Assert.Equal(28, quoted.Length);
            Assert.Equal(inbound.AsSpan(0, 28).ToArray(), quoted);
        }

        [Fact]
        public async Task InboundUdp_ToOpenPort_IsDelivered_NoIcmpError()
        {
            var channel = new CaptureChannel();
            var stack = new TcpIpStack(channel, Local);
            UdpConnection socket = stack.BindUdp(5353);

            byte[] payload = MakePayload(16);
            channel.Inject(BuildUdp(srcPort: 53, dstPort: 5353, payload));

            Assert.Empty(channel.Written); // an open port must not draw an error
            UdpReceiveResult got = await socket.ReceiveAsync(new CancellationTokenSource(TimeSpan.FromSeconds(1)).Token);
            Assert.Equal(payload, got.Data);
            Assert.Equal((ushort)53, got.RemotePort);
        }

        [Fact]
        public void InboundTcpSyn_ToClosedPort_RepliesRstAck()
        {
            var channel = new CaptureChannel();
            _ = new TcpIpStack(channel, Local);

            // A bare SYN to a port we are not listening on — the classic "connection refused" case.
            byte[] syn = BuildTcp(srcPort: 40000, dstPort: 80, sequence: 1000, acknowledgment: 0, TcpFlags.Syn, mss: 1460);
            channel.Inject(syn);

            ReadOnlyMemory<byte> rst = TcpReplyTo(channel);
            Assert.Equal(TcpFlags.Rst | TcpFlags.Ack, TcpSegment.Flags(rst.Span)); // no ACK to borrow → seq 0, ACK the SYN
            Assert.Equal(0u, TcpSegment.Sequence(rst.Span));
            Assert.Equal(1001u, TcpSegment.Acknowledgment(rst.Span));             // SYN consumes one sequence number
            Assert.Equal((ushort)80, TcpSegment.SourcePort(rst.Span));
            Assert.Equal((ushort)40000, TcpSegment.DestinationPort(rst.Span));
        }

        [Fact]
        public void InboundTcpAck_ToClosedPort_RepliesRst_BorrowingAck()
        {
            var channel = new CaptureChannel();
            _ = new TcpIpStack(channel, Local);

            // A stale data segment carrying an ACK for a connection we already tore down.
            byte[] segment = BuildTcp(srcPort: 40000, dstPort: 80, sequence: 5000, acknowledgment: 7777,
                TcpFlags.Ack | TcpFlags.Psh, payload: MakePayload(4));
            channel.Inject(segment);

            ReadOnlyMemory<byte> rst = TcpReplyTo(channel);
            Assert.Equal(TcpFlags.Rst, TcpSegment.Flags(rst.Span)); // borrows the segment's ACK as its sequence
            Assert.Equal(7777u, TcpSegment.Sequence(rst.Span));
            Assert.Equal(0u, TcpSegment.Acknowledgment(rst.Span));
        }

        [Fact]
        public void InboundTcpRst_ToClosedPort_IsSilent()
        {
            var channel = new CaptureChannel();
            _ = new TcpIpStack(channel, Local);

            byte[] rst = BuildTcp(srcPort: 40000, dstPort: 80, sequence: 1000, acknowledgment: 2000, TcpFlags.Rst);
            channel.Inject(rst);

            Assert.Empty(channel.Written); // never answer a RST with a RST (no reset storm)
        }

        static ReadOnlyMemory<byte> TcpReplyTo(CaptureChannel channel)
        {
            byte[] reply = Assert.Single(channel.Written);
            Assert.Equal(Ipv4.ProtocolTcp, Ipv4.Protocol(reply));
            Assert.Equal(Local, Ipv4.Source(reply));
            Assert.Equal(Remote, Ipv4.Destination(reply));
            return Ipv4.Payload(reply);
        }

        static byte[] BuildUdp(ushort srcPort, ushort dstPort, byte[] payload)
        {
            byte[] udp = UdpDatagram.Build(Remote, Local, srcPort, dstPort, payload);
            return Ipv4.Build(Remote, Local, Ipv4.ProtocolUdp, udp, identification: 0x1234);
        }

        static byte[] BuildTcp(ushort srcPort, ushort dstPort, uint sequence, uint acknowledgment, TcpFlags flags, ushort mss = 0, byte[]? payload = null)
        {
            byte[] tcp = TcpSegment.Build(Remote, Local, srcPort, dstPort, sequence, acknowledgment, flags, window: 65535, payload ?? ReadOnlySpan<byte>.Empty, mss);
            return Ipv4.Build(Remote, Local, Ipv4.ProtocolTcp, tcp, identification: 0x1234);
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
