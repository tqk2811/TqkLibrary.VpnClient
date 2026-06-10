using System.Net;
using TqkLibrary.Vpn.Abstractions.Channels.Enums;
using TqkLibrary.Vpn.Abstractions.Channels.Interfaces;
using TqkLibrary.Vpn.IpStack;
using TqkLibrary.Vpn.IpStack.Tcp;
using Xunit;

namespace TqkLibrary.Vpn.IpStack.Tests
{
    public class IcmpStackTests
    {
        [Fact]
        public void Icmpv4_Echo_RoundTrips_WithChecksum()
        {
            byte[] data = { 0x01, 0x02, 0x03, 0x04, 0x05 };

            byte[] msg = Icmpv4.BuildEcho(Icmpv4.TypeEchoRequest, 0xABCD, 0x0007, data);

            Assert.Equal(Icmpv4.TypeEchoRequest, Icmpv4.Type(msg));
            Assert.Equal(0, Icmpv4.Code(msg));
            Assert.Equal(0xABCD, Icmpv4.Identifier(msg));
            Assert.Equal(0x0007, Icmpv4.Sequence(msg));
            Assert.Equal(data, Icmpv4.Payload(msg).ToArray());
            Assert.True(Icmpv4.VerifyChecksum(msg));

            msg[Icmpv4.HeaderSize] ^= 0xFF; // corrupt the payload
            Assert.False(Icmpv4.VerifyChecksum(msg));
        }

        [Fact]
        public void Icmpv4_DestinationUnreachable_QuotesOffendingDatagram()
        {
            // An offending IPv4 packet (20-byte header + 12 bytes payload) to be quoted.
            byte[] offending = Ipv4.Build(IPAddress.Parse("10.0.0.1"), IPAddress.Parse("8.8.8.8"),
                Ipv4.ProtocolIcmp, new byte[12], identification: 1);

            byte[] msg = Icmpv4.BuildDestinationUnreachable(Icmpv4.CodePortUnreachable, offending);

            Assert.Equal(Icmpv4.TypeDestinationUnreachable, Icmpv4.Type(msg));
            Assert.Equal(Icmpv4.CodePortUnreachable, Icmpv4.Code(msg));
            Assert.True(Icmpv4.VerifyChecksum(msg));

            // RFC 792 quote = original IP header (20) + first 8 payload bytes = 28 bytes.
            byte[] quoted = Icmpv4.Payload(msg).ToArray();
            Assert.Equal(28, quoted.Length);
            Assert.Equal(offending.AsSpan(0, 28).ToArray(), quoted);
        }

        [Fact]
        public async Task Ping_EchoesThroughTwoStacks()
        {
            var link = new LoopbackPair();
            IPAddress ipA = IPAddress.Parse("10.0.0.1"), ipB = IPAddress.Parse("10.0.0.2");
            var stackA = new TcpIpStack(link.A, ipA);
            _ = new TcpIpStack(link.B, ipB); // stack B auto-replies to Echo Requests

            using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(5));
            byte[] data = System.Text.Encoding.ASCII.GetBytes("hello-icmp");
            PingReply reply = await stackA.PingAsync(ipB, data, cts.Token);

            Assert.Equal(ipB, reply.RemoteAddress);
            Assert.Equal(data, reply.Data);
            Assert.True(reply.RoundTripTime >= TimeSpan.Zero);
        }

        [Fact]
        public async Task Ping_Cancellation_Throws()
        {
            var channel = new CaptureChannel(); // no peer → no reply ever arrives
            var stack = new TcpIpStack(channel, IPAddress.Parse("10.0.0.1"));

            using var cts = new CancellationTokenSource();
            Task<PingReply> ping = stack.PingAsync(IPAddress.Parse("10.0.0.2"), default, cts.Token);
            cts.CancelAfter(TimeSpan.FromMilliseconds(50));

            await Assert.ThrowsAnyAsync<OperationCanceledException>(() => ping);
        }

        [Fact]
        public async Task Ping_DestinationUnreachable_Throws()
        {
            var channel = new CaptureChannel();
            var stack = new TcpIpStack(channel, IPAddress.Parse("10.0.0.1"));
            IPAddress remote = IPAddress.Parse("10.0.0.2");

            Task<PingReply> ping = stack.PingAsync(remote); // runs synchronously up to the first await → packet captured
            byte[] sentIp = channel.TakeOutbound();         // the Echo Request IPv4 packet we emitted

            // The gateway answers with Destination Unreachable quoting our Echo Request.
            byte[] error = Icmpv4.BuildDestinationUnreachable(Icmpv4.CodePortUnreachable, sentIp);
            byte[] errorIp = Ipv4.Build(remote, IPAddress.Parse("10.0.0.1"), Ipv4.ProtocolIcmp, error, identification: 99);
            channel.Inject(errorIp);

            IcmpUnreachableException ex = await Assert.ThrowsAsync<IcmpUnreachableException>(() => ping);
            Assert.Equal(Icmpv4.CodePortUnreachable, ex.Code);
        }

        /// <summary>An in-memory channel that records outbound packets and lets the test inject inbound ones.</summary>
        sealed class CaptureChannel : IPacketChannel
        {
            readonly System.Collections.Concurrent.BlockingCollection<byte[]> _outbound = new();

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

        /// <summary>Two in-memory IP packet channels wired back to back (A writes → B's inbound, and vice versa).</summary>
        sealed class LoopbackPair
        {
            public LoopbackPair()
            {
                A = new Channel();
                B = new Channel();
                ((Channel)A).Peer = (Channel)B;
                ((Channel)B).Peer = (Channel)A;
            }

            public IPacketChannel A { get; }
            public IPacketChannel B { get; }

            sealed class Channel : IPacketChannel
            {
                public Channel? Peer;
                public LinkMedium Medium => LinkMedium.Ip;
                public int Mtu => 1400;
                public int MaxHeaderLength => 0;
                public bool RequiresLinkAddressResolution => false;
                public event Action<ReadOnlyMemory<byte>>? InboundIpPacket;

                public ValueTask WriteIpPacketAsync(ReadOnlyMemory<byte> ipPacket, CancellationToken cancellationToken = default)
                {
                    byte[] copy = ipPacket.ToArray();
                    Channel? peer = Peer;
                    _ = Task.Run(() => peer?.InboundIpPacket?.Invoke(copy));
                    return default;
                }

                public ValueTask DisposeAsync() => default;
            }
        }
    }
}
