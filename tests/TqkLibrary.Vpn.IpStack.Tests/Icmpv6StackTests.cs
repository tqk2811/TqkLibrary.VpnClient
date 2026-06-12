using System.Linq;
using System.Net;
using System.Threading.Channels;
using TqkLibrary.Vpn.Abstractions.Channels.Enums;
using TqkLibrary.Vpn.Abstractions.Channels.Interfaces;
using TqkLibrary.Vpn.IpStack;
using Xunit;

namespace TqkLibrary.Vpn.IpStack.Tests
{
    /// <summary>ICMPv6 (RFC 4443) through the stack: Echo ping round-trip, concurrent pings, cancellation, and Destination Unreachable.</summary>
    public class Icmpv6StackTests
    {
        static readonly IPAddress IpA = IPAddress.Parse("fd00::1");
        static readonly IPAddress IpB = IPAddress.Parse("fd00::2");

        [Fact]
        public async Task Ping_EchoesThroughTwoStacks()
        {
            var link = new LoopbackPair();
            var stackA = new TcpIpStack(link.A, IpA);
            _ = new TcpIpStack(link.B, IpB); // stack B auto-replies to Echo Requests

            using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(5));
            byte[] data = System.Text.Encoding.ASCII.GetBytes("hello-icmpv6");
            PingReply reply = await stackA.PingAsync(IpB, data, cts.Token);

            Assert.Equal(IpB, reply.RemoteAddress);
            Assert.Equal(data, reply.Data);
            Assert.True(reply.RoundTripTime >= TimeSpan.Zero);
        }

        [Fact]
        public async Task Ping_ManyConcurrent_EachGetsItsOwnReply()
        {
            var link = new LoopbackPair();
            var stackA = new TcpIpStack(link.A, IpA);
            _ = new TcpIpStack(link.B, IpB);

            using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(10));
            Task<PingReply>[] pings = Enumerable.Range(0, 32)
                .Select(i => stackA.PingAsync(IpB, new byte[] { (byte)i, 0x5A }, cts.Token))
                .ToArray();

            PingReply[] replies = await Task.WhenAll(pings);
            for (int i = 0; i < replies.Length; i++)
                Assert.Equal(new byte[] { (byte)i, 0x5A }, replies[i].Data);
        }

        [Fact]
        public async Task Ping_Cancellation_Throws()
        {
            var channel = new CaptureChannel(); // no peer → no reply ever arrives
            var stack = new TcpIpStack(channel, IpA);

            using var cts = new CancellationTokenSource();
            Task<PingReply> ping = stack.PingAsync(IpB, default, cts.Token);
            cts.CancelAfter(TimeSpan.FromMilliseconds(50));

            await Assert.ThrowsAnyAsync<OperationCanceledException>(() => ping);
        }

        [Fact]
        public async Task Ping_DestinationUnreachable_Throws()
        {
            var channel = new CaptureChannel();
            var stack = new TcpIpStack(channel, IpA);

            Task<PingReply> ping = stack.PingAsync(IpB); // runs synchronously up to the first await → packet captured
            byte[] sentIp = channel.TakeOutbound();        // the Echo Request IPv6 packet we emitted

            // The gateway answers with ICMPv6 Destination Unreachable quoting our Echo Request.
            byte[] error = Icmpv6.BuildDestinationUnreachable(Icmpv6.CodePortUnreachable, sentIp, IpB, IpA);
            byte[] errorIp = Ipv6.Build(IpB, IpA, Ipv6.NextHeaderIcmpv6, error);
            channel.Inject(errorIp);

            IcmpUnreachableException ex = await Assert.ThrowsAsync<IcmpUnreachableException>(() => ping);
            Assert.Equal(Icmpv6.CodePortUnreachable, ex.Code);
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
