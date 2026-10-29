using System.Collections.Concurrent;
using System.Diagnostics;
using System.Net;
using TqkLibrary.VpnClient.Abstractions.Channels.Enums;
using TqkLibrary.VpnClient.Abstractions.Channels.Interfaces;
using TqkLibrary.VpnClient.IpStack;
using TqkLibrary.VpnClient.IpStack.Udp;
using Xunit;

namespace TqkLibrary.VpnClient.IpStack.Tests
{
    /// <summary>
    /// The stack's ordered egress queue: every outbound packet reaches <see cref="IPacketChannel.WriteIpPacketAsync"/>
    /// from one drain loop, in <c>SendIp</c> order, and a channel that throws, faults, stalls or is slow never reaches
    /// back into the caller.
    /// </summary>
    public class EgressQueueTests
    {
        const int Guard = 5000;
        static readonly IPAddress Local = IPAddress.Parse("10.0.0.1");
        static readonly IPAddress Remote = IPAddress.Parse("10.0.0.2");

        [Fact]
        public async Task ChannelThatThrows_IsCounted_AndLaterPacketsStillGoOut()
        {
            var channel = new ScriptedChannel((n, _) => n switch
            {
                0 => throw new InvalidOperationException("synchronous throw"),
                1 => new ValueTask(Task.FromException(new IOException("asynchronous fault"))),
                _ => default,
            });
            using var stack = new TcpIpStack(channel, Local);
            UdpConnection udp = stack.BindUdp();

            for (int i = 0; i < 3; i++)
                udp.SendTo(Remote, 9, Index(i));   // must not throw even though the channel does

            await channel.WaitForCallsAsync(3);
            Assert.Equal(2, stack.EgressFaults);
            Assert.Equal(2, IndexOf(channel.Delivered.Single()));

            udp.SendTo(Remote, 9, Index(3));
            await channel.WaitForCallsAsync(4);
            Assert.Equal(3, IndexOf(channel.Delivered.Last()));
        }

        [Fact]
        public async Task SlowChannel_SeesPacketsInSendOrder()
        {
            var random = new Random(1234);
            var channel = new ScriptedChannel((_, _) => new ValueTask(Task.Delay(random.Next(0, 3))));
            using var stack = new TcpIpStack(channel, Local);
            UdpConnection udp = stack.BindUdp();

            const int count = 200;
            for (int i = 0; i < count; i++)
                udp.SendTo(Remote, 9, Index(i));

            await channel.WaitForCallsAsync(count);
            Assert.Equal(Enumerable.Range(0, count), channel.Delivered.Select(IndexOf));
            Assert.Equal(1, channel.MaxConcurrent);   // never two writes in flight at once
        }

        [Fact]
        public async Task StuckChannel_QueuesUpToCapacity_ThenDropsWithoutBlocking()
        {
            var stuck = new TaskCompletionSource<bool>(TaskCreationOptions.RunContinuationsAsynchronously);
            var channel = new ScriptedChannel((_, _) => new ValueTask(stuck.Task));
            using var stack = new TcpIpStack(channel, Local);
            UdpConnection udp = stack.BindUdp();

            udp.SendTo(Remote, 9, Index(0));
            await channel.WaitForCallsAsync(1);   // packet 0 is in flight: the queue is empty again

            const int extra = 50;
            var sw = Stopwatch.StartNew();
            for (int i = 1; i <= TcpIpStack.EgressCapacity + extra; i++)
                udp.SendTo(Remote, 9, Index(i));
            sw.Stop();

            Assert.True(sw.ElapsedMilliseconds < Guard, "SendIp blocked on a stuck channel");
            Assert.Equal(extra, stack.EgressDropped);

            stuck.TrySetResult(true);   // the channel recovers: the queued packets drain in order, the dropped ones are gone
            await channel.WaitForCallsAsync(1 + TcpIpStack.EgressCapacity);
            Assert.Equal(Enumerable.Range(0, 1 + TcpIpStack.EgressCapacity), channel.Delivered.Select(IndexOf));
        }

        [Fact]
        public async Task Dispose_CancelsTheWriteInFlight_AndStopsEgress()
        {
            var channel = new ScriptedChannel((_, token) => new ValueTask(Task.Delay(Timeout.Infinite, token)));
            var stack = new TcpIpStack(channel, Local);
            UdpConnection udp = stack.BindUdp();
            udp.SendTo(Remote, 9, Index(0));
            udp.SendTo(Remote, 9, Index(1));
            await channel.WaitForCallsAsync(1);

            var sw = Stopwatch.StartNew();
            stack.Dispose();
            // The stop timeout is 2 s; cancelling returns at once, so anything well under it shows the wait was not used.
            Assert.True(sw.ElapsedMilliseconds < 1500, "Dispose waited for the timeout instead of cancelling");
            Assert.True(channel.LastToken.IsCancellationRequested);

            // After Dispose: silently discarded, not counted as a drop. SendIp decides synchronously (no writer may be
            // claimed once disposed), so no delay is needed before checking that the channel saw nothing new.
            udp.SendTo(Remote, 9, Index(2));
            Assert.Equal(1, channel.Calls);
            Assert.Equal(0, stack.EgressDropped);
            Assert.Equal(0, stack.EgressFaults);
        }

        [Fact]
        public async Task Dispose_DoesNotHang_OnAChannelThatIgnoresCancellation()
        {
            var never = new TaskCompletionSource<bool>();
            var channel = new ScriptedChannel((_, _) => new ValueTask(never.Task));
            var stack = new TcpIpStack(channel, Local);
            stack.BindUdp().SendTo(Remote, 9, Index(0));
            await channel.WaitForCallsAsync(1);

            var sw = Stopwatch.StartNew();
            stack.Dispose();
            Assert.True(sw.ElapsedMilliseconds < Guard);
        }

        [Fact]
        public void SynchronousChannel_IsWrittenInlineOnTheCallersThread()
        {
            var channel = new ScriptedChannel((_, _) => default);
            using var stack = new TcpIpStack(channel, Local);
            UdpConnection udp = stack.BindUdp();

            udp.SendTo(Remote, 9, Index(0));

            // Fast path: no write was in flight, so the packet reached the channel before SendTo returned, on this thread.
            Assert.Equal(1, channel.Calls);
            Assert.Equal(Environment.CurrentManagedThreadId, channel.LastThreadId);
            Assert.Equal(0, IndexOf(channel.Delivered.Single()));
        }

        [Fact]
        public async Task MixedSyncAndAsyncChannel_KeepsSendOrder_OneWriteAtATime()
        {
            // Every third write goes asynchronous: the writer role passes from the inline caller to the async drain and
            // back, while packets sent meanwhile must queue behind it.
            var channel = new ScriptedChannel((n, _) => n % 3 == 0 ? new ValueTask(Task.Delay(1)) : default);
            using var stack = new TcpIpStack(channel, Local);
            UdpConnection udp = stack.BindUdp();

            const int count = 300;
            for (int i = 0; i < count; i++)
                udp.SendTo(Remote, 9, Index(i));

            await stack.FlushEgressAsync().WaitAsync(TimeSpan.FromMilliseconds(Guard));
            Assert.Equal(Enumerable.Range(0, count), channel.Delivered.Select(IndexOf));
            Assert.Equal(1, channel.MaxConcurrent);
            Assert.Equal(0, stack.EgressDropped);
        }

        [Fact]
        public async Task SendIp_ReenteredFromInsideTheChannelWrite_IsQueued_NotRecursed()
        {
            UdpConnection? udp = null;
            ScriptedChannel? channel = null;
            channel = new ScriptedChannel((n, _) =>
            {
                // Like an inbound handler running on the writing thread: the write of packet 0 triggers another send.
                if (n == 0) udp!.SendTo(Remote, 9, Index(1));
                // Recursion would show up as a second call while this one is still in progress.
                Assert.Equal(n + 1, channel!.Calls);
                return default;
            });
            using var stack = new TcpIpStack(channel, Local);
            udp = stack.BindUdp();

            udp.SendTo(Remote, 9, Index(0));

            await stack.FlushEgressAsync().WaitAsync(TimeSpan.FromMilliseconds(Guard));
            Assert.Equal(new[] { 0, 1 }, channel.Delivered.Select(IndexOf));
            Assert.Equal(1, channel.MaxConcurrent);
            Assert.Equal(0, stack.EgressFaults);
        }

        /// <summary>
        /// The fast path's purpose: with a channel that completes synchronously, egress needs no thread-pool thread, so
        /// a starved pool cannot stall it (a queue-only design hopped every packet, bare ACKs included, through the pool).
        /// </summary>
        [Collection(nameof(ThreadPoolStarvationCollection))]
        public class StarvedPool
        {
            const int StarvedWakeBound = 1500;   // same reasoning as TcpSyncIoThreadPoolStarvationTests

            [Fact]
            public void SynchronousChannel_StillReceivesPackets_WhileTheThreadPoolIsStarved()
            {
                var channel = new ScriptedChannel((_, _) => default);
                using var stack = new TcpIpStack(channel, Local);
                UdpConnection udp = stack.BindUdp();

                using (TcpSyncIoThreadPoolStarvationTests.Starve())
                {
                    var send = Blocking.Start(() => udp.SendTo(Remote, 9, Index(0)));
                    Assert.True(send.Wait(StarvedWakeBound), "SendTo did not return");
                    var sw = Stopwatch.StartNew();
                    while (channel.Calls < 1 && sw.ElapsedMilliseconds < StarvedWakeBound) Thread.Sleep(5);
                    Assert.True(channel.Calls == 1, "egress needed a thread-pool thread to reach the channel");
                }
            }
        }

        internal static byte[] Index(int i) => BitConverter.GetBytes(i);

        internal static int IndexOf(byte[] ipPacket) => BitConverter.ToInt32(ipPacket, 20 + 8);   // IPv4 header + UDP header

        /// <summary>Records every write; <c>behavior(callIndex, token)</c> decides how the write completes.</summary>
        internal sealed class ScriptedChannel : IPacketChannel
        {
            readonly Func<int, CancellationToken, ValueTask> _behavior;
            readonly ConcurrentQueue<byte[]> _delivered = new();
            int _calls;
            int _inFlight;

            public ScriptedChannel(Func<int, CancellationToken, ValueTask> behavior) => _behavior = behavior;

            public LinkMedium Medium => LinkMedium.Ip;
            public int Mtu => 1400;
            public int MaxHeaderLength => 0;
            public bool RequiresLinkAddressResolution => false;
#pragma warning disable CS0067   // never raised: these tests only look at egress
            public event Action<ReadOnlyMemory<byte>>? InboundIpPacket;
#pragma warning restore CS0067

            public int Calls => Volatile.Read(ref _calls);
            public int MaxConcurrent;
            public CancellationToken LastToken;
            public int LastThreadId;
            /// <summary>Packets whose write completed successfully, in completion order.</summary>
            public IReadOnlyList<byte[]> Delivered => _delivered.ToArray();

            public ValueTask WriteIpPacketAsync(ReadOnlyMemory<byte> ipPacket, CancellationToken cancellationToken = default)
            {
                int now = Interlocked.Increment(ref _inFlight);
                if (now > MaxConcurrent) MaxConcurrent = now;
                LastToken = cancellationToken;
                LastThreadId = Environment.CurrentManagedThreadId;
                int n = Interlocked.Increment(ref _calls) - 1;
                ValueTask pending;
                try
                {
                    // Not an async method: a throw from _behavior leaves this call synchronously, like a channel
                    // implementation that fails before it returns a task.
                    pending = _behavior(n, cancellationToken);
                }
                catch
                {
                    Interlocked.Decrement(ref _inFlight);
                    throw;
                }
                return CompleteAsync(pending, ipPacket.ToArray());
            }

            async ValueTask CompleteAsync(ValueTask pending, byte[] copy)
            {
                try
                {
                    await pending.ConfigureAwait(false);
                    _delivered.Enqueue(copy);
                }
                finally
                {
                    Interlocked.Decrement(ref _inFlight);
                }
            }

            public ValueTask DisposeAsync() => default;

            public async Task WaitForCallsAsync(int count)
            {
                var sw = Stopwatch.StartNew();
                while (Calls < count)
                {
                    if (sw.ElapsedMilliseconds > Guard) throw new TimeoutException($"Only {Calls}/{count} writes reached the channel.");
                    await Task.Delay(5);
                }
                // Let the last write record its completion before the caller inspects Delivered.
                await Task.Delay(20);
            }
        }
    }
}
