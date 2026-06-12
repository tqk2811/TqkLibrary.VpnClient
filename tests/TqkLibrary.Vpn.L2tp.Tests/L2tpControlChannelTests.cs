using TqkLibrary.Vpn.L2tp;
using TqkLibrary.Vpn.L2tp.Enums;
using TqkLibrary.Vpn.L2tp.Models;
using Xunit;

namespace TqkLibrary.Vpn.L2tp.Tests
{
    /// <summary>
    /// Verifies the reliable control channel's retransmit cap: a head message that is never acked is resent at most
    /// <c>maxRetransmits</c> times and then raises <see cref="L2tpControlChannel.Failed"/>; an ack before the cap
    /// clears the queue so the channel never fails.
    /// </summary>
    public class L2tpControlChannelTests
    {
        [Fact]
        public async Task UnackedHead_IsResentUpToTheCap_ThenFailsAndStops()
        {
            int sends = 0;
            Func<ReadOnlyMemory<byte>, Task> sink = _ => { Interlocked.Increment(ref sends); return Task.CompletedTask; };

            const int maxRetransmits = 3;
            using var channel = new L2tpControlChannel(sink, new L2tpRetransmitOptions { Interval = TimeSpan.FromMilliseconds(50), MaxRetransmits = maxRetransmits });

            var failed = new TaskCompletionSource<string>(TaskCreationOptions.RunContinuationsAsynchronously);
            channel.Failed += reason => failed.TrySetResult(reason);

            await channel.SendAsync(L2tpControlMessage.Create(L2tpMessageType.Hello, 0)); // never acked

            Task completed = await Task.WhenAny(failed.Task, Task.Delay(TimeSpan.FromSeconds(5)));
            Assert.True(completed == failed.Task, "the channel never declared the peer unresponsive");

            // Initial send + exactly maxRetransmits resends, then it gives up (no further sends).
            int atFailure = Volatile.Read(ref sends);
            Assert.Equal(1 + maxRetransmits, atFailure);

            await Task.Delay(TimeSpan.FromMilliseconds(250)); // a few more tick intervals
            Assert.Equal(atFailure, Volatile.Read(ref sends));
        }

        [Fact]
        public async Task AckBeforeCap_ClearsQueue_NeverFails()
        {
            int sends = 0;
            Func<ReadOnlyMemory<byte>, Task> sink = _ => { Interlocked.Increment(ref sends); return Task.CompletedTask; };

            const int maxRetransmits = 3;
            using var channel = new L2tpControlChannel(sink, new L2tpRetransmitOptions { Interval = TimeSpan.FromMilliseconds(50), MaxRetransmits = maxRetransmits });

            bool failedFired = false;
            channel.Failed += _ => failedFired = true;

            await channel.SendAsync(L2tpControlMessage.Create(L2tpMessageType.Hello, 0)); // assigned Ns = 0
            // Peer acks Ns 0 with a ZLB carrying Nr = 1 — cumulative ack drops the queued message.
            channel.OnDatagram(L2tpCodec.EncodeControl(new L2tpControlMessage { IsZeroLengthBody = true, Nr = 1 }));

            await Task.Delay(TimeSpan.FromMilliseconds(300)); // well past the cap's worth of ticks

            Assert.False(failedFired, "an acked message must not trip the retransmit cap");
            Assert.True(Volatile.Read(ref sends) < 1 + maxRetransmits, "the channel kept retransmitting an acked message");
        }
    }
}
