using System;
using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;
using TqkLibrary.VpnClient.Pptp.Gre;
using Xunit;

namespace TqkLibrary.VpnClient.Pptp.Tests
{
    /// <summary>
    /// Offline coverage for the PPTP GRE data-plane channel (RFC 2637 §4): two channels over an in-memory
    /// datagram link exchange PPP frames; wrong-Call-ID packets are dropped; sequence numbers increment and the
    /// piggy-backed acknowledgment tracks the highest received sequence.
    /// </summary>
    public class PptpGreChannelTests
    {
        const ushort CallA = 0x0101; // A's local Call ID (peer addresses this to A)
        const ushort CallB = 0x0202; // B's local Call ID

        [Fact]
        public async Task Frame_Sent_On_A_Surfaces_On_B_WithCorrectPayload()
        {
            var link = new LoopbackDatagramLink();
            // A sends to peer (B) → packets stamped with B's Call ID; B's localCallId = CallB.
            var a = new PptpGreChannel(link.A, localCallId: CallA, peerCallId: CallB);
            var b = new PptpGreChannel(link.B, localCallId: CallB, peerCallId: CallA);

            var received = new TaskCompletionSource<byte[]>(TaskCreationOptions.RunContinuationsAsynchronously);
            b.FrameReceived += f => received.TrySetResult(f.ToArray());
            a.Start();
            b.Start();

            byte[] frame = { 0xFF, 0x03, 0x00, 0x21, 0x11, 0x22, 0x33 };
            await a.SendAsync(frame);

            byte[] got = await WithTimeout(received.Task);
            Assert.Equal(frame, got); // FF 03 re-prepended → matches the canonical form

            await a.DisposeAsync();
            await b.DisposeAsync();
        }

        [Fact]
        public async Task Packet_With_Wrong_CallId_Is_Dropped()
        {
            var link = new LoopbackDatagramLink();
            // B expects CallB, but A is (mis)configured to stamp a different Call ID → B drops it.
            var a = new PptpGreChannel(link.A, localCallId: CallA, peerCallId: 0x9999);
            var b = new PptpGreChannel(link.B, localCallId: CallB, peerCallId: CallA);

            int count = 0;
            b.FrameReceived += _ => Interlocked.Increment(ref count);
            a.Start();
            b.Start();

            await a.SendAsync(new byte[] { 0xFF, 0x03, 0x00, 0x21, 0x01 });
            await Task.Delay(150);
            Assert.Equal(0, count);

            await a.DisposeAsync();
            await b.DisposeAsync();
        }

        [Fact]
        public async Task SequenceNumbers_Increment_And_Ack_Piggybacks_HighestReceived()
        {
            var link = new LoopbackDatagramLink();
            var a = new PptpGreChannel(link.A, localCallId: CallA, peerCallId: CallB);

            // Sniff what A puts on the wire by decoding B-side datagrams directly.
            var seqs = new List<uint>();
            var sniffed = new TaskCompletionSource<bool>(TaskCreationOptions.RunContinuationsAsynchronously);
            byte[] buffer = new byte[2048];

            a.Start();
            await a.SendAsync(new byte[] { 0xFF, 0x03, 0x00, 0x21, 0xA0 });
            await a.SendAsync(new byte[] { 0xFF, 0x03, 0x00, 0x21, 0xA1 });

            for (int i = 0; i < 2; i++)
            {
                int n = await link.B.ReceiveAsync(buffer);
                Assert.True(PptpGreCodec.TryDecode(buffer.AsSpan(0, n), out PptpGrePacket? p));
                seqs.Add(p!.SequenceNumber!.Value);
            }
            Assert.Equal(new uint[] { 0, 1 }, seqs.ToArray());

            await a.DisposeAsync();
        }

        [Fact]
        public async Task Ack_Piggybacks_HighestReceivedSeq_On_Next_Send()
        {
            var link = new LoopbackDatagramLink();
            var a = new PptpGreChannel(link.A, localCallId: CallA, peerCallId: CallB);
            a.Start();

            // Deliver a payload packet to A bearing sequence 5 (addressed to A's local Call ID).
            var inbound = new PptpGrePacket { CallId = CallA, SequenceNumber = 5, Payload = new byte[] { 0x00, 0x21, 0x77 } };
            await link.B.SendAsync(PptpGreCodec.Encode(inbound));

            // Wait until A surfaced it (so ack bookkeeping is updated) then have A send — the ack must carry 5.
            var got = new TaskCompletionSource<bool>(TaskCreationOptions.RunContinuationsAsynchronously);
            a.FrameReceived += _ => got.TrySetResult(true);
            await WithTimeout(got.Task);

            await a.SendAsync(new byte[] { 0xFF, 0x03, 0x00, 0x21, 0xB0 });

            byte[] buffer = new byte[2048];
            int n = await link.B.ReceiveAsync(buffer);
            Assert.True(PptpGreCodec.TryDecode(buffer.AsSpan(0, n), out PptpGrePacket? p));
            Assert.Equal(5u, p!.AckNumber);

            await a.DisposeAsync();
        }

        static async Task<T> WithTimeout<T>(Task<T> task)
        {
            Task completed = await Task.WhenAny(task, Task.Delay(5000));
            Assert.Same(task, completed);
            return await task;
        }
    }
}
