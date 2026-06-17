using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading;
using System.Threading.Channels;
using System.Threading.Tasks;
using TqkLibrary.VpnClient.Abstractions.Transport.Interfaces;
using TqkLibrary.VpnClient.SoftEther.DataChannel;
using TqkLibrary.VpnClient.SoftEther.DataChannel.Enums;
using TqkLibrary.VpnClient.SoftEther.Models;
using Xunit;

namespace TqkLibrary.VpnClient.SoftEther.Tests
{
    /// <summary>
    /// Offline tests for SoftEther multi-connection (V.4): the <c>additional_connect</c> handshake codec, the welcome
    /// PACK carrying <c>max_connection</c>/<c>half_connection</c>, the direction planner, and the connection mux that
    /// pools N sockets into one data path (round-robin egress + per-connection decode loops, full-duplex and
    /// half-duplex). No network, no Integration trait.
    /// </summary>
    public class SoftEtherMultiConnectionTests
    {
        static SoftEtherHandshake NewHandshake() => new(new SoftEtherAuth(new TqkLibrary.VpnClient.Crypto.Sha0()), new Random(1));

        static byte[] SessionKey(byte start = 0xA0)
        {
            var k = new byte[SoftEtherProtocol.RandomSize];
            for (int i = 0; i < k.Length; i++) k[i] = (byte)(start + i);
            return k;
        }

        // ---- additional_connect codec ----------------------------------------------------------------

        [Fact]
        public void BuildAdditionalConnectPack_HasMethodAndSessionKey()
        {
            byte[] key = SessionKey();
            Pack pack = NewHandshake().BuildAdditionalConnectPack(key);

            Assert.Equal("additional_connect", pack.GetStr("method"));
            Assert.Equal(key, pack.GetData("session_name"));
        }

        [Fact]
        public void BuildAdditionalConnectPack_RejectsWrongSizedKey()
            => Assert.Throws<ArgumentException>(() => NewHandshake().BuildAdditionalConnectPack(new byte[19]));

        [Fact]
        public void ParseAdditionalConnectReply_NonZeroError_Throws()
        {
            var pack = new Pack().SetInt("error", 11u);
            var ex = Assert.Throws<SoftEtherProtocolException>(() => NewHandshake().ParseAdditionalConnectReply(pack));
            Assert.Equal(11u, ex.ErrorCode);
        }

        [Fact]
        public void ParseAdditionalConnectReply_NoError_Succeeds()
            => NewHandshake().ParseAdditionalConnectReply(new Pack().SetInt("error", 0u));

        // ---- welcome PACK: max_connection + half_connection ------------------------------------------

        [Fact]
        public void ParseWelcome_ReadsMaxConnectionAndHalfConnection()
        {
            byte[] key = SessionKey();
            var pack = new Pack()
                .SetInt("error", 0u)
                .SetData("session_name", key)
                .SetInt("max_connection", 8u)
                .SetBool("half_connection", true);

            SoftEtherWelcomeInfo welcome = NewHandshake().ParseWelcome(pack);
            Assert.Equal(key, welcome.SessionKey);
            Assert.Equal(8u, welcome.MaxConnection);
            Assert.True(welcome.HalfConnection);
        }

        [Fact]
        public void ParseWelcome_DefaultsMaxConnectionToOne_WhenAbsentOrZero()
        {
            SoftEtherWelcomeInfo a = NewHandshake().ParseWelcome(
                new Pack().SetInt("error", 0u).SetData("session_name", SessionKey()));
            Assert.Equal(1u, a.MaxConnection);
            Assert.False(a.HalfConnection);

            SoftEtherWelcomeInfo b = NewHandshake().ParseWelcome(
                new Pack().SetInt("error", 0u).SetData("session_name", SessionKey()).SetInt("max_connection", 0u));
            Assert.Equal(1u, b.MaxConnection);
        }

        // ---- direction planner -----------------------------------------------------------------------

        [Fact]
        public void Planner_FullDuplex_AllBoth()
        {
            var d = SoftEtherConnectionDirectionPlanner.Plan(4, halfConnection: false);
            Assert.All(d, x => Assert.Equal(SoftEtherConnectionDirection.Both, x));
        }

        [Fact]
        public void Planner_HalfDuplex_SplitsSendThenReceive_AtLeastOneEach()
        {
            var d = SoftEtherConnectionDirectionPlanner.Plan(4, halfConnection: true);
            Assert.Equal(2, d.Count(x => x == SoftEtherConnectionDirection.Send));
            Assert.Equal(2, d.Count(x => x == SoftEtherConnectionDirection.Receive));
            Assert.Equal(SoftEtherConnectionDirection.Send, d[0]);
            Assert.Equal(SoftEtherConnectionDirection.Receive, d[3]);

            // Odd count: floor split, at least one of each.
            var d3 = SoftEtherConnectionDirectionPlanner.Plan(3, halfConnection: true);
            Assert.Equal(1, d3.Count(x => x == SoftEtherConnectionDirection.Send));
            Assert.Equal(2, d3.Count(x => x == SoftEtherConnectionDirection.Receive));
        }

        [Fact]
        public void Planner_HalfDuplex_SingleConnection_StaysBoth()
        {
            var d = SoftEtherConnectionDirectionPlanner.Plan(1, halfConnection: true);
            Assert.Equal(SoftEtherConnectionDirection.Both, Assert.Single(d));
        }

        // ---- connection mux: full-duplex round-robin egress + merged ingress -------------------------

        [Fact]
        public async Task Mux_FullDuplex_RoundRobinsEgress_AcrossAllConnections()
        {
            // Three full-duplex connections; the server side of each captures what the mux wrote.
            var pairs = Enumerable.Range(0, 3).Select(_ => DuplexPipe.CreatePair()).ToArray();
            var clientEnds = pairs.Select(p => (IByteStreamTransport)p.client).ToList();
            var directions = SoftEtherConnectionDirectionPlanner.Plan(3, halfConnection: false);

            var mux = new SoftEtherMultiConnectionMux(clientEnds, directions, _ => { });
            Assert.Equal(3, mux.ConnectionCount);

            // Send 6 distinct blocks; with round-robin each connection should receive exactly 2.
            for (int i = 0; i < 6; i++)
                await mux.SendBlockAsync(SoftEtherDataFrameCodec.EncodeSingle(new byte[] { (byte)i }));

            for (int c = 0; c < 3; c++)
            {
                var reader = new SoftEtherDataBlockReader(pairs[c].server);
                int blocksOnThisConnection = 0;
                using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(5));
                // Drain whatever is buffered on this connection (we wrote then never more, so read until we have 2).
                while (blocksOnThisConnection < 2)
                {
                    var frames = await reader.ReadBlockAsync(cts.Token);
                    Assert.NotEmpty(frames);
                    blocksOnThisConnection++;
                }
                Assert.Equal(2, blocksOnThisConnection);
            }

            await mux.DisposeAsync();
        }

        [Fact]
        public async Task Mux_MergesInboundFrames_FromAllConnections_PreservingPerConnectionOrder()
        {
            var pairs = Enumerable.Range(0, 2).Select(_ => DuplexPipe.CreatePair()).ToArray();
            var clientEnds = pairs.Select(p => (IByteStreamTransport)p.client).ToList();
            var directions = SoftEtherConnectionDirectionPlanner.Plan(2, halfConnection: false);

            var received = Channel.CreateUnbounded<byte[]>();
            var mux = new SoftEtherMultiConnectionMux(clientEnds, directions, _ => { });
            mux.InboundFrame += m => received.Writer.TryWrite(m.ToArray());
            mux.StartReceiveLoops();

            // Server pushes frames on both connections; the mux must surface every one.
            await pairs[0].server.WriteAsync(SoftEtherDataFrameCodec.EncodeSingle(new byte[] { 1, 2 }));
            await pairs[1].server.WriteAsync(SoftEtherDataFrameCodec.EncodeSingle(new byte[] { 3, 4 }));
            await pairs[0].server.WriteAsync(SoftEtherDataFrameCodec.EncodeSingle(new byte[] { 5, 6 }));

            using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(5));
            var got = new List<byte[]>();
            for (int i = 0; i < 3; i++) got.Add(await received.Reader.ReadAsync(cts.Token));

            // All three arrived (union of both connections).
            Assert.Contains(got, x => x.SequenceEqual(new byte[] { 1, 2 }));
            Assert.Contains(got, x => x.SequenceEqual(new byte[] { 3, 4 }));
            Assert.Contains(got, x => x.SequenceEqual(new byte[] { 5, 6 }));
            // Per-connection order preserved: {1,2} before {5,6} (same connection 0).
            int idx12 = got.FindIndex(x => x.SequenceEqual(new byte[] { 1, 2 }));
            int idx56 = got.FindIndex(x => x.SequenceEqual(new byte[] { 5, 6 }));
            Assert.True(idx12 < idx56);

            await mux.DisposeAsync();
        }

        [Fact]
        public async Task Mux_HalfDuplex_SendsOnlyOnSendConnections_ReceivesOnlyOnReceiveConnections()
        {
            // 2 connections: index 0 = Send-only, index 1 = Receive-only.
            var pairs = Enumerable.Range(0, 2).Select(_ => DuplexPipe.CreatePair()).ToArray();
            var clientEnds = pairs.Select(p => (IByteStreamTransport)p.client).ToList();
            var directions = SoftEtherConnectionDirectionPlanner.Plan(2, halfConnection: true);
            Assert.Equal(SoftEtherConnectionDirection.Send, directions[0]);
            Assert.Equal(SoftEtherConnectionDirection.Receive, directions[1]);

            var received = Channel.CreateUnbounded<byte[]>();
            var mux = new SoftEtherMultiConnectionMux(clientEnds, directions, _ => { });
            mux.InboundFrame += m => received.Writer.TryWrite(m.ToArray());
            mux.StartReceiveLoops();

            // Egress must all go out the send-only connection (index 0).
            for (int i = 0; i < 4; i++)
                await mux.SendBlockAsync(SoftEtherDataFrameCodec.EncodeSingle(new byte[] { (byte)i }));

            using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(5));
            var sendReader = new SoftEtherDataBlockReader(pairs[0].server);
            for (int i = 0; i < 4; i++)
                Assert.NotEmpty(await sendReader.ReadBlockAsync(cts.Token));

            // Ingress must be read only on the receive-only connection (index 1).
            await pairs[1].server.WriteAsync(SoftEtherDataFrameCodec.EncodeSingle(new byte[] { 0xEE }));
            byte[] inbound = await received.Reader.ReadAsync(cts.Token);
            Assert.Equal(new byte[] { 0xEE }, inbound);

            await mux.DisposeAsync();
        }

        [Fact]
        public async Task Mux_RaisesLinkLostOnce_WhenAConnectionCloses()
        {
            var pairs = Enumerable.Range(0, 2).Select(_ => DuplexPipe.CreatePair()).ToArray();
            var clientEnds = pairs.Select(p => (IByteStreamTransport)p.client).ToList();
            var directions = SoftEtherConnectionDirectionPlanner.Plan(2, halfConnection: false);

            int lostCount = 0;
            var lost = new TaskCompletionSource<bool>();
            var mux = new SoftEtherMultiConnectionMux(clientEnds, directions, _ =>
            {
                Interlocked.Increment(ref lostCount);
                lost.TrySetResult(true);
            });
            mux.StartReceiveLoops();

            // Close both server ends; the mux must report link-loss exactly once (one-shot guard).
            await pairs[0].server.DisposeAsync();
            await pairs[1].server.DisposeAsync();

            using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(5));
            await lost.Task.WaitAsync(cts.Token);
            await Task.Delay(50, cts.Token);   // give the second loop a chance to (not) re-raise
            Assert.Equal(1, lostCount);

            await mux.DisposeAsync();
        }

        [Fact]
        public void Mux_RejectsAllReceiveOnlyConnections()
        {
            var (a, _) = DuplexPipe.CreatePair();
            Assert.Throws<ArgumentException>(() => new SoftEtherMultiConnectionMux(
                new IByteStreamTransport[] { a },
                new[] { SoftEtherConnectionDirection.Receive },
                _ => { }));
        }
    }
}
