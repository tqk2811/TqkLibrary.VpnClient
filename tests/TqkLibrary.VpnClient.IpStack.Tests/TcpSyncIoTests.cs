using System.Diagnostics;
using System.Net;
using System.Text;
using TqkLibrary.VpnClient.IpStack;
using TqkLibrary.VpnClient.IpStack.Tcp;
using TqkLibrary.VpnClient.IpStack.Tcp.Enums;
using Xunit;

namespace TqkLibrary.VpnClient.IpStack.Tests
{
    /// <summary>
    /// The synchronous <see cref="TcpConnection.Read"/> / <see cref="TcpConnection.Send(ReadOnlySpan{byte}, int)"/> /
    /// <see cref="TcpConnection.ThrowIfNotWritable"/>: they block the calling thread inside the connection (Monitor
    /// wait/pulse) rather than waiting on the async path, with the same data, end-of-stream, fault and backpressure
    /// semantics as <c>ReadAsync</c>/<c>SendAsync</c>. The peer is hand-driven (segments injected on the test thread);
    /// every blocking call runs on its own thread and is joined with a timeout, so a regression fails instead of hanging.
    /// </summary>
    public class TcpSyncIoTests
    {
        internal const int Guard = 5000;   // ms: upper bound on any wait, so a broken wake-up fails the test rather than hanging it

        // Zero-window / backpressure tests: no RTO or persist probe may fire while the writer is parked.
        static TcpRetransmitOptions Quiet(int highWaterMark) => new TcpRetransmitOptions(
            initialRto: TimeSpan.FromSeconds(30), minRto: TimeSpan.FromSeconds(30),
            persistMin: TimeSpan.FromSeconds(30), sendBufferHighWaterMark: highWaterMark);

        [Fact]
        public void Read_EmptyBuffer_ReturnsZeroWithoutBlocking()
        {
            using var peer = new HandDrivenPeer();
            var read = Blocking.Start(() => peer.Conn.Read(Span<byte>.Empty));

            Assert.True(read.Wait(Guard));   // no data yet: a zero-length read must not park
            Assert.Equal(0, read.Result);
        }

        [Fact]
        public void Read_BlocksUntilData_ThenReturnsIt()
        {
            using var peer = new HandDrivenPeer();
            byte[] buffer = new byte[16];
            var read = Blocking.Start(() => peer.Conn.Read(buffer));

            Assert.False(read.Wait(100));     // nothing received yet: the reader is parked
            peer.SendData("hello");

            Assert.True(read.Wait(Guard));
            Assert.Equal("hello", Encoding.ASCII.GetString(buffer, 0, read.Result));
        }

        [Fact]
        public void Read_ReturnsZero_OnPeerFin()
        {
            using var peer = new HandDrivenPeer();
            var read = Blocking.Start(() => peer.Conn.Read(new byte[16]));
            Assert.False(read.Wait(50));

            peer.Inject(peer.ServerNxt, peer.ClientIss + 1, TcpFlags.Fin | TcpFlags.Ack, 65535);

            Assert.True(read.Wait(Guard));
            Assert.Equal(0, read.Result);
        }

        [Fact]
        public void Read_Throws_OnPeerRst()
        {
            using var peer = new HandDrivenPeer();
            var read = Blocking.Start(() => peer.Conn.Read(new byte[16]));
            Assert.False(read.Wait(50));

            peer.Inject(peer.ServerNxt, peer.ClientIss + 1, TcpFlags.Rst, 0);

            Assert.True(read.Wait(Guard));
            Assert.IsType<IOException>(read.Error);
        }

        [Fact]
        public void Read_IsReleased_ByAbort()
        {
            using var peer = new HandDrivenPeer();
            var read = Blocking.Start(() => peer.Conn.Read(new byte[16]));
            Assert.False(read.Wait(50));

            peer.Conn.Abort();

            Assert.True(read.Wait(Guard));
            Assert.Equal(0, read.Result);
        }

        [Fact]
        public void Read_IsReleased_ByDispose()
        {
            var peer = new HandDrivenPeer();
            var read = Blocking.Start(() => peer.Conn.Read(new byte[16]));
            Assert.False(read.Wait(50));

            peer.Dispose();

            Assert.True(read.Wait(Guard));
            Assert.Equal(0, read.Result);
        }

        [Fact]
        public void Read_Timeout_ThrowsIOException()
        {
            using var peer = new HandDrivenPeer();
            var sw = Stopwatch.StartNew();

            Assert.Throws<IOException>(() => peer.Conn.Read(new byte[16], timeoutMilliseconds: 100));
            Assert.True(sw.ElapsedMilliseconds >= 90, $"timed out early: {sw.ElapsedMilliseconds} ms");

            // A timed-out read leaves the connection usable.
            peer.SendData("late");
            Assert.Equal(4, peer.Conn.Read(new byte[16], Guard));
        }

        [Fact]
        public void Read_RejectsInvalidTimeout()
        {
            using var peer = new HandDrivenPeer();
            Assert.Throws<ArgumentOutOfRangeException>(() => peer.Conn.Read(new byte[1], -2));
        }

        [Fact]
        public void Send_BlocksAtHighWaterMark_UnderZeroWindow_ThenResumesOnWindowOpen()
        {
            using var peer = new HandDrivenPeer(Quiet(highWaterMark: 4), window: 0);
            var send = Blocking.Start(() => peer.Conn.Send(Encoding.ASCII.GetBytes("0123456789")));

            Assert.False(send.Wait(100));            // 4 bytes buffered, the rest waits for the window
            Assert.Equal(0, peer.DataBytesSent());

            peer.Inject(peer.ServerNxt, peer.ClientIss + 1, TcpFlags.Ack, 65535);

            Assert.True(send.Wait(Guard));
            Assert.Null(send.Error);
            Assert.Equal("0123456789", peer.AssembleData());
        }

        [Fact]
        public void Send_BlockedThenPeerRst_ThrowsIOException()
        {
            using var peer = new HandDrivenPeer(Quiet(highWaterMark: 4), window: 0);
            var send = Blocking.Start(() => peer.Conn.Send(Encoding.ASCII.GetBytes("0123456789")));
            Assert.False(send.Wait(100));

            peer.Inject(peer.ServerNxt, peer.ClientIss + 1, TcpFlags.Rst, 0);

            Assert.True(send.Wait(Guard));
            Assert.IsType<IOException>(send.Error);
        }

        [Fact]
        public void Send_Timeout_ThrowsIOException()
        {
            using var peer = new HandDrivenPeer(Quiet(highWaterMark: 4), window: 0);
            var sw = Stopwatch.StartNew();

            Assert.Throws<IOException>(() => peer.Conn.Send(Encoding.ASCII.GetBytes("0123456789"), timeoutMilliseconds: 100));
            Assert.True(sw.ElapsedMilliseconds >= 90, $"timed out early: {sw.ElapsedMilliseconds} ms");
        }

        [Fact]
        public void ThrowIfNotWritable_DoesNotBlock_WhileTheBufferIsFull_ButThrowsAfterRst()
        {
            using var peer = new HandDrivenPeer(Quiet(highWaterMark: 4), window: 0);
            peer.Conn.Enqueue(Encoding.ASCII.GetBytes("0123456789"));   // past the mark, zero window

            var flush = Blocking.Start(() => peer.Conn.ThrowIfNotWritable());
            Assert.True(flush.Wait(Guard));
            Assert.Null(flush.Error);

            peer.Inject(peer.ServerNxt, peer.ClientIss + 1, TcpFlags.Rst, 0);
            Assert.Throws<IOException>(() => peer.Conn.ThrowIfNotWritable());
        }

        [Fact]
        public async Task SyncAndAsyncReads_Interleaved_KeepByteOrder()
        {
            using var peer = new HandDrivenPeer();
            using var cts = new CancellationTokenSource(Guard);
            peer.SendData("AB");
            peer.SendData("CD");

            var sb = new StringBuilder();
            byte[] one = new byte[1];
            sb.Append((char)one[peer.Conn.Read(one, Guard) - 1]);                              // A
            sb.Append((char)one[await peer.Conn.ReadAsync(one, 0, 1, cts.Token) - 1]);        // B
            byte[] buffer = new byte[8];
            sb.Append(Encoding.ASCII.GetString(buffer, 0, peer.Conn.Read(buffer, Guard)));    // CD

            // A parked async reader, then a sync one, each fed in turn.
            Task<int> pending = peer.Conn.ReadAsync(buffer, 0, buffer.Length, cts.Token);
            peer.SendData("EF");
            sb.Append(Encoding.ASCII.GetString(buffer, 0, await pending));
            var read = Blocking.Start(() => peer.Conn.Read(buffer));
            peer.SendData("GH");
            Assert.True(read.Wait(Guard));
            sb.Append(Encoding.ASCII.GetString(buffer, 0, read.Result));

            Assert.Equal("ABCDEFGH", sb.ToString());
        }

        [Fact]
        public async Task SyncWriterThenAsyncWriter_KeepByteOrder()
        {
            using var peer = new HandDrivenPeer();
            using var cts = new CancellationTokenSource(Guard);

            peer.Conn.Send(Encoding.ASCII.GetBytes("abc"), Guard);
            await peer.Conn.SendAsync(Encoding.ASCII.GetBytes("def"), cts.Token);
            peer.Conn.Send(Encoding.ASCII.GetBytes("ghi"), Guard);

            Assert.Equal("abcdefghi", peer.AssembleData());
        }
    }

    /// <summary>Holds the thread-pool-starvation tests apart: they block every pool worker, which would stall tests running beside them.</summary>
    [CollectionDefinition(nameof(ThreadPoolStarvationCollection), DisableParallelization = true)]
    public sealed class ThreadPoolStarvationCollection { }

    /// <summary>
    /// The point of the synchronous path: a blocked <c>Read</c>/<c>Send</c> is woken directly on its own thread, so it
    /// still completes while every thread-pool worker is busy. The previous implementation — <c>ReadAsync(...).GetAwaiter().GetResult()</c>
    /// — needed a pool thread to run the continuation and stalled here until the pool injected enough threads.
    /// </summary>
    [Collection(nameof(ThreadPoolStarvationCollection))]
    public class TcpSyncIoThreadPoolStarvationTests
    {
        // Generous enough for a slow CI box to schedule the dedicated thread, yet far below what a pool-dependent wake-up
        // needs: its continuation sits behind ~3x MinThreads blocked items, each waiting for the pool's ~0.5 s injection.
        const int StarvedWakeBound = 1500;

        [Fact]
        public void BlockedRead_CompletesWhileTheThreadPoolIsStarved()
        {
            using var peer = new HandDrivenPeer();
            byte[] buffer = new byte[16];
            var read = Blocking.Start(() => peer.Conn.Read(buffer));
            Assert.False(read.Wait(50));

            using (Starve())
            {
                peer.SendData("x");
                Assert.True(read.Wait(StarvedWakeBound), "sync Read needed a thread-pool thread to wake up");
            }
            Assert.Equal(1, read.Result);
        }

        [Fact]
        public void BlockedSend_CompletesWhileTheThreadPoolIsStarved()
        {
            var opts = new TcpRetransmitOptions(
                initialRto: TimeSpan.FromSeconds(30), minRto: TimeSpan.FromSeconds(30),
                persistMin: TimeSpan.FromSeconds(30), sendBufferHighWaterMark: 4);
            using var peer = new HandDrivenPeer(opts, window: 0);
            var send = Blocking.Start(() => peer.Conn.Send(Encoding.ASCII.GetBytes("0123456789")));
            Assert.False(send.Wait(50));

            using (Starve())
            {
                peer.Inject(peer.ServerNxt, peer.ClientIss + 1, TcpFlags.Ack, 65535);
                Assert.True(send.Wait(StarvedWakeBound), "sync Send needed a thread-pool thread to wake up");
            }
            Assert.Null(send.Error);
        }

        // Queues far more blocking work items than the pool has threads, so any work item queued after them (such as an
        // async continuation) waits for the pool's slow thread injection. Disposing releases them.
        internal static IDisposable Starve()
        {
            var gate = new ManualResetEventSlim(false);
            ThreadPool.GetMinThreads(out int workers, out _);
            int count = Math.Max(64, workers * 4);
            for (int i = 0; i < count; i++)
                ThreadPool.UnsafeQueueUserWorkItem(_ => gate.Wait(TcpSyncIoTests.Guard * 2), null);
            Thread.Sleep(50);   // let the idle workers pick up their blocking item
            return new Release(gate);
        }

        sealed class Release : IDisposable
        {
            readonly ManualResetEventSlim _gate;
            public Release(ManualResetEventSlim gate) => _gate = gate;
            // Set, not Dispose: released workers may still be inside Wait, and disposing under them would throw on a pool thread.
            public void Dispose() => _gate.Set();
        }
    }

    /// <summary>Runs a blocking call on a dedicated (non-pool) thread so the test can observe it being parked and woken.</summary>
    static class Blocking
    {
        public static Blocking<T> Start<T>(Func<T> call) => new Blocking<T>(call);

        public static Blocking<bool> Start(Action call) => new Blocking<bool>(() => { call(); return true; });
    }

    sealed class Blocking<T>
    {
        readonly ManualResetEventSlim _done = new(false);
        T _result = default!;
        public Exception? Error { get; private set; }

        public Blocking(Func<T> call)
        {
            var thread = new Thread(() =>
            {
                try { _result = call(); }
                catch (Exception ex) { Error = ex; }
                finally { _done.Set(); }
            }) { IsBackground = true };
            thread.Start();
        }

        public bool Wait(int milliseconds) => _done.Wait(milliseconds);

        public T Result
        {
            get
            {
                if (Error != null) throw new InvalidOperationException("the call threw", Error);
                return _result;
            }
        }
    }

    /// <summary>A real <see cref="TcpConnection"/> as active opener, handshaken synchronously, with the test playing the peer.</summary>
    sealed class HandDrivenPeer : IDisposable
    {
        const ushort ClientPort = 50000, ServerPort = 80;
        static readonly IPAddress ClientIp = IPAddress.Parse("10.0.0.1");
        static readonly IPAddress ServerIp = IPAddress.Parse("10.0.0.2");
        const uint ServerIss = 7000;

        readonly object _lock = new();
        readonly SortedDictionary<uint, byte[]> _dataBySeq = new();

        public TcpConnection Conn { get; }
        public uint ServerNxt { get; private set; }
        public uint ClientIss { get; }

        public HandDrivenPeer(TcpRetransmitOptions? options = null, ushort window = 65535)
        {
            uint? syn = null;
            Conn = new TcpConnection(ClientIp, ClientPort, ServerIp, ServerPort, ip =>
            {
                ReadOnlyMemory<byte> tcp = Ipv4.Payload(ip);
                uint seq = TcpSegment.Sequence(tcp.Span);
                if ((TcpSegment.Flags(tcp.Span) & TcpFlags.Syn) != 0) syn = seq;
                byte[] payload = TcpSegment.Payload(tcp).ToArray();
                if (payload.Length > 0) lock (_lock) _dataBySeq[seq] = payload;
            }, options);
            Conn.StartConnect();   // the SYN is emitted inline
            ClientIss = syn ?? throw new InvalidOperationException("no SYN emitted");
            Inject(ServerIss, ClientIss + 1, TcpFlags.Syn | TcpFlags.Ack, window, mss: 1360);
            ServerNxt = ServerIss + 1;
        }

        public void Inject(uint seq, uint ack, TcpFlags flags, ushort window, ReadOnlySpan<byte> payload = default, ushort mss = 0)
            => Conn.OnSegment(TcpSegment.Build(ServerIp, ClientIp, ServerPort, ClientPort, seq, ack, flags, window, payload, mss));

        /// <summary>Delivers in-order peer data (acknowledging only our SYN).</summary>
        public void SendData(string text)
        {
            byte[] bytes = Encoding.ASCII.GetBytes(text);
            Inject(ServerNxt, ClientIss + 1, TcpFlags.Psh | TcpFlags.Ack, 65535, bytes);
            ServerNxt += (uint)bytes.Length;
        }

        public int DataBytesSent() { lock (_lock) return _dataBySeq.Values.Sum(p => p.Length); }

        public string AssembleData()
        {
            lock (_lock) return string.Concat(_dataBySeq.Values.Select(p => Encoding.ASCII.GetString(p)));
        }

        public void Dispose() => Conn.Dispose();
    }
}
