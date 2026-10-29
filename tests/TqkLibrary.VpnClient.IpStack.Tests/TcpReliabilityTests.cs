using System.Net;
using System.Text;
using TqkLibrary.VpnClient.IpStack;
using TqkLibrary.VpnClient.IpStack.Tcp;
using TqkLibrary.VpnClient.IpStack.Tcp.Enums;
using Xunit;

namespace TqkLibrary.VpnClient.IpStack.Tests
{
    /// <summary>
    /// Offline tests for the TCP send-path reliability added in slice 1: RFC 6298 retransmission/RTO with a
    /// give-up cap, sliding-window flow control, and the zero-window persist probe. The peer is hand-driven —
    /// the test constructs a <see cref="TcpConnection"/> directly with a custom send callback that captures every
    /// outbound IP packet, then injects inbound segments by hand — so loss, window advertisements and ACK timing
    /// are fully under the test's control (no real channel, no real socket). Timers are shrunk to a few tens of
    /// milliseconds via <see cref="TcpRetransmitOptions"/> so the retransmit/persist/give-up paths run fast.
    /// </summary>
    public class TcpReliabilityTests
    {
        [Fact]
        public async Task Retransmit_ResendsUnackedData_ThenStopsOnceAcked()
        {
            var opts = new TcpRetransmitOptions(
                initialRto: TimeSpan.FromMilliseconds(40), minRto: TimeSpan.FromMilliseconds(40),
                maxRto: TimeSpan.FromMilliseconds(200), maxRetransmits: 8);
            using var h = new ClientHarness(opts);
            using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(5));
            await h.HandshakeAsync(window: 65535, cts.Token);

            byte[] data = Encoding.ASCII.GetBytes("DATA");
            h.Conn.Enqueue(data);

            // The same data segment must be retransmitted (same SEQ + payload) because no ACK arrived.
            uint dataSeq = (await h.WaitForAsync(s => s.HasData, cts.Token)).Seq;
            await h.WaitUntilAsync(() => h.CountData(dataSeq, data) >= 2, cts.Token);
            Assert.True(h.CountData(dataSeq, data) >= 2);

            // Acknowledge it; retransmission must cease.
            h.Inject(seq: h.ServerNxt, ack: dataSeq + (uint)data.Length, TcpFlags.Ack, window: 65535);
            await Task.Delay(150, cts.Token);
            int settled = h.CountData(dataSeq, data);
            await Task.Delay(150, cts.Token);
            Assert.Equal(settled, h.CountData(dataSeq, data));
        }

        [Fact]
        public async Task Retransmit_GivesUp_FaultsConnectionAfterMaxRetries()
        {
            var opts = new TcpRetransmitOptions(
                initialRto: TimeSpan.FromMilliseconds(20), minRto: TimeSpan.FromMilliseconds(20),
                maxRto: TimeSpan.FromMilliseconds(60), maxRetransmits: 3);
            using var h = new ClientHarness(opts);
            using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(5));
            await h.HandshakeAsync(window: 65535, cts.Token);

            bool closed = false;
            h.Conn.Closed += () => closed = true;

            h.Conn.Enqueue(Encoding.ASCII.GetBytes("X")); // never acknowledged

            byte[] buffer = new byte[8];
            await Assert.ThrowsAsync<IOException>(() => h.Conn.ReadAsync(buffer, 0, buffer.Length, cts.Token));
            Assert.True(closed);
        }

        [Fact]
        public async Task FlowControl_NeverSendsBeyondAdvertisedWindow()
        {
            // A long RTO keeps retransmission out of the picture so the in-flight assertion is purely about the window.
            var opts = new TcpRetransmitOptions(initialRto: TimeSpan.FromSeconds(30), minRto: TimeSpan.FromSeconds(30));
            using var h = new ClientHarness(opts);
            using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(5));
            await h.HandshakeAsync(window: 4, cts.Token);

            byte[] message = Encoding.ASCII.GetBytes("0123456789"); // 10 bytes; window only admits 4
            h.Conn.Enqueue(message);

            await h.WaitUntilAsync(() => h.DataBytesSent() == 4, cts.Token);
            Assert.Equal(4, h.DataBytesSent()); // capped at the advertised window

            // Acknowledge the first 4 bytes and open the window; the remaining 6 must now flow, in order.
            uint firstDataSeq = h.FirstDataSeq();
            h.Inject(seq: h.ServerNxt, ack: firstDataSeq + 4, TcpFlags.Ack, window: 10);
            await h.WaitUntilAsync(() => h.DataBytesSent() == 10, cts.Token);
            Assert.Equal("0123456789", h.AssembleData());
        }

        [Fact]
        public async Task ZeroWindow_PersistProbe_DribblesThenFlushesWhenWindowOpens()
        {
            var opts = new TcpRetransmitOptions(
                initialRto: TimeSpan.FromSeconds(30), minRto: TimeSpan.FromSeconds(30),       // no RTO interference
                persistMin: TimeSpan.FromMilliseconds(30), persistMax: TimeSpan.FromMilliseconds(120));
            using var h = new ClientHarness(opts);
            using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(5));
            await h.HandshakeAsync(window: 0, cts.Token);

            byte[] message = Encoding.ASCII.GetBytes("abc");
            h.Conn.Enqueue(message);
            Assert.Equal(0, h.DataBytesSent()); // zero window blocks the initial send

            // The persist timer must probe with a single byte even though the window stayed shut.
            await h.WaitUntilAsync(() => h.DataBytesSent() >= 1, cts.Token);
            Assert.Equal(1, h.DataBytesSent());

            // Acknowledge the probe byte and open the window; the rest flushes and reassembles in order.
            uint firstDataSeq = h.FirstDataSeq();
            h.Inject(seq: h.ServerNxt, ack: firstDataSeq + 1, TcpFlags.Ack, window: 10);
            await h.WaitUntilAsync(() => h.DataBytesSent() == 3, cts.Token);
            Assert.Equal("abc", h.AssembleData());
        }

        [Fact]
        public async Task ZeroWindow_WithWindowScaling_ReopenByPureWindowUpdate_DoesNotStayStuck()
        {
            // Reproduces the live V.2/V.4 stall (HTTP upload through the tunnel): the peer negotiates RFC 7323 window
            // scaling, fills its receive buffer and advertises a zero window so the client enters zero-window persist.
            // The peer then ACKs the persist probe but keeps advertising zero (still full). Finally the peer's app drains
            // its buffer and it sends a PURE WINDOW UPDATE — a bare ACK with the SAME ack number (no new data was sent so
            // its seq is unchanged, and the client sent nothing new so the ack does not advance) but a non-zero scaled
            // window. The client must apply that reopened window and resume sending; the bug left _sndWnd stuck at 0 and
            // the connection dribbled one byte per persist tick forever.
            var opts = new TcpRetransmitOptions(
                initialRto: TimeSpan.FromSeconds(30), minRto: TimeSpan.FromSeconds(30),       // no RTO interference
                persistMin: TimeSpan.FromMilliseconds(20), persistMax: TimeSpan.FromMilliseconds(40));
            using var h = new ClientHarness(opts);
            using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(5));
            await h.HandshakeAsync(window: 0, windowScale: 7, cts.Token); // peer scales its window by 2^7 = 128

            byte[] message = new byte[8000];
            for (int i = 0; i < message.Length; i++) message[i] = (byte)i;
            h.Conn.Enqueue(message);
            Assert.Equal(0, h.DataBytesSent()); // zero window blocks the initial send

            // Persist probes with a single byte; ACK that probe but keep the window shut (peer still full).
            await h.WaitUntilAsync(() => h.DataBytesSent() >= 1, cts.Token);
            uint probeSeq = h.FirstDataSeq();
            h.Inject(seq: h.ServerNxt, ack: probeSeq + 1, TcpFlags.Ack, window: 0); // probe acked, still zero window

            // Let persist run a few more ticks (the connection is now idle-but-blocked behind the zero window).
            await Task.Delay(80, cts.Token);

            // PURE WINDOW UPDATE: same seq (peer sent no data), same ack (probeSeq+1 — we sent nothing new), window now
            // non-zero (raw 200 << 7 = 25600). This must reopen the send window and unblock the transfer.
            h.Inject(seq: h.ServerNxt, ack: probeSeq + 1, TcpFlags.Ack, window: 200);

            // Drive the rest of the transfer, ACKing each burst so congestion control opens; the message must complete.
            uint ackNo = probeSeq + 1;
            for (int round = 0; round < 30; round++)
            {
                if (h.DataBytesSent() >= message.Length) break;
                await Task.Delay(15, cts.Token);
                uint highest = h.HighestDataSeqEnd();
                if (highest > ackNo) { ackNo = highest; h.Inject(seq: h.ServerNxt, ack: ackNo, TcpFlags.Ack, window: 200); }
            }
            Assert.Equal(message.Length, h.DataBytesSent());
        }

        [Fact]
        public async Task ZeroWindow_PeerDataThenReopen_DownloadConcurrentWithUpload_DoesNotStayStuck()
        {
            // Bidirectional HTTP (upload body while the server streams a response): while the client is sending, the peer
            // sends a DATA segment (download) that ALSO advertises window 0 (its receive buffer momentarily full). Later
            // the peer reopens with a pure window update whose seq sits AFTER that data. The window-update sequencing
            // (RFC 793 WL1/WL2) must still accept the reopened window and unblock the upload.
            var opts = new TcpRetransmitOptions(
                initialRto: TimeSpan.FromSeconds(30), minRto: TimeSpan.FromSeconds(30),
                persistMin: TimeSpan.FromMilliseconds(20), persistMax: TimeSpan.FromMilliseconds(40));
            using var h = new ClientHarness(opts);
            using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(5));
            await h.HandshakeAsync(window: 0, windowScale: 7, cts.Token);

            byte[] message = new byte[8000];
            for (int i = 0; i < message.Length; i++) message[i] = (byte)i;
            h.Conn.Enqueue(message);

            await h.WaitUntilAsync(() => h.DataBytesSent() >= 1, cts.Token);
            uint probeSeq = h.FirstDataSeq();

            // Peer sends us a chunk of download data, advertising window 0 in the same segment.
            byte[] download = Encoding.ASCII.GetBytes("HELLO");
            h.Inject(seq: h.ServerNxt, ack: probeSeq + 1, TcpFlags.Psh | TcpFlags.Ack, window: 0, payload: download);
            uint serverAfterData = h.ServerNxt + (uint)download.Length;

            await Task.Delay(60, cts.Token);

            // Pure window update with the post-data seq and a non-zero scaled window → must reopen the send window.
            h.Inject(seq: serverAfterData, ack: probeSeq + 1, TcpFlags.Ack, window: 200);

            uint ackNo = probeSeq + 1;
            for (int round = 0; round < 30; round++)
            {
                if (h.DataBytesSent() >= message.Length) break;
                await Task.Delay(15, cts.Token);
                uint highest = h.HighestDataSeqEnd();
                if (highest > ackNo) { ackNo = highest; h.Inject(seq: serverAfterData, ack: ackNo, TcpFlags.Ack, window: 200); }
            }
            Assert.Equal(message.Length, h.DataBytesSent());
        }

        [Fact]
        public async Task SmallWindow_SenderSwsAvoidance_DoesNotDribbleTinySegments()
        {
            // Reproduces the live V.2/V.4 "1 byte/segment" stall. The peer's receiver opens its window only a few bytes
            // at a time (a slow-reading app), so each ACK exposes a tiny `usable = window − inflight`. Without sender-side
            // Silly Window Syndrome avoidance (RFC 9293 §3.8.6.2.1 / RFC 1122 §4.2.3.4) the stack emits one tiny segment
            // per ACK — the silly-window dribble seen on the wire. With SWS avoidance the stack must hold back until it can
            // send a full-size (MSS) segment (or the buffer empties / a sizeable fraction of the window opens), so the data
            // travels in a few large segments instead of thousands of byte-sized ones.
            var opts = new TcpRetransmitOptions(
                initialRto: TimeSpan.FromSeconds(30), minRto: TimeSpan.FromSeconds(30),   // no RTO interference
                persistMin: TimeSpan.FromSeconds(30));                                    // no persist (window never zero)
            using var h = new ClientHarness(opts);
            using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(5));
            // Peer negotiates window scaling and first advertises a large window (as a real server does), then shrinks it
            // to a trickle — exactly the live shape (server seen at win 502 wscale 7, opening only crumbs as its app reads).
            await h.HandshakeAsync(window: 502, windowScale: 7, cts.Token); // 502 << 7 ≈ 64 KB max window ever seen

            byte[] message = new byte[40000]; // larger than the initial cwnd (~13.6 KB) so a tail remains after the first burst
            for (int i = 0; i < message.Length; i++) message[i] = (byte)i;
            h.Conn.Enqueue(message);
            await h.WaitUntilAsync(() => h.DataBytesSent() > 0, cts.Token);
            int afterFirstBurst = h.SegmentCount(); // the (legitimate) full-size segments sent while the window was large

            // Now the peer's window collapses to a trickle: each ACK advances by what it consumed but re-advertises only a
            // crumb of room (raw 1 << 7 = 128, still « MSS 1360). SWS avoidance must refuse to emit sub-MSS segments for it.
            uint ackNo = h.HighestDataSeqEnd();
            for (int round = 0; round < 200; round++)
            {
                await Task.Delay(5, cts.Token);
                uint highest = h.HighestDataSeqEnd();
                if (highest > ackNo) ackNo = highest;
                h.Inject(seq: h.ServerNxt, ack: ackNo, TcpFlags.Ack, window: 1); // dangling crumb, far below MSS
                if (h.SegmentCount() - afterFirstBurst > 60) break;
            }

            // Count the segments emitted AFTER the window collapsed. SWS avoidance holds the tail back (no sub-MSS sends),
            // so this stays ~0; the bug ships ~one segment per crumb, exploding the count.
            int dribbleSegs = h.SegmentCount() - afterFirstBurst;
            Assert.True(dribbleSegs < 10, $"sender SWS avoidance failed: emitted {dribbleSegs} tiny segments after the window shrank (silly-window dribble), max tail payload {h.MaxSegmentPayload()}");
        }

        // ---- SendAsync backpressure + fault propagation (P0.3) ---------------------------------------------

        [Fact]
        public async Task SendAsync_BufferFull_BlocksUntilWindowDrains()
        {
            var opts = new TcpRetransmitOptions(
                initialRto: TimeSpan.FromSeconds(30), minRto: TimeSpan.FromSeconds(30),   // no RTO interference
                persistMin: TimeSpan.FromSeconds(30),                                      // persist probe won't fire during the test
                sendBufferHighWaterMark: 4);
            using var h = new ClientHarness(opts);
            using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(5));
            await h.HandshakeAsync(window: 0, cts.Token);   // zero window: nothing can leave the send buffer

            // 10 bytes but the buffer caps at 4 → SendAsync enqueues 4, then parks waiting for the window to drain it.
            Task send = h.Conn.SendAsync(Encoding.ASCII.GetBytes("0123456789"), cts.Token);
            await Task.Delay(100, cts.Token);
            Assert.False(send.IsCompleted);                 // backpressure: the writer is blocked, not buffering unbounded
            Assert.Equal(0, h.DataBytesSent());             // zero window: nothing on the wire yet

            // Open the window; the buffered bytes flush, the buffer drains, and SendAsync enqueues the rest and completes.
            h.Inject(seq: h.ServerNxt, ack: h.ClientIss + 1, TcpFlags.Ack, window: 65535);
            await send;
            await h.WaitUntilAsync(() => h.DataBytesSent() == 10, cts.Token);
            Assert.Equal("0123456789", h.AssembleData());
        }

        [Fact]
        public async Task SendAsync_AfterReset_ThrowsIOException()
        {
            using var h = new ClientHarness(new TcpRetransmitOptions());
            using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(5));
            await h.HandshakeAsync(window: 65535, cts.Token);

            h.Inject(seq: h.ServerNxt, ack: h.ClientIss + 1, TcpFlags.Rst, window: 0);   // peer resets → connection faults
            await h.WaitUntilAsync(() => h.Conn.State == TcpState.Closed, cts.Token);

            await Assert.ThrowsAsync<IOException>(() => h.Conn.SendAsync(Encoding.ASCII.GetBytes("X"), cts.Token));
        }

        [Fact]
        public async Task FlushAsync_AfterReset_ThrowsIOException()
        {
            using var h = new ClientHarness(new TcpRetransmitOptions());
            using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(5));
            await h.HandshakeAsync(window: 65535, cts.Token);

            h.Inject(seq: h.ServerNxt, ack: h.ClientIss + 1, TcpFlags.Rst, window: 0);
            await h.WaitUntilAsync(() => h.Conn.State == TcpState.Closed, cts.Token);

            // FlushAsync is SendAsync(empty): no data to enqueue, but it still surfaces the fault instead of swallowing it.
            await Assert.ThrowsAsync<IOException>(() => h.Conn.SendAsync(ReadOnlyMemory<byte>.Empty, cts.Token));
        }

        // ---- Slice 2: out-of-order reassembly --------------------------------------------------------------

        [Fact]
        public async Task Reassembly_OutOfOrderSegments_DeliveredInOrder()
        {
            using var h = new ClientHarness(new TcpRetransmitOptions());
            using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(5));
            await h.HandshakeAsync(window: 65535, cts.Token);

            // The peer sends the second half first; the stack must buffer it until the first half fills the gap.
            h.Inject(seq: h.ServerNxt + 5, ack: h.ClientIss + 1, TcpFlags.Psh | TcpFlags.Ack, window: 65535, Encoding.ASCII.GetBytes("WORLD"));
            h.Inject(seq: h.ServerNxt, ack: h.ClientIss + 1, TcpFlags.Psh | TcpFlags.Ack, window: 65535, Encoding.ASCII.GetBytes("HELLO"));

            Assert.Equal("HELLOWORLD", await ReadExactAsync(h.Conn, 10, cts.Token));
        }

        [Fact]
        public async Task Reassembly_DuplicateAndOldSegments_Ignored()
        {
            using var h = new ClientHarness(new TcpRetransmitOptions());
            using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(5));
            await h.HandshakeAsync(window: 65535, cts.Token);

            byte[] hello = Encoding.ASCII.GetBytes("HELLO"), world = Encoding.ASCII.GetBytes("WORLD");
            uint ack = h.ClientIss + 1;
            h.Inject(h.ServerNxt + 5, ack, TcpFlags.Psh | TcpFlags.Ack, 65535, world); // buffered out of order
            h.Inject(h.ServerNxt + 5, ack, TcpFlags.Psh | TcpFlags.Ack, 65535, world); // exact duplicate (deduped)
            h.Inject(h.ServerNxt, ack, TcpFlags.Psh | TcpFlags.Ack, 65535, hello);     // fills the gap → drains both
            h.Inject(h.ServerNxt, ack, TcpFlags.Psh | TcpFlags.Ack, 65535, hello);     // wholly-old retransmit (dropped)

            Assert.Equal("HELLOWORLD", await ReadExactAsync(h.Conn, 10, cts.Token));
        }

        // ---- Slice 2: half-close FSM ----------------------------------------------------------------------

        [Fact]
        public async Task HalfClose_AckOfFin_GoesFinWait2_ThenPeerFin_GoesTimeWait()
        {
            using var h = new ClientHarness(new TcpRetransmitOptions());
            using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(5));
            await h.HandshakeAsync(window: 65535, cts.Token);

            h.Conn.CloseSend();
            Assert.Equal(TcpState.FinWait1, h.Conn.State);

            h.Inject(h.ServerNxt, ack: h.ClientIss + 2, TcpFlags.Ack, window: 65535); // acks our FIN only
            Assert.Equal(TcpState.FinWait2, h.Conn.State);

            h.Inject(h.ServerNxt, ack: h.ClientIss + 2, TcpFlags.Fin | TcpFlags.Ack, window: 65535);
            Assert.Equal(TcpState.TimeWait, h.Conn.State);
        }

        [Fact]
        public async Task HalfClose_SimultaneousClose_GoesClosing_ThenAck_GoesTimeWait()
        {
            using var h = new ClientHarness(new TcpRetransmitOptions());
            using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(5));
            await h.HandshakeAsync(window: 65535, cts.Token);

            h.Conn.CloseSend();
            Assert.Equal(TcpState.FinWait1, h.Conn.State);

            // Peer FIN that does NOT acknowledge our FIN (ack only covers our SYN) → simultaneous close.
            h.Inject(h.ServerNxt, ack: h.ClientIss + 1, TcpFlags.Fin | TcpFlags.Ack, window: 65535);
            Assert.Equal(TcpState.Closing, h.Conn.State);

            // The peer then acknowledges our FIN → CLOSING → TIME-WAIT.
            h.Inject(h.ServerNxt + 1, ack: h.ClientIss + 2, TcpFlags.Ack, window: 65535);
            Assert.Equal(TcpState.TimeWait, h.Conn.State);
        }

        [Fact]
        public async Task HalfClose_TimeWait_LingersThenClosed_RaisesClosed()
        {
            var opts = new TcpRetransmitOptions(timeWait: TimeSpan.FromMilliseconds(40));
            using var h = new ClientHarness(opts);
            using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(5));
            await h.HandshakeAsync(window: 65535, cts.Token);

            bool closed = false;
            h.Conn.Closed += () => closed = true;

            h.Conn.CloseSend();
            h.Inject(h.ServerNxt, ack: h.ClientIss + 2, TcpFlags.Fin | TcpFlags.Ack, window: 65535); // → TIME-WAIT
            Assert.Equal(TcpState.TimeWait, h.Conn.State);

            await h.WaitUntilAsync(() => h.Conn.State == TcpState.Closed, cts.Token);
            Assert.Equal(TcpState.Closed, h.Conn.State);
            Assert.True(closed);
        }

        [Fact]
        public async Task PassiveClose_PeerFinFirst_CloseWait_ThenLastAck_ThenClosed()
        {
            using var h = new ClientHarness(new TcpRetransmitOptions());
            using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(5));
            await h.HandshakeAsync(window: 65535, cts.Token);

            bool closed = false;
            h.Conn.Closed += () => closed = true;

            // Peer closes first → CLOSE-WAIT, reader sees end-of-stream.
            h.Inject(h.ServerNxt, ack: h.ClientIss + 1, TcpFlags.Fin | TcpFlags.Ack, window: 65535);
            Assert.Equal(TcpState.CloseWait, h.Conn.State);
            Assert.Equal(0, await h.Conn.ReadAsync(new byte[4], 0, 4, cts.Token));

            // We close our side → LAST-ACK; the peer's ACK of our FIN completes the close.
            h.Conn.CloseSend();
            Assert.Equal(TcpState.LastAck, h.Conn.State);
            h.Inject(h.ServerNxt + 1, ack: h.ClientIss + 2, TcpFlags.Ack, window: 65535);
            Assert.Equal(TcpState.Closed, h.Conn.State);
            Assert.True(closed);
        }

        static async Task<string> ReadExactAsync(TcpConnection conn, int count, CancellationToken cancellationToken)
        {
            byte[] buffer = new byte[count];
            int offset = 0;
            while (offset < count)
            {
                int read = await conn.ReadAsync(buffer, offset, count - offset, cancellationToken).ConfigureAwait(false);
                if (read == 0) break;
                offset += read;
            }
            return Encoding.ASCII.GetString(buffer, 0, offset);
        }

        /// <summary>Drives a real <see cref="TcpConnection"/> as the active opener and lets the test play the peer by hand.</summary>
        sealed class ClientHarness : IDisposable
        {
            public const ushort ClientPort = 50000, ServerPort = 80;
            public static readonly IPAddress ClientIp = IPAddress.Parse("10.0.0.1");
            public static readonly IPAddress ServerIp = IPAddress.Parse("10.0.0.2");

            readonly object _lock = new();
            readonly List<Seg> _outbox = new();

            public TcpConnection Conn { get; }
            public uint ServerNxt { get; private set; }
            public uint ClientIss { get; private set; }

            public ClientHarness(TcpRetransmitOptions options)
            {
                Conn = new TcpConnection(ClientIp, ClientPort, ServerIp, ServerPort, OnSendIp, options);
            }

            void OnSendIp(byte[] ipPacket)
            {
                Seg seg = Seg.Parse(ipPacket);
                lock (_lock) _outbox.Add(seg);
            }

            Seg[] Snapshot() { lock (_lock) return _outbox.ToArray(); }

            public void Inject(uint seq, uint ack, TcpFlags flags, ushort window, ReadOnlySpan<byte> payload = default, ushort mss = 0)
            {
                byte[] tcp = TcpSegment.Build(ServerIp, ClientIp, ServerPort, ClientPort, seq, ack, flags, window, payload, mss);
                Conn.OnSegment(tcp);
            }

            public Task HandshakeAsync(ushort window, CancellationToken cancellationToken)
                => HandshakeAsync(window, TcpSegment.NoWindowScale, cancellationToken);

            public async Task HandshakeAsync(ushort window, byte windowScale, CancellationToken cancellationToken)
            {
                Conn.StartConnect();
                Seg syn = await WaitForAsync(s => (s.Flags & TcpFlags.Syn) != 0, cancellationToken);
                ClientIss = syn.Seq;
                const uint serverIss = 7000;
                InjectWithOptions(serverIss, syn.Seq + 1, TcpFlags.Syn | TcpFlags.Ack, window, mss: 1360, windowScale: windowScale);
                ServerNxt = serverIss + 1;
                await Conn.Connected.ConfigureAwait(false);
            }

            // Injects a segment carrying SYN-time options (MSS + Window Scale), so the test peer can negotiate RFC 7323 scaling.
            public void InjectWithOptions(uint seq, uint ack, TcpFlags flags, ushort window, ushort mss, byte windowScale)
            {
                byte[] tcp = TcpSegment.Build(ServerIp, ClientIp, ServerPort, ClientPort, seq, ack, flags, window, ReadOnlySpan<byte>.Empty, mss, windowScale);
                Conn.OnSegment(tcp);
            }

            public async Task<Seg> WaitForAsync(Func<Seg, bool> predicate, CancellationToken cancellationToken)
            {
                while (true)
                {
                    foreach (Seg s in Snapshot())
                        if (predicate(s)) return s;
                    cancellationToken.ThrowIfCancellationRequested();
                    await Task.Delay(5, cancellationToken).ConfigureAwait(false);
                }
            }

            public async Task WaitUntilAsync(Func<bool> condition, CancellationToken cancellationToken)
            {
                try
                {
                    while (!condition())
                    {
                        cancellationToken.ThrowIfCancellationRequested();
                        await Task.Delay(5, cancellationToken).ConfigureAwait(false);
                    }
                }
                catch (OperationCanceledException) { /* let the caller's assertion report the actual value */ }
            }

            /// <summary>How many captured segments carry exactly <paramref name="payload"/> at <paramref name="seq"/> (counts retransmits).</summary>
            public int CountData(uint seq, byte[] payload)
            {
                int count = 0;
                foreach (Seg s in Snapshot())
                    if (s.Seq == seq && s.Payload.AsSpan().SequenceEqual(payload)) count++;
                return count;
            }

            /// <summary>Total distinct data bytes sent (deduped by sequence number, so retransmits don't double-count).</summary>
            public int DataBytesSent() => DataBySeq().Values.Sum(p => p.Length);

            /// <summary>The largest single data-segment payload captured (1 while persist-dribbling, MSS-sized once the window is open).</summary>
            public int MaxSegmentPayload()
            {
                int max = 0;
                foreach (Seg s in Snapshot())
                    if (s.HasData) max = Math.Max(max, s.Payload.Length);
                return max;
            }

            /// <summary>How many data-carrying segments were emitted on the wire (counts every emission, incl. tiny ones).</summary>
            public int SegmentCount()
            {
                int count = 0;
                foreach (Seg s in Snapshot())
                    if (s.HasData) count++;
                return count;
            }

            public uint FirstDataSeq() => DataBySeq().Keys.Min();

            /// <summary>The right edge (seq + length) of the highest-sequence data segment captured — what the peer can cumulatively ACK.</summary>
            public uint HighestDataSeqEnd()
            {
                SortedDictionary<uint, byte[]> map = DataBySeq();
                if (map.Count == 0) return 0;
                uint key = map.Keys.Max();
                return key + (uint)map[key].Length;
            }

            public string AssembleData()
            {
                var sb = new StringBuilder();
                foreach (KeyValuePair<uint, byte[]> kv in DataBySeq().OrderBy(kv => kv.Key))
                    sb.Append(Encoding.ASCII.GetString(kv.Value));
                return sb.ToString();
            }

            SortedDictionary<uint, byte[]> DataBySeq()
            {
                var map = new SortedDictionary<uint, byte[]>();
                foreach (Seg s in Snapshot())
                    if (s.HasData) map[s.Seq] = s.Payload;
                return map;
            }

            public void Dispose() => Conn.Dispose();
        }

        /// <summary>A parsed outbound TCP segment (the fields the reliability tests assert on).</summary>
        readonly struct Seg
        {
            public Seg(TcpFlags flags, uint seq, uint ack, ushort window, byte[] payload)
            {
                Flags = flags; Seq = seq; Ack = ack; Window = window; Payload = payload;
            }

            public TcpFlags Flags { get; }
            public uint Seq { get; }
            public uint Ack { get; }
            public ushort Window { get; }
            public byte[] Payload { get; }
            public bool HasData => Payload.Length > 0;

            public static Seg Parse(byte[] ipPacket)
            {
                ReadOnlyMemory<byte> tcp = Ipv4.Payload(ipPacket);
                ReadOnlySpan<byte> s = tcp.Span;
                return new Seg(
                    TcpSegment.Flags(s), TcpSegment.Sequence(s), TcpSegment.Acknowledgment(s),
                    TcpSegment.Window(s), TcpSegment.Payload(tcp).ToArray());
            }
        }
    }
}
