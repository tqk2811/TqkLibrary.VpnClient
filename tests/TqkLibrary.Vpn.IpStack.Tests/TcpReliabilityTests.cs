using System.Net;
using System.Text;
using TqkLibrary.Vpn.IpStack;
using TqkLibrary.Vpn.IpStack.Tcp;
using TqkLibrary.Vpn.IpStack.Tcp.Enums;
using Xunit;

namespace TqkLibrary.Vpn.IpStack.Tests
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
            h.Conn.Send(data);

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

            h.Conn.Send(Encoding.ASCII.GetBytes("X")); // never acknowledged

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
            h.Conn.Send(message);

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
            h.Conn.Send(message);
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

            public async Task HandshakeAsync(ushort window, CancellationToken cancellationToken)
            {
                Conn.StartConnect();
                Seg syn = await WaitForAsync(s => (s.Flags & TcpFlags.Syn) != 0, cancellationToken);
                ClientIss = syn.Seq;
                const uint serverIss = 7000;
                Inject(serverIss, syn.Seq + 1, TcpFlags.Syn | TcpFlags.Ack, window, mss: 1360);
                ServerNxt = serverIss + 1;
                await Conn.Connected.ConfigureAwait(false);
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

            public uint FirstDataSeq() => DataBySeq().Keys.Min();

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
