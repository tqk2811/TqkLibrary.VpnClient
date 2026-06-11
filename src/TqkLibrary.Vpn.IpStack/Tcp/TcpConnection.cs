using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Net;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Threading;
using TqkLibrary.Vpn.IpStack.Tcp.Enums;

namespace TqkLibrary.Vpn.IpStack.Tcp
{
    /// <summary>
    /// An active-open TCP connection over the userspace stack. The peer is a real host on the internet (reached
    /// through the VPN gateway), so this is a reliable stack: the send path holds every sequence-consuming segment
    /// in a retransmission queue, retransmits on an RFC 6298 RTO (RTT-estimated, exponentially backed-off, with a
    /// give-up cap), honours the peer's window (flow control + zero-window persist), and runs NewReno congestion
    /// control (RFC 5681/6582) with window scaling (RFC 7323); the receive path reassembles out-of-order segments
    /// before delivering in order via <see cref="ReadAsync"/>, and the close path runs the full half-close FSM
    /// (FINWAIT1/2, CLOSING, TIMEWAIT, CLOSEWAIT, LASTACK) with a TIME-WAIT linger.
    /// </summary>
    /// <remarks>
    /// Selective Acknowledgment (RFC 2018/6675) is negotiated on the SYN exchange: when both peers offer SACK-Permitted
    /// the receive path reports its out-of-order blocks and the send path retransmits only the missing holes (selective
    /// retransmission, sending new data to keep the pipe full) instead of NewReno's recover-from-the-first-hole. With no
    /// SACK the stack falls back to NewReno. Inbound IP fragments are assumed already reassembled by the IP layer.
    /// </remarks>
    public sealed class TcpConnection : IDisposable
    {
        const ushort DefaultLinkMtu = 1400;  // tunnel default → MSS 1360 (unchanged from the old hard-coded value)
        const ushort MinMss = 88;            // defensive floor so a tiny/bogus MTU can't produce a useless segment size
        const ushort AssumedPeerMss = 536;   // RFC 1122: assume a 536-byte send MSS if the peer advertises none
        const ushort ReceiveWindow = 65535;
        const byte RcvWScale = 2;            // window scaling we advertise (RFC 7323): effective rwnd = 65535 << 2 ≈ 256 KB
        const uint MaxCwnd = 16u * 1024 * 1024; // sanity ceiling so the congestion window can't overflow over time

        // RFC 6298 estimator constants.
        const double Alpha = 0.125;          // SRTT gain (1/8)
        const double Beta = 0.25;            // RTTVAR gain (1/4)
        const int K = 4;                     // RTTVAR multiplier
        const double ClockGranularityMs = 1; // G

        static readonly double MsPerTick = 1000.0 / Stopwatch.Frequency;

        readonly IPAddress _localIp;
        readonly IPAddress _remoteIp;
        readonly ushort _localPort;
        readonly ushort _remotePort;
        readonly Action<byte[]> _sendIp;
        readonly TcpRetransmitOptions _opts;
        readonly object _sync = new();
        readonly TaskCompletionSource<bool> _connected = new(TaskCreationOptions.RunContinuationsAsynchronously);

        // Receive buffer (separate lock so reads don't contend with the send path).
        readonly object _recvLock = new();
        readonly Queue<byte[]> _recvQueue = new();
        byte[]? _head;
        int _headPos;
        bool _recvCompleted;
        Exception? _recvError;
        TaskCompletionSource<bool>? _recvWaiter;

        uint _sndNxt;
        uint _sndUna;
        uint _rcvNxt;
        ushort _ipId = 1;
        TcpState _state = TcpState.Closed;

        // Send-side flow control (peer's advertised window + the RFC 793 window-update sequencing).
        uint _sndWnd;
        uint _sndWl1;
        uint _sndWl2;

        // MSS negotiation: _localMss (advertised, derived from the link MTU) caps what the peer may send us; _sendMss
        // (= min(_localMss, peer's advertised MSS)) caps what we send. Both keep TCP segments within the link MTU so
        // SendIp never has to fragment them. Path MTU Discovery (RFC 1191 / RFC 8201) lowers _sendMss further when an
        // ICMP "fragmentation needed" / ICMPv6 "packet too big" reports a path MTU below the link MTU: _mssOverhead is
        // the IP+TCP header cost (40 IPv4 / 60 IPv6) subtracted from a reported path MTU, and _minPathMtu is the floor
        // we clamp a too-small or unknown (0) advertised MTU to before deriving the MSS.
        readonly ushort _localMss;
        readonly int _mssOverhead;
        readonly int _minPathMtu;
        ushort _sendMss;

        // Window scaling (RFC 7323), negotiated on the SYN exchange. _sndWScale scales the peer's advertised window
        // (raising our send ceiling above 64 KB); _rcvScaleActive (peer also offered scaling) widens the window we
        // accept on receive. Both stay 0/false unless the peer's SYN-ACK carries a Window Scale option.
        byte _sndWScale;
        bool _rcvScaleActive;

        // Congestion control (RFC 5681 + NewReno RFC 6582). The send rate is bounded by min(_cwnd, _sndWnd) − flight.
        // _cwnd grows on each new ACK (slow start while < _ssthresh, else congestion avoidance); 3 duplicate ACKs
        // trigger fast retransmit + fast recovery, and an RTO collapses _cwnd to one segment. Set at the handshake.
        uint _cwnd;
        uint _ssthresh = uint.MaxValue;  // "infinity" → begin in slow start
        int _dupAcks;
        bool _inRecovery;
        uint _recover;                   // NewReno: the highest sequence sent when fast recovery began

        // Selective acknowledgment (RFC 2018 / 6675), negotiated on the SYN exchange — we always offer SACK-Permitted;
        // _sackEnabled flips on only if the peer offers it too. _sackedBytes is how much of the retx queue the peer has
        // selectively acked; it is subtracted from the in-flight estimate so the send path can fill the pipe past holes.
        // _lastOooEnd is the right edge of the most-recently-buffered out-of-order range (reported first, RFC 2018 §4).
        bool _sackEnabled;
        uint _sackedBytes;
        uint _lastOooEnd;

        // Unsent application bytes waiting for window space (a queue of arrays + an offset into the head array).
        readonly Queue<byte[]> _sndChunks = new();
        int _sndChunkPos;
        int _sndBufferedBytes;

        // Out-of-order receive reassembly: segments past _rcvNxt held until the gap fills (bounded by ReceiveWindow).
        readonly List<(uint Seq, byte[] Data)> _ooo = new();

        // Deferred FIN: requested via CloseSend, emitted once the send buffer drains.
        bool _finRequested;
        bool _finSent;
        uint _finSeq;
        TcpState _finState;

        // Peer FIN tracking for the half-close FSM (consumed only once _rcvNxt reaches the FIN's sequence).
        bool _peerFinReceived;
        bool _peerFinPending;
        uint _peerFinSeq;

        // Retransmission queue (oldest first) + RFC 6298 RTO estimator.
        readonly LinkedList<RetxUnit> _retx = new();
        int _retxAttempts;
        double _rtoMs;
        double _srtt = -1;
        double _rttvar;
        readonly Timer _rtoTimer;

        // Zero-window persist.
        readonly Timer _persistTimer;
        double _persistMs;
        bool _persistArmed;

        // TIME-WAIT linger (and the only timer used in the closing FSM after the retx queue drains).
        readonly Timer _closeTimer;

        bool _terminal;

        /// <summary>Raised once when the connection reaches a terminal state — graceful CLOSED or a fault (RST / retransmission give-up); lets the stack drop and dispose it.</summary>
        public event Action? Closed;

        /// <summary>Creates a connection from the local endpoint to the remote endpoint.</summary>
        public TcpConnection(
            IPAddress localIp, ushort localPort, IPAddress remoteIp, ushort remotePort, Action<byte[]> sendIp,
            TcpRetransmitOptions? options = null, int linkMtu = DefaultLinkMtu)
        {
            _localIp = localIp;
            _localPort = localPort;
            _remoteIp = remoteIp;
            _remotePort = remotePort;
            _sendIp = sendIp;
            _opts = options ?? TcpRetransmitOptions.Default;
            // MSS = link MTU − IP header − TCP(20); the IP header is 20 (IPv4) or 40 (IPv6). Floored so a tiny MTU
            // can't yield a useless segment size, and capped so an absurd MTU stays within the 16-bit option field.
            // Until the peer's SYN-ACK is seen we send at our own MSS.
            bool ipv6 = _localIp.AddressFamily == AddressFamily.InterNetworkV6;
            _mssOverhead = ipv6 ? 60 : 40;          // IP header (20/40) + TCP header (20)
            _minPathMtu = ipv6 ? 1280 : 576;        // RFC 8200 minimum link MTU / RFC 1191 §3 plateau floor
            _localMss = (ushort)Math.Min(65495, Math.Max(MinMss, linkMtu - _mssOverhead));
            _sendMss = _localMss;
            _rtoMs = _opts.InitialRto.TotalMilliseconds;
            _persistMs = _opts.PersistMin.TotalMilliseconds;
            _rtoTimer = new Timer(_ => OnRtoTimer(), null, Timeout.InfiniteTimeSpan, Timeout.InfiniteTimeSpan);
            _persistTimer = new Timer(_ => OnPersistTimer(), null, Timeout.InfiniteTimeSpan, Timeout.InfiniteTimeSpan);
            _closeTimer = new Timer(_ => OnCloseTimer(), null, Timeout.InfiniteTimeSpan, Timeout.InfiniteTimeSpan);
        }

        /// <summary>This connection's local port.</summary>
        public ushort LocalPort => _localPort;

        /// <summary>The current TCP state (observable for diagnostics/tests; transitions happen under the connection lock).</summary>
        public TcpState State => _state;

        /// <summary>The segment size we currently send at — lowered below the link-MTU MSS by Path MTU Discovery (observable for diagnostics/tests).</summary>
        public int SendMss => _sendMss;

        /// <summary>Completes when the 3-way handshake finishes (or faults on RST).</summary>
        public Task Connected => _connected.Task;

        /// <summary>Sends the initial SYN.</summary>
        public void StartConnect()
        {
            lock (_sync)
            {
                byte[] r = new byte[4];
                using (var rng = RandomNumberGenerator.Create()) rng.GetBytes(r);
                uint iss = ((uint)r[0] << 24) | ((uint)r[1] << 16) | ((uint)r[2] << 8) | r[3];
                _sndUna = iss;
                _sndNxt = iss;
                EmitSegment(iss, TcpFlags.Syn, ReadOnlySpan<byte>.Empty, mss: _localMss, windowScale: RcvWScale, sackPermitted: true);
                EnqueueRetx(iss, TcpFlags.Syn, Array.Empty<byte>(), seqLen: 1);
                _sndNxt = iss + 1;
                _state = TcpState.SynSent;
                ArmRtoTimer();
            }
        }

        /// <summary>Feeds one inbound TCP segment (the IP payload) into the state machine.</summary>
        public void OnSegment(ReadOnlyMemory<byte> segment)
        {
            lock (_sync) Handle(segment);
        }

        /// <summary>Queues application data to send (flushed within the peer's advertised window).</summary>
        public void Send(ReadOnlySpan<byte> data)
        {
            lock (_sync)
            {
                if (_terminal) return;
                if (data.Length > 0)
                {
                    _sndChunks.Enqueue(data.ToArray());
                    _sndBufferedBytes += data.Length;
                }
                TrySendData();
            }
        }

        /// <summary>Reads received bytes into <paramref name="buffer"/>; returns 0 at end of stream.</summary>
        public async Task<int> ReadAsync(byte[] buffer, int offset, int count, CancellationToken cancellationToken)
        {
            while (true)
            {
                Task waiter;
                lock (_recvLock)
                {
                    if (_head == null && _recvQueue.Count > 0) { _head = _recvQueue.Dequeue(); _headPos = 0; }
                    if (_head != null)
                    {
                        int available = _head.Length - _headPos;
                        int n = Math.Min(available, count);
                        Buffer.BlockCopy(_head, _headPos, buffer, offset, n);
                        _headPos += n;
                        if (_headPos >= _head.Length) _head = null;
                        return n;
                    }
                    if (_recvError != null) throw _recvError;
                    if (_recvCompleted) return 0;
                    _recvWaiter = new TaskCompletionSource<bool>(TaskCreationOptions.RunContinuationsAsynchronously);
                    waiter = _recvWaiter.Task;
                }

                await Task.WhenAny(waiter, Task.Delay(Timeout.Infinite, cancellationToken)).ConfigureAwait(false);
                cancellationToken.ThrowIfCancellationRequested();
            }
        }

        /// <summary>Requests a FIN to close our send side; the FIN is emitted once any buffered data has drained.</summary>
        public void CloseSend()
        {
            lock (_sync)
            {
                if (_terminal) return;
                if (_state == TcpState.Established) { _finRequested = true; _finState = TcpState.FinWait1; TrySendData(); }
                else if (_state == TcpState.CloseWait) { _finRequested = true; _finState = TcpState.LastAck; TrySendData(); }
            }
        }

        /// <summary>
        /// Reports an ICMP "fragmentation needed" (IPv4, RFC 1191) or ICMPv6 "packet too big" (RFC 8201) for a segment we
        /// sent: <paramref name="nextHopMtu"/> is the path MTU the router could forward, <paramref name="offendingSeq"/> the
        /// sequence number the quoted segment carried. Lowers the send MSS below the link MTU and re-segments the in-flight
        /// retransmission queue so the dropped data is resent small enough to traverse the path (Path MTU Discovery).
        /// </summary>
        public void OnIcmpPacketTooBig(int nextHopMtu, uint offendingSeq)
        {
            lock (_sync) ApplyPathMtu(nextHopMtu, offendingSeq);
        }

        void Handle(ReadOnlyMemory<byte> segment)
        {
            ReadOnlySpan<byte> span = segment.Span;
            TcpFlags flags = TcpSegment.Flags(span);
            uint seq = TcpSegment.Sequence(span);
            uint ack = TcpSegment.Acknowledgment(span);
            ushort wnd = TcpSegment.Window(span);
            ReadOnlyMemory<byte> payload = TcpSegment.Payload(segment);
            int len = payload.Length;

            if (_terminal) return;
            if ((flags & TcpFlags.Rst) != 0)
            {
                Fail("connection reset by peer");
                return;
            }

            if (_state == TcpState.SynSent)
            {
                if ((flags & TcpFlags.Syn) != 0 && (flags & TcpFlags.Ack) != 0)
                {
                    _rcvNxt = seq + 1;
                    // Clamp our outbound segment size to the peer's advertised MSS (RFC 1122: assume 536 if absent).
                    ushort peerMss = TcpSegment.MaxSegmentSize(span);
                    _sendMss = (ushort)Math.Max(MinMss, Math.Min(_localMss, peerMss > 0 ? peerMss : AssumedPeerMss));
                    ProcessAck(ack, seq, wnd, 0, flags, span);  // acks our SYN, seeds the send window (SYN-ACK window is unscaled)
                    // Window scaling takes effect only if the peer also offered it (RFC 7323); its window is scaled hereafter.
                    byte peerWScale = TcpSegment.WindowScale(span);
                    if (peerWScale != TcpSegment.NoWindowScale)
                    {
                        _sndWScale = peerWScale > 14 ? (byte)14 : peerWScale; // RFC 7323 §2.3: clamp the shift count to 14
                        _rcvScaleActive = true;
                    }
                    _sackEnabled = TcpSegment.SackPermitted(span); // selective ACK is on only if the peer also offered it (RFC 2018)
                    _cwnd = InitialCwnd(_sendMss);             // RFC 6928 initial window — set after the SYN-ACK is processed
                    EmitSegment(_sndNxt, TcpFlags.Ack, ReadOnlySpan<byte>.Empty);
                    _state = TcpState.Established;
                    _connected.TrySetResult(true);
                    TrySendData();                             // flush anything queued before the handshake finished
                }
                return;
            }
            if (_state == TcpState.Closed) return;

            // Data-transfer + closing states (Established/FinWait1/FinWait2/Closing/TimeWait/CloseWait/LastAck).
            bool fin = (flags & TcpFlags.Fin) != 0;
            if ((flags & TcpFlags.Ack) != 0) ProcessAck(ack, seq, wnd, len, flags, span);
            if (len > 0) ReceiveData(seq, payload);
            if (fin) NoteFin(seq, len);
            TryConsumePeerFin();
            if (len > 0 || fin) EmitAck(); // cumulative / dup ACK (carries SACK blocks when out-of-order data is buffered)
            AdvanceClose();
            if (_state == TcpState.TimeWait && fin) ArmCloseTimer(); // refresh linger on a retransmitted peer FIN
        }

        // ---- Receive reassembly + half-close FSM -----------------------------------------------------------

        // The receive window we actually honour: the advertised 65535 scaled up when window scaling was negotiated
        // (RFC 7323). This bounds how far past _rcvNxt an out-of-order segment may sit before we drop it.
        uint RcvWindowEffective() => _rcvScaleActive ? ((uint)ReceiveWindow << RcvWScale) : ReceiveWindow;

        // Accepts in-window data, delivering in order and buffering out-of-order segments until the gap fills.
        void ReceiveData(uint seq, ReadOnlyMemory<byte> payload)
        {
            uint end = seq + (uint)payload.Length;
            if (SeqGeq(_rcvNxt, end)) return;                         // wholly old/duplicate
            if (!SeqGreater(_rcvNxt + RcvWindowEffective(), seq)) return; // beyond the advertised (scaled) window

            if (seq == _rcvNxt)
            {
                DeliverReceived(payload);
                _rcvNxt = end;
                if (_ooo.Count > 0) DrainOoo();
                return;
            }

            for (int i = 0; i < _ooo.Count; i++)                      // dedupe an identical out-of-order arrival
                if (_ooo[i].Seq == seq) { _ooo.RemoveAt(i); break; }
            _ooo.Add((seq, payload.ToArray()));
            _lastOooEnd = end;                                        // most-recent block → reported first in our SACK (RFC 2018 §4)
            DrainOoo();
        }

        // Delivers any buffered segments now contiguous with _rcvNxt (wrap-safe; small buffer, linear scan).
        void DrainOoo()
        {
            bool progress = true;
            while (progress)
            {
                progress = false;
                for (int i = 0; i < _ooo.Count; i++)
                {
                    (uint s, byte[] d) = _ooo[i];
                    uint end = s + (uint)d.Length;
                    if (SeqGeq(_rcvNxt, end)) { _ooo.RemoveAt(i); progress = true; break; }   // wholly old now
                    if (SeqGeq(_rcvNxt, s))                                                    // contiguous → deliver tail
                    {
                        int skip = (int)(_rcvNxt - s);
                        DeliverReceived(d.AsMemory(skip));
                        _rcvNxt = end;
                        _ooo.RemoveAt(i);
                        progress = true;
                        break;
                    }
                }
            }
        }

        // Records the peer's FIN (its sequence slot sits after any data the segment carried).
        void NoteFin(uint seq, int len)
        {
            if (_peerFinReceived) return;     // already consumed; a retransmitted FIN just gets re-ACKed
            _peerFinSeq = seq + (uint)len;
            _peerFinPending = true;
        }

        // Consumes the peer FIN once all preceding data has been reassembled (delivers end-of-stream to the reader).
        void TryConsumePeerFin()
        {
            if (!_peerFinPending || _rcvNxt != _peerFinSeq) return;
            _rcvNxt += 1;
            _peerFinPending = false;
            _peerFinReceived = true;
            CompleteReceive(null);
        }

        bool OurFinAcked => _finSent && SeqGeq(_sndUna, _finSeq + 1);

        // Drives the closing FSM from the per-segment flags (RFC 793 §3.5/§3.9 active+passive close).
        void AdvanceClose()
        {
            switch (_state)
            {
                case TcpState.Established:
                    if (_peerFinReceived) _state = TcpState.CloseWait;       // passive close: peer closed first
                    break;
                case TcpState.FinWait1:
                    if (_peerFinReceived && OurFinAcked) EnterTimeWait();    // peer FIN+ACK in one segment
                    else if (_peerFinReceived) _state = TcpState.Closing;    // simultaneous close
                    else if (OurFinAcked) _state = TcpState.FinWait2;        // our FIN acked, awaiting peer FIN
                    break;
                case TcpState.FinWait2:
                    if (_peerFinReceived) EnterTimeWait();
                    break;
                case TcpState.Closing:
                    if (OurFinAcked) EnterTimeWait();
                    break;
                case TcpState.LastAck:
                    if (OurFinAcked) Terminate(null);                        // passive close complete → CLOSED
                    break;
            }
        }

        void EnterTimeWait()
        {
            _state = TcpState.TimeWait;
            ArmCloseTimer();
        }

        void ArmCloseTimer() => _closeTimer.Change(_opts.TimeWait, Timeout.InfiniteTimeSpan);

        void OnCloseTimer()
        {
            lock (_sync)
            {
                if (_terminal) return;
                if (_state == TcpState.TimeWait) Terminate(null); // linger elapsed → CLOSED
            }
        }

        // ---- Send path: flow control + retransmission ------------------------------------------------------

        void TrySendData()
        {
            if (_terminal) return;
            bool canSend = _state == TcpState.Established || _state == TcpState.CloseWait;
            if (canSend)
            {
                while (_sndBufferedBytes > 0)
                {
                    long window = Math.Min(_cwnd, _sndWnd);           // bounded by congestion window + peer flow control
                    long usable = window - InFlight();                // minus the bytes still in flight (SACKed holes excluded)
                    if (usable <= 0) break;
                    int chunk = (int)Math.Min(Math.Min((long)_sendMss, usable), _sndBufferedBytes);
                    EmitData(_sndNxt, DequeueUpTo(chunk));
                }

                if (_finRequested && !_finSent && _sndBufferedBytes == 0)
                    EmitFin();
            }

            if (canSend && !_finSent && _sndWnd == 0 && _sndBufferedBytes > 0) EnsurePersist();
            else StopPersist();

            ArmRtoTimer();
        }

        void ProcessAck(uint ack, uint segSeq, ushort segWnd, int payloadLen, TcpFlags flags, ReadOnlySpan<byte> segSpan)
        {
            uint advertised = (uint)segWnd << _sndWScale;
            if (_sackEnabled) ApplySackBlocks(segSpan, ack); // mark selectively-acked segments before any congestion decision

            if (SeqGreater(ack, _sndUna))
            {
                // ---- new data acknowledged: free the retx queue, sample RTT, then advance congestion control ----
                uint acked = ack - _sndUna;
                long now = Now();
                bool sampled = false;
                double sampleMs = 0;
                LinkedListNode<RetxUnit>? node = _retx.First;
                while (node != null && SeqGeq(ack, node.Value.Seq + (uint)node.Value.SeqLen))
                {
                    if (!node.Value.Retransmitted) { sampleMs = (now - node.Value.SentTicks) * MsPerTick; sampled = true; } // Karn: skip retransmitted
                    LinkedListNode<RetxUnit>? next = node.Next;
                    _retx.Remove(node);
                    node = next;
                }
                _sndUna = ack;
                _retxAttempts = 0;                  // forward progress resets the give-up counter
                if (sampled) UpdateRto(sampleMs);
                if (_sackEnabled) RecomputeSacked(); // some SACKed units were just cumulatively acked and removed

                if (_inRecovery)
                {
                    if (SeqGeq(ack, _recover)) { _cwnd = _ssthresh; _inRecovery = false; } // full ACK → exit recovery
                    else                                                                    // NewReno partial ACK
                    {
                        RetransmitNext();                                    // SACK → the next hole(s); NewReno → the oldest segment
                        _cwnd = _cwnd > acked ? _cwnd - acked : 0;           // deflate by the newly-acked amount...
                        if (acked >= _sendMss) _cwnd += _sendMss;            // ...then add one segment back (RFC 6582)
                        if (_cwnd < _sendMss) _cwnd = _sendMss;
                    }
                }
                else GrowCwnd(acked);               // slow start (< ssthresh) or congestion avoidance
                _dupAcks = 0;
            }
            else if (ack == _sndUna && payloadLen == 0 && (flags & (TcpFlags.Syn | TcpFlags.Fin)) == 0
                     && _sndNxt != _sndUna && advertised == _sndWnd)
            {
                // ---- duplicate ACK (RFC 5681 §2): pure ACK, no window change, data still outstanding ----
                _dupAcks++;
                if (_inRecovery)
                {
                    _cwnd += _sendMss;                  // inflate while recovering (RFC 5681 §3.2 step 4)
                    if (_sackEnabled) RetransmitNext(); // a fresh SACK block may have exposed another hole as lost
                }
                else if (_dupAcks == 3) EnterFastRecovery(); // 3rd dup ACK → fast retransmit + fast recovery
            }

            // RFC 793 window update: accept only if this segment is newer (by seq, then by ack).
            if (SeqGreater(segSeq, _sndWl1) || (segSeq == _sndWl1 && !SeqGreater(_sndWl2, ack)))
            {
                if (_sndWnd == 0 && segWnd > 0) _persistMs = _opts.PersistMin.TotalMilliseconds; // window reopened
                _sndWnd = advertised;               // apply the peer's negotiated window scale (RFC 7323)
                _sndWl1 = segSeq;
                _sndWl2 = ack;
            }

            TrySendData();
        }

        // RFC 6928 initial congestion window: min(10·SMSS, max(2·SMSS, 14600)) bytes.
        static uint InitialCwnd(ushort mss) => (uint)Math.Min(10 * mss, Math.Max(2 * mss, 14600));

        // Opens the congestion window for one newly-acked stretch: exponential in slow start, ~+1 SMSS/RTT after.
        void GrowCwnd(uint acked)
        {
            uint inc = _cwnd < _ssthresh
                ? Math.Min(acked, _sendMss)                                   // slow start (RFC 5681 §3.1)
                : Math.Max(1u, (uint)((long)_sendMss * _sendMss / _cwnd));    // congestion avoidance
            _cwnd = Math.Min(_cwnd + inc, MaxCwnd);
        }

        // RFC 5681 §3.2 / RFC 6582: on the 3rd duplicate ACK, halve the window, inflate by the 3 dup ACKs, and
        // retransmit the lost segment(s) without waiting for the RTO.
        void EnterFastRecovery()
        {
            uint flight = InFlight();
            _ssthresh = Math.Max(flight / 2, (uint)(2 * _sendMss));
            _cwnd = _ssthresh + 3u * _sendMss;
            _recover = _sndNxt;
            _inRecovery = true;
            if (_sackEnabled) foreach (RetxUnit u in _retx) u.ResentInRecovery = false; // fresh scoreboard for this episode
            RetransmitNext();
        }

        // Bytes still in flight: everything sent-but-not-cumulatively-acked, minus what the peer has SACKed (the RFC 6675
        // pipe estimate). Equals _sndNxt − _sndUna when SACK is off (_sackedBytes stays 0), so the non-SACK path is unchanged.
        uint InFlight() => (_sndNxt - _sndUna) - _sackedBytes;

        // Selective-retransmission entry point: with SACK, resend the confirmed holes (RFC 6675); otherwise the single
        // NewReno retransmit of the oldest unacked segment.
        void RetransmitNext()
        {
            if (_sackEnabled) RetransmitHoles();
            else RetransmitOldest();
        }

        // Re-sends the oldest unacked segment (the head of the retx queue), re-advertising SYN options when it is a SYN.
        void RetransmitOldest()
        {
            LinkedListNode<RetxUnit>? node = _retx.First;
            if (node == null) return;
            RetxUnit u = node.Value;
            bool isSyn = (u.Flags & TcpFlags.Syn) != 0;
            EmitSegment(u.Seq, u.Flags, u.Payload, isSyn ? _localMss : (ushort)0, isSyn ? RcvWScale : TcpSegment.NoWindowScale, sackPermitted: isSyn);
            u.Retransmitted = true;
            u.SentTicks = Now();
        }

        // RFC 6675 NextSeg: resend each un-SACKed segment that sits below SACKed data (a confirmed hole) and hasn't yet
        // been resent this recovery episode, injecting at most a congestion window's worth of bytes per call.
        void RetransmitHoles()
        {
            uint highestSacked = HighestSacked();
            long injected = 0;
            for (LinkedListNode<RetxUnit>? node = _retx.First; node != null; node = node.Next)
            {
                RetxUnit u = node.Value;
                if (u.Sacked || u.ResentInRecovery) continue;
                if (!SeqGreater(highestSacked, u.Seq + (uint)u.SeqLen)) continue; // no SACK above it yet → not a confirmed hole
                bool isSyn = (u.Flags & TcpFlags.Syn) != 0;
                EmitSegment(u.Seq, u.Flags, u.Payload, isSyn ? _localMss : (ushort)0, isSyn ? RcvWScale : TcpSegment.NoWindowScale, sackPermitted: isSyn);
                u.ResentInRecovery = true;
                u.Retransmitted = true;
                u.SentTicks = Now();
                injected += u.SeqLen;
                if (injected >= _cwnd) break;
            }
        }

        // ---- Path MTU Discovery (RFC 1191 / RFC 8201) ------------------------------------------------------

        // An ICMP error reported that a segment we sent was too big for some link on the path. Lower the send MSS below
        // the link MTU, re-segment the in-flight queue to the new size, and retransmit it so the dropped data flows again
        // without waiting for the RTO (and without black-holing forever on the same oversized segment).
        void ApplyPathMtu(int nextHopMtu, uint offendingSeq)
        {
            if (_terminal) return;
            // Ignore errors that don't quote currently-outstanding data (stale, or for a since-acked/foreign segment).
            if (!SeqGeq(offendingSeq, _sndUna) || !SeqGreater(_sndNxt, offendingSeq)) return;

            if (nextHopMtu < _minPathMtu) nextHopMtu = _minPathMtu; // router reported 0 (pre-RFC-1191) or an implausibly small MTU
            int candidate = Math.Max(MinMss, nextHopMtu - _mssOverhead);
            if (candidate >= _sendMss) return;                      // PMTUD only ever lowers the MSS — never raise it

            _sendMss = (ushort)candidate;
            ResegmentRetxQueue();
            RetransmitAfterMtuDrop();
            ArmRtoTimer();
        }

        // Splits every queued data segment larger than the (just-lowered) send MSS into MSS-sized pieces, preserving
        // sequence numbers and flags, so each retransmission now fits the path. SYN/FIN units carry no splittable payload
        // and are left alone. SACK state is reset on the pieces — a fresh SACK block re-marks whichever the peer already holds.
        void ResegmentRetxQueue()
        {
            for (LinkedListNode<RetxUnit>? node = _retx.First; node != null;)
            {
                LinkedListNode<RetxUnit>? next = node.Next;
                RetxUnit u = node.Value;
                if (u.Payload.Length > _sendMss && (u.Flags & (TcpFlags.Syn | TcpFlags.Fin)) == 0)
                {
                    LinkedListNode<RetxUnit> anchor = node;
                    for (int off = 0; off < u.Payload.Length; off += _sendMss)
                    {
                        int len = Math.Min(_sendMss, u.Payload.Length - off);
                        byte[] piece = new byte[len];
                        Buffer.BlockCopy(u.Payload, off, piece, 0, len);
                        anchor = _retx.AddAfter(anchor, new RetxUnit
                        {
                            Seq = u.Seq + (uint)off,
                            Flags = u.Flags,
                            Payload = piece,
                            SeqLen = len,
                            SentTicks = u.SentTicks,
                            Retransmitted = u.Retransmitted,
                        });
                    }
                    _retx.Remove(node);
                }
                node = next;
            }
            if (_sackEnabled) RecomputeSacked();
        }

        // Retransmits the (now correctly-sized) outstanding segments after a PMTU drop, bounded by the send window so the
        // burst stays within flow/congestion control; segments the peer has already SACKed are skipped.
        void RetransmitAfterMtuDrop()
        {
            long limit = Math.Max(_sendMss, Math.Min(_cwnd, _sndWnd));
            long injected = 0;
            for (LinkedListNode<RetxUnit>? node = _retx.First; node != null; node = node.Next)
            {
                RetxUnit u = node.Value;
                if (u.Sacked) continue;
                bool isSyn = (u.Flags & TcpFlags.Syn) != 0;
                EmitSegment(u.Seq, u.Flags, u.Payload, isSyn ? _localMss : (ushort)0, isSyn ? RcvWScale : TcpSegment.NoWindowScale, sackPermitted: isSyn);
                u.Retransmitted = true;
                u.SentTicks = Now();
                injected += u.SeqLen;
                if (injected >= limit) break;
            }
        }

        // Highest right edge the peer has selectively acknowledged (≥ _sndUna when nothing is SACKed).
        uint HighestSacked()
        {
            uint hi = _sndUna;
            foreach (RetxUnit u in _retx)
                if (u.Sacked && SeqGreater(u.Seq + (uint)u.SeqLen, hi)) hi = u.Seq + (uint)u.SeqLen;
            return hi;
        }

        // Marks every retx unit fully covered by an incoming SACK block as SACKed (RFC 2018 §4), then refreshes the total.
        void ApplySackBlocks(ReadOnlySpan<byte> segSpan, uint ack)
        {
            Span<uint> blocks = stackalloc uint[8];
            int n = TcpSegment.ReadSackBlocks(segSpan, blocks);
            if (n == 0) return;
            foreach (RetxUnit u in _retx)
            {
                if (u.Sacked) continue;
                uint uEnd = u.Seq + (uint)u.SeqLen;
                for (int b = 0; b < n; b++)
                {
                    uint left = blocks[b * 2], right = blocks[b * 2 + 1];
                    if (!SeqGreater(right, ack)) continue;                  // stale block at/below the cumulative ACK
                    if (SeqGeq(u.Seq, left) && SeqGeq(right, uEnd)) { u.Sacked = true; break; }
                }
            }
            RecomputeSacked();
        }

        // Re-totals the SACKed bytes still resident in the retx queue (after marking, or after cumulative removal).
        void RecomputeSacked()
        {
            uint total = 0;
            foreach (RetxUnit u in _retx) if (u.Sacked) total += (uint)u.SeqLen;
            _sackedBytes = total;
        }

        void UpdateRto(double rttMs)
        {
            if (_srtt < 0) { _srtt = rttMs; _rttvar = rttMs / 2; }
            else
            {
                _rttvar = (1 - Beta) * _rttvar + Beta * Math.Abs(_srtt - rttMs);
                _srtt = (1 - Alpha) * _srtt + Alpha * rttMs;
            }
            double rto = _srtt + Math.Max(ClockGranularityMs, K * _rttvar);
            _rtoMs = Math.Min(Math.Max(rto, _opts.MinRto.TotalMilliseconds), _opts.MaxRto.TotalMilliseconds);
        }

        void EmitData(uint seq, byte[] payload)
        {
            EmitSegment(seq, TcpFlags.Psh | TcpFlags.Ack, payload);
            EnqueueRetx(seq, TcpFlags.Psh | TcpFlags.Ack, payload, seqLen: payload.Length);
            _sndNxt += (uint)payload.Length;
        }

        void EmitFin()
        {
            uint seq = _sndNxt;
            EmitSegment(seq, TcpFlags.Fin | TcpFlags.Ack, ReadOnlySpan<byte>.Empty);
            EnqueueRetx(seq, TcpFlags.Fin | TcpFlags.Ack, Array.Empty<byte>(), seqLen: 1);
            _sndNxt += 1;
            _finSent = true;
            _finSeq = seq;
            _state = _finState;
        }

        void EnqueueRetx(uint seq, TcpFlags flags, byte[] payload, int seqLen)
        {
            _retx.AddLast(new RetxUnit { Seq = seq, Flags = flags, Payload = payload, SeqLen = seqLen, SentTicks = Now() });
        }

        void EmitSegment(uint seq, TcpFlags flags, ReadOnlySpan<byte> payload, ushort mss = 0, byte windowScale = TcpSegment.NoWindowScale,
            bool sackPermitted = false, ReadOnlySpan<uint> sackBlocks = default)
        {
            byte[] tcp = TcpSegment.Build(_localIp, _remoteIp, _localPort, _remotePort, seq, _rcvNxt, flags, ReceiveWindow, payload, mss, windowScale, sackPermitted, sackBlocks);
            byte[] ip = IpLayer.Build(_localIp, _remoteIp, Ipv4.ProtocolTcp, tcp, _ipId++); // TCP protocol number 6 is shared by IPv4/IPv6
            _sendIp(ip);
        }

        // Sends a bare ACK, attaching SACK blocks describing the buffered out-of-order data when SACK is in effect (RFC 2018).
        void EmitAck()
        {
            if (_sackEnabled && _ooo.Count > 0)
            {
                Span<uint> blocks = stackalloc uint[8];
                int pairs = BuildSackBlocks(blocks);
                EmitSegment(_sndNxt, TcpFlags.Ack, ReadOnlySpan<byte>.Empty, sackBlocks: blocks.Slice(0, pairs * 2));
            }
            else EmitSegment(_sndNxt, TcpFlags.Ack, ReadOnlySpan<byte>.Empty);
        }

        // Coalesces the buffered out-of-order segments into maximal blocks and writes up to 4 (leftEdge, rightEdge) pairs
        // into <paramref name="dst"/>, the block holding the most recently received data first (RFC 2018 §4). Returns the
        // block count. Offsets are taken relative to _rcvNxt so the sort and merge stay wrap-safe within the receive window.
        int BuildSackBlocks(Span<uint> dst)
        {
            var ranges = new List<(uint Start, uint End)>(_ooo.Count);
            foreach ((uint seq, byte[] data) in _ooo) ranges.Add((seq, seq + (uint)data.Length));
            uint baseSeq = _rcvNxt;
            ranges.Sort((x, y) => ((uint)(x.Start - baseSeq)).CompareTo((uint)(y.Start - baseSeq)));

            var merged = new List<(uint Start, uint End)>();
            foreach ((uint start, uint end) in ranges)
            {
                int last = merged.Count - 1;
                if (last >= 0 && SeqGeq(merged[last].End, start))
                {
                    if (SeqGreater(end, merged[last].End)) merged[last] = (merged[last].Start, end);
                }
                else merged.Add((start, end));
            }

            int firstIdx = -1; // the merged block that contains the most-recently-received segment (ends at _lastOooEnd)
            for (int i = 0; i < merged.Count; i++)
                if (SeqGreater(_lastOooEnd, merged[i].Start) && SeqGeq(merged[i].End, _lastOooEnd)) { firstIdx = i; break; }

            int count = 0;
            if (firstIdx >= 0) { dst[0] = merged[firstIdx].Start; dst[1] = merged[firstIdx].End; count = 1; }
            for (int i = merged.Count - 1; i >= 0 && count < 4; i--)   // remaining blocks, most-recent (highest offset) first
            {
                if (i == firstIdx) continue;
                dst[count * 2] = merged[i].Start; dst[count * 2 + 1] = merged[i].End; count++;
            }
            return count;
        }

        byte[] DequeueUpTo(int max)
        {
            int want = Math.Min(max, _sndBufferedBytes);
            byte[] result = new byte[want];
            int copied = 0;
            while (copied < want)
            {
                byte[] head = _sndChunks.Peek();
                int take = Math.Min(head.Length - _sndChunkPos, want - copied);
                Buffer.BlockCopy(head, _sndChunkPos, result, copied, take);
                _sndChunkPos += take;
                copied += take;
                if (_sndChunkPos >= head.Length) { _sndChunks.Dequeue(); _sndChunkPos = 0; }
            }
            _sndBufferedBytes -= want;
            return result;
        }

        // ---- RTO timer (RFC 6298 §5) -----------------------------------------------------------------------

        void OnRtoTimer()
        {
            lock (_sync)
            {
                if (_terminal) return;
                LinkedListNode<RetxUnit>? node = _retx.First;
                if (node == null) return;

                long now = Now();
                long deadline = node.Value.SentTicks + (long)(_rtoMs / MsPerTick);
                if (now < deadline) { ArmRtoTimer(); return; } // woke early (timer coalescing) — re-arm

                if (++_retxAttempts > _opts.MaxRetransmits)
                {
                    Fail($"retransmission timeout (no ACK after {_opts.MaxRetransmits} retries)");
                    return;
                }

                // RFC 6675 §5.1: an RTO may mean the peer reneged on its SACKs — clear the scoreboard and recover
                // from the cumulative ACK via go-back-N.
                if (_sackEnabled)
                {
                    foreach (RetxUnit u in _retx) { u.Sacked = false; u.ResentInRecovery = false; }
                    _sackedBytes = 0;
                }

                // RFC 5681 §3.1: an RTO is the strongest congestion signal — drop ssthresh to half the flight and
                // collapse the congestion window to one segment, restarting slow start.
                _ssthresh = Math.Max((_sndNxt - _sndUna) / 2, (uint)(2 * _sendMss));
                _cwnd = _sendMss;
                _inRecovery = false;
                _dupAcks = 0;

                RetransmitOldest();
                _rtoMs = Math.Min(_rtoMs * 2, _opts.MaxRto.TotalMilliseconds); // exponential backoff (RFC 6298 §5.5)
                ArmRtoTimer();
            }
        }

        void ArmRtoTimer()
        {
            if (_terminal) return;
            LinkedListNode<RetxUnit>? node = _retx.First;
            if (node == null) { _rtoTimer.Change(Timeout.InfiniteTimeSpan, Timeout.InfiniteTimeSpan); return; }
            long deadline = node.Value.SentTicks + (long)(_rtoMs / MsPerTick);
            double dueMs = Math.Max(0, (deadline - Now()) * MsPerTick);
            _rtoTimer.Change(TimeSpan.FromMilliseconds(dueMs), Timeout.InfiniteTimeSpan);
        }

        // ---- Zero-window persist (RFC 9293 §3.8.6.1) -------------------------------------------------------

        void EnsurePersist()
        {
            if (_persistArmed) return;
            _persistArmed = true;
            _persistTimer.Change(TimeSpan.FromMilliseconds(_persistMs), Timeout.InfiniteTimeSpan);
        }

        void StopPersist()
        {
            if (!_persistArmed) return;
            _persistArmed = false;
            _persistTimer.Change(Timeout.InfiniteTimeSpan, Timeout.InfiniteTimeSpan);
        }

        void OnPersistTimer()
        {
            lock (_sync)
            {
                if (_terminal) return;
                bool canSend = _state == TcpState.Established || _state == TcpState.CloseWait;
                if (!canSend || _sndWnd != 0 || _sndBufferedBytes == 0) { StopPersist(); return; }

                // Send one probe byte only when nothing is already in flight, so at most one byte sits beyond the
                // zero window; the RTO timer retransmits it until acked, after which the next probe goes out.
                if (_retx.Count == 0)
                {
                    EmitData(_sndNxt, DequeueUpTo(1));
                    ArmRtoTimer();
                }

                _persistMs = Math.Min(_persistMs * 2, _opts.PersistMax.TotalMilliseconds);
                _persistTimer.Change(TimeSpan.FromMilliseconds(_persistMs), Timeout.InfiniteTimeSpan);
            }
        }

        // ---- Receive delivery ------------------------------------------------------------------------------

        void DeliverReceived(ReadOnlyMemory<byte> payload)
        {
            byte[] copy = payload.ToArray();
            lock (_recvLock)
            {
                _recvQueue.Enqueue(copy);
                Signal();
            }
        }

        void CompleteReceive(Exception? error)
        {
            lock (_recvLock)
            {
                _recvCompleted = true;
                _recvError = error;
                Signal();
            }
        }

        void Signal()
        {
            TaskCompletionSource<bool>? waiter = _recvWaiter;
            _recvWaiter = null;
            waiter?.TrySetResult(true);
        }

        void Fail(string message) => Terminate(new IOException(message));

        // Single terminal path: graceful close (error == null) or fault. Stops timers, signals the reader, raises Closed.
        void Terminate(Exception? error)
        {
            if (_terminal) return;
            _terminal = true;
            _rtoTimer.Change(Timeout.InfiniteTimeSpan, Timeout.InfiniteTimeSpan);
            _persistTimer.Change(Timeout.InfiniteTimeSpan, Timeout.InfiniteTimeSpan);
            _closeTimer.Change(Timeout.InfiniteTimeSpan, Timeout.InfiniteTimeSpan);
            _persistArmed = false;
            _state = TcpState.Closed;
            if (error != null) _connected.TrySetException(error);
            CompleteReceive(error); // null = end-of-stream (idempotent if the FIN already completed it)

            Action? handler = Closed;
            Closed = null;
            handler?.Invoke();
        }

        /// <summary>
        /// Aborts the connection if it is still alive — a pending <see cref="ReadAsync"/> completes with end-of-stream
        /// and a pending connect faults — then releases the timers. Idempotent; also invoked when the connection terminates.
        /// </summary>
        public void Dispose()
        {
            lock (_sync)
            {
                _connected.TrySetException(new ObjectDisposedException(nameof(TcpConnection))); // no-op once connected
                Terminate(null);
            }
            _rtoTimer.Dispose();
            _persistTimer.Dispose();
            _closeTimer.Dispose();
        }

        static bool SeqGreater(uint a, uint b) => (int)(a - b) > 0;
        static bool SeqGeq(uint a, uint b) => (int)(a - b) >= 0;
        static long Now() => Stopwatch.GetTimestamp();

        /// <summary>One unacked, sequence-consuming segment held for possible retransmission.</summary>
        sealed class RetxUnit
        {
            public uint Seq;
            public TcpFlags Flags;
            public byte[] Payload = Array.Empty<byte>();
            public int SeqLen;       // sequence space consumed: payload length, or 1 for a lone SYN/FIN
            public long SentTicks;
            public bool Retransmitted;
            public bool Sacked;            // peer selectively acknowledged this segment (RFC 2018) — excluded from the in-flight estimate
            public bool ResentInRecovery;  // already retransmitted as a hole during the current recovery episode (RFC 6675)
        }
    }
}
