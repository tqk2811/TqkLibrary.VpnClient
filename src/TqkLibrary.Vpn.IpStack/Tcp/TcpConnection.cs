using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Net;
using System.Security.Cryptography;
using System.Threading;
using TqkLibrary.Vpn.IpStack.Tcp.Enums;

namespace TqkLibrary.Vpn.IpStack.Tcp
{
    /// <summary>
    /// An active-open TCP connection over the userspace stack. The peer is a real host on the internet (reached
    /// through the VPN gateway), so this is a reliable stack: the send path holds every sequence-consuming segment
    /// in a retransmission queue, retransmits on an RFC 6298 RTO (RTT-estimated, exponentially backed-off, with a
    /// give-up cap), and honours the peer's advertised receive window (sliding-window flow control + a zero-window
    /// persist probe); the receive path reassembles out-of-order segments before delivering in order via
    /// <see cref="ReadAsync"/>, and the close path runs the full half-close FSM (FINWAIT1/2, CLOSING, TIMEWAIT,
    /// CLOSEWAIT, LASTACK) with a TIME-WAIT linger.
    /// </summary>
    /// <remarks>
    /// Congestion control (cwnd/slow-start/fast-retransmit) is intentionally omitted — only flow control (the
    /// receiver window) is implemented. Inbound IP fragments are assumed already reassembled by the IP layer.
    /// </remarks>
    public sealed class TcpConnection : IDisposable
    {
        const ushort DefaultLinkMtu = 1400;  // tunnel default → MSS 1360 (unchanged from the old hard-coded value)
        const ushort MinMss = 88;            // defensive floor so a tiny/bogus MTU can't produce a useless segment size
        const ushort AssumedPeerMss = 536;   // RFC 1122: assume a 536-byte send MSS if the peer advertises none
        const ushort ReceiveWindow = 65535;
        const byte RcvWScale = 2;            // window scaling we advertise (RFC 7323): effective rwnd = 65535 << 2 ≈ 256 KB

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
        // SendIp never has to fragment them.
        readonly ushort _localMss;
        ushort _sendMss;

        // Window scaling (RFC 7323), negotiated on the SYN exchange. _sndWScale scales the peer's advertised window
        // (raising our send ceiling above 64 KB); _rcvScaleActive (peer also offered scaling) widens the window we
        // accept on receive. Both stay 0/false unless the peer's SYN-ACK carries a Window Scale option.
        byte _sndWScale;
        bool _rcvScaleActive;

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
            // MSS = link MTU − IPv4(20) − TCP(20); floored so a tiny MTU can't yield a useless segment size, and
            // capped so an absurd MTU stays within the 16-bit option field. Until the peer's SYN-ACK is seen we send
            // at our own MSS.
            _localMss = (ushort)Math.Min(65495, Math.Max(MinMss, linkMtu - 40));
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
                EmitSegment(iss, TcpFlags.Syn, ReadOnlySpan<byte>.Empty, mss: _localMss, windowScale: RcvWScale);
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
                    ProcessAck(ack, seq, wnd);                 // acks our SYN, seeds the send window (SYN-ACK window is unscaled)
                    // Window scaling takes effect only if the peer also offered it (RFC 7323); its window is scaled hereafter.
                    byte peerWScale = TcpSegment.WindowScale(span);
                    if (peerWScale != TcpSegment.NoWindowScale)
                    {
                        _sndWScale = peerWScale > 14 ? (byte)14 : peerWScale; // RFC 7323 §2.3: clamp the shift count to 14
                        _rcvScaleActive = true;
                    }
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
            if ((flags & TcpFlags.Ack) != 0) ProcessAck(ack, seq, wnd);
            if (len > 0) ReceiveData(seq, payload);
            if (fin) NoteFin(seq, len);
            TryConsumePeerFin();
            if (len > 0 || fin) EmitSegment(_sndNxt, TcpFlags.Ack, ReadOnlySpan<byte>.Empty); // cumulative / dup ACK
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
                    int usable = (int)((_sndUna + _sndWnd) - _sndNxt); // signed window space left
                    if (usable <= 0) break;
                    int chunk = Math.Min(Math.Min((int)_sendMss, usable), _sndBufferedBytes);
                    EmitData(_sndNxt, DequeueUpTo(chunk));
                }

                if (_finRequested && !_finSent && _sndBufferedBytes == 0)
                    EmitFin();
            }

            if (canSend && !_finSent && _sndWnd == 0 && _sndBufferedBytes > 0) EnsurePersist();
            else StopPersist();

            ArmRtoTimer();
        }

        void ProcessAck(uint ack, uint segSeq, ushort segWnd)
        {
            if (SeqGreater(ack, _sndUna))
            {
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
            }

            // RFC 793 window update: accept only if this segment is newer (by seq, then by ack).
            if (SeqGreater(segSeq, _sndWl1) || (segSeq == _sndWl1 && !SeqGreater(_sndWl2, ack)))
            {
                if (_sndWnd == 0 && segWnd > 0) _persistMs = _opts.PersistMin.TotalMilliseconds; // window reopened
                _sndWnd = (uint)segWnd << _sndWScale; // apply the peer's negotiated window scale (RFC 7323)
                _sndWl1 = segSeq;
                _sndWl2 = ack;
            }

            TrySendData();
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

        void EmitSegment(uint seq, TcpFlags flags, ReadOnlySpan<byte> payload, ushort mss = 0, byte windowScale = TcpSegment.NoWindowScale)
        {
            byte[] tcp = TcpSegment.Build(_localIp, _remoteIp, _localPort, _remotePort, seq, _rcvNxt, flags, ReceiveWindow, payload, mss, windowScale);
            byte[] ip = Ipv4.Build(_localIp, _remoteIp, Ipv4.ProtocolTcp, tcp, _ipId++);
            _sendIp(ip);
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

                RetxUnit u = node.Value;
                bool isSyn = (u.Flags & TcpFlags.Syn) != 0;
                EmitSegment(u.Seq, u.Flags, u.Payload, isSyn ? _localMss : (ushort)0, isSyn ? RcvWScale : TcpSegment.NoWindowScale);
                u.Retransmitted = true;
                u.SentTicks = now;
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
        }
    }
}
