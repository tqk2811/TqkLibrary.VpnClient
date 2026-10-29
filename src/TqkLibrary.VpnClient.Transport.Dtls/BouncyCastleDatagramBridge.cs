using System.Collections.Concurrent;
using System.Threading.Channels;
using Org.BouncyCastle.Tls;
using TqkLibrary.VpnClient.Abstractions.Transport.Interfaces;

namespace TqkLibrary.VpnClient.Transport.Dtls
{
    /// <summary>
    /// Adapts our async <see cref="IDatagramTransport"/> (the outer UDP pipe) to BouncyCastle's <b>synchronous</b>
    /// <see cref="Org.BouncyCastle.Tls.DatagramTransport"/>, which the DTLS record layer drives directly.
    /// <para>
    /// BouncyCastle's record layer is blocking: it calls <see cref="Send"/> inline and <see cref="Receive(byte[],int,int,int)"/>
    /// with a <c>waitMillis</c> timeout (returning <c>-1</c> on timeout so its retransmit logic can fire). The inner pipe is
    /// async, so a background receive loop pulls datagrams off it and parks them in a bounded queue that <see cref="Receive(byte[],int,int,int)"/>
    /// blocks on. <see cref="Send(byte[],int,int)"/> never blocks: it copies the datagram into a bounded outbound queue that a
    /// background send loop drains in order through <see cref="IDatagramTransport.SendAsync"/>; that loop's first failure
    /// is thrown (as <see cref="IOException"/>) by the next <see cref="Send(byte[],int,int)"/>. This bridge is internal —
    /// it only ever runs on the dedicated handshake/IO thread <see cref="DtlsDatagramTransport"/> owns, never on the
    /// public async path.
    /// </para>
    /// </summary>
    sealed class BouncyCastleDatagramBridge : Org.BouncyCastle.Tls.DatagramTransport
    {
        // DTLS 1.2 records ride a single UDP datagram; 1500 (typical Ethernet MTU) bounds one record's plaintext/ciphertext.
        const int MtuLimit = 1500;

        readonly IDatagramTransport _inner;
        readonly BlockingCollection<byte[]> _inbound = new(new ConcurrentQueue<byte[]>());
        // Outbound datagrams waiting for the async inner SendAsync. A DTLS flight is a handful of datagrams (a long
        // certificate chain fragments into ~10) and app data is paced by the caller, so 256 only fills if the inner
        // pipe stalls; then dropping the oldest is plain UDP loss, which DTLS retransmission already recovers from.
        const int OutboundCapacity = 256;

        readonly Channel<byte[]> _outbound = Channel.CreateBounded<byte[]>(new BoundedChannelOptions(OutboundCapacity)
        {
            FullMode = BoundedChannelFullMode.DropOldest,
            SingleReader = true,
        });
        readonly CancellationTokenSource _loopCts = new();
        readonly Task _receivePump;
        readonly Task _sendPump;
        Exception? _sendFault; // first inner SendAsync failure; the next Send rethrows it (wrapped) so DTLS fails fast
        int _closed;

        public BouncyCastleDatagramBridge(IDatagramTransport inner)
        {
            _inner = inner ?? throw new ArgumentNullException(nameof(inner));
            _receivePump = Task.Run(() => PumpInboundAsync(_loopCts.Token));
            _sendPump = Task.Run(() => PumpOutboundAsync(_loopCts.Token));
        }

        /// <summary>Background loop: sends each queued datagram on the inner pipe, in order, until the queue completes.</summary>
        async Task PumpOutboundAsync(CancellationToken cancellationToken)
        {
            try
            {
                while (await _outbound.Reader.WaitToReadAsync(cancellationToken).ConfigureAwait(false))
                {
                    while (_outbound.Reader.TryRead(out byte[]? datagram))
                    {
                        try { await _inner.SendAsync(datagram, cancellationToken).ConfigureAwait(false); }
                        catch (OperationCanceledException) { throw; }
                        catch (Exception ex) { Interlocked.CompareExchange(ref _sendFault, ex, null); } // surfaced by the next Send
                    }
                }
            }
            catch (OperationCanceledException) { } // normal shutdown
        }

        /// <summary>Background loop: copies each inner datagram into the inbound queue until cancelled or the pipe faults.</summary>
        async Task PumpInboundAsync(CancellationToken cancellationToken)
        {
            byte[] buffer = new byte[MtuLimit];
            try
            {
                while (!cancellationToken.IsCancellationRequested)
                {
                    int read = await _inner.ReceiveAsync(buffer, cancellationToken).ConfigureAwait(false);
                    if (read <= 0) continue; // a 0-length datagram is not a close on UDP — keep listening
                    _inbound.Add(buffer.AsSpan(0, read).ToArray(), cancellationToken);
                }
            }
            catch (OperationCanceledException) { } // normal shutdown
            catch (Exception) { } // inner pipe faulted/closed — Receive will then time out and DTLS surfaces the failure
            finally { _inbound.CompleteAdding(); }
        }

        /// <inheritdoc/>
        public int GetReceiveLimit() => MtuLimit;

        /// <inheritdoc/>
        public int GetSendLimit() => MtuLimit;

        /// <inheritdoc/>
        public int Receive(byte[] buf, int off, int len, int waitMillis)
        {
            // -1 signals "no datagram within waitMillis" so BouncyCastle's flight-retransmit timer can fire.
            if (!_inbound.TryTake(out byte[]? datagram, waitMillis)) return -1;
            int n = Math.Min(len, datagram.Length);
            Buffer.BlockCopy(datagram, 0, buf, off, n);
            return n;
        }

#if NETSTANDARD2_1_OR_GREATER || NET5_0_OR_GREATER
        /// <inheritdoc/>
        public int Receive(Span<byte> buffer, int waitMillis)
        {
            if (!_inbound.TryTake(out byte[]? datagram, waitMillis)) return -1;
            int n = Math.Min(buffer.Length, datagram.Length);
            datagram.AsSpan(0, n).CopyTo(buffer);
            return n;
        }
#endif

        /// <inheritdoc/>
        public void Send(byte[] buf, int off, int len)
        {
            // Non-blocking: copy (BouncyCastle reuses its buffer) and queue for the send pump. A failure of an earlier
            // (pumped) send is thrown here as IOException, and Send after Close throws ObjectDisposedException — like the
            // old inline SendAsync did — so BouncyCastle fails the record layer instead of retransmitting into a dead pipe.
            if (Volatile.Read(ref _closed) != 0) throw new ObjectDisposedException(nameof(BouncyCastleDatagramBridge));
            Exception? fault = Volatile.Read(ref _sendFault);
            if (fault != null) throw new IOException("An earlier send on the DTLS inner transport failed.", fault);
            byte[] datagram = new byte[len];
            Buffer.BlockCopy(buf, off, datagram, 0, len);
            if (!_outbound.Writer.TryWrite(datagram)) throw new ObjectDisposedException(nameof(BouncyCastleDatagramBridge));
        }

#if NETSTANDARD2_1_OR_GREATER || NET5_0_OR_GREATER
        /// <inheritdoc/>
        public void Send(ReadOnlySpan<byte> buffer)
            => Send(buffer.ToArray(), 0, buffer.Length);
#endif

        /// <inheritdoc/>
        public void Close()
        {
            if (Interlocked.Exchange(ref _closed, 1) != 0) return;
            // Let already-queued datagrams (e.g. the close_notify alert BouncyCastle sends right before Close) drain first.
            _outbound.Writer.TryComplete();
            try { _sendPump.Wait(1000); } catch { }
            try { _loopCts.Cancel(); } catch { }
            try { _receivePump.Wait(2000); } catch { }
            try { _sendPump.Wait(2000); } catch { }
            _loopCts.Dispose();
            _inbound.Dispose();
        }
    }
}
