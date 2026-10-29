using System.Runtime.ExceptionServices;
using System.Runtime.InteropServices;
using System.Threading.Channels;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Tls;
using Org.BouncyCastle.Tls.Crypto.Impl.BC;
using TqkLibrary.VpnClient.Abstractions.Transport.Interfaces;

namespace TqkLibrary.VpnClient.Transport.Dtls
{
    /// <summary>
    /// A DTLS 1.2 client datagram transport: an <see cref="IDatagramTransport"/> that wraps an <b>inner</b>
    /// <see cref="IDatagramTransport"/> (the plaintext UDP pipe), runs a BouncyCastle DTLS handshake over it on
    /// <see cref="ConnectAsync"/>, then encrypts each <see cref="SendAsync"/> and decrypts each <see cref="ReceiveAsync"/>
    /// as a single DTLS record. Boundaries are preserved (one app datagram = one DTLS record = one UDP datagram), so this
    /// is a drop-in replacement for a raw UDP transport wherever a confidential datagram pipe is needed — first consumer
    /// is the OpenConnect (V.5) DTLS data path.
    /// <para>
    /// <b>Why BouncyCastle:</b> the BCL <c>SslStream</c> implements TLS only, not DTLS, on every supported target
    /// framework, so the handshake and record layer run through <see cref="DtlsClientProtocol"/> on both
    /// <c>netstandard2.0</c> and <c>net8.0</c>.
    /// </para>
    /// <para>
    /// <b>Threading:</b> BouncyCastle's <see cref="DtlsTransport"/> is synchronous. The blocking handshake runs once on a
    /// thread-pool thread inside <see cref="ConnectAsync"/>. Afterwards no pool thread is parked: one dedicated
    /// background thread blocks in <c>Receive</c> and queues decrypted datagrams for <see cref="ReceiveAsync"/>, and
    /// <see cref="SendAsync"/> encrypts inline under a lock (the bridge's <c>Send</c> only queues). BouncyCastle's record
    /// layer tolerates one concurrent sender and one concurrent receiver; <see cref="ReceiveAsync"/> is single-consumer,
    /// exactly like a raw socket.
    /// </para>
    /// </summary>
    public sealed class DtlsDatagramTransport : IDatagramTransport
    {
        readonly IDatagramTransport _inner;
        readonly DtlsServerCertificateValidationCallback? _certificateValidationCallback;
        readonly DtlsResumptionParameters? _resumption;
        readonly DtlsPskParameters? _psk;
        readonly bool _ownsInner;

        BouncyCastleDatagramBridge? _bridge;
        DtlsTransport? _dtls;
        int _disposed;

        internal const int ReceiveQueueCapacity = 256;
        const int ReceivePollMillis = 250;
        static readonly TimeSpan ReceiverStopTimeout = TimeSpan.FromSeconds(2);

        // Receive side: one dedicated thread (started on the first ReceiveAsync) owns the blocking BC Receive and queues
        // decrypted datagrams here. When the consumer falls behind the oldest datagram is dropped, like a NIC ring —
        // stale tunnel packets are worth less than fresh ones, and the receive thread must keep draining the bridge.
        readonly Channel<byte[]> _inbound;
        readonly object _sendLock = new();
        Thread? _receiverThread;
        int _receiverStarted;
        long _receiveDropped;

        /// <summary>
        /// Wraps <paramref name="inner"/> (the plaintext UDP pipe) in DTLS. <paramref name="certificateValidationCallback"/>
        /// validates the server certificate during the handshake (null = accept any). When <paramref name="ownsInner"/> is
        /// true (the default) disposing this transport also disposes the inner pipe.
        /// <para>
        /// The handshake mode is chosen by the optional parameters (PSK wins when both are given):
        /// <list type="bullet">
        /// <item><paramref name="psk"/> — the modern OpenConnect <b>DTLS 1.2 PSK</b> full handshake (<c>PSK-NEGOTIATE</c>):
        /// a real handshake with a TLS-PSK key exchange, App-ID forced into the ClientHello session_id.</item>
        /// <item><paramref name="resumption"/> — the legacy AnyConnect <b>abbreviated</b> handshake (ocserv
        /// <c>dtls-legacy</c>): offers the gateway's session id + in-band master secret.</item>
        /// <item>neither — a normal full handshake (offline loopback / non-legacy certificate gateways).</item>
        /// </list>
        /// </para>
        /// </summary>
        public DtlsDatagramTransport(IDatagramTransport inner,
            DtlsServerCertificateValidationCallback? certificateValidationCallback = null, bool ownsInner = true,
            DtlsResumptionParameters? resumption = null, DtlsPskParameters? psk = null)
        {
            _inner = inner ?? throw new ArgumentNullException(nameof(inner));
            _certificateValidationCallback = certificateValidationCallback;
            _resumption = resumption;
            _psk = psk;
            _ownsInner = ownsInner;
            _inbound = Channel.CreateBounded<byte[]>(new BoundedChannelOptions(ReceiveQueueCapacity)
            {
                SingleReader = true,
                SingleWriter = true,
                FullMode = BoundedChannelFullMode.DropOldest,
            }, _ => Interlocked.Increment(ref _receiveDropped));
        }

        /// <summary>The negotiated DTLS receive limit (max plaintext bytes per <see cref="ReceiveAsync"/>); 0 until connected.</summary>
        public int ReceiveLimit => _dtls?.GetReceiveLimit() ?? 0;

        /// <summary>The negotiated DTLS send limit (max plaintext bytes per <see cref="SendAsync"/>); 0 until connected.</summary>
        public int SendLimit => _dtls?.GetSendLimit() ?? 0;

        /// <summary>Connects the inner pipe (if needed) then runs the DTLS 1.2 client handshake over it.</summary>
        public async ValueTask ConnectAsync(CancellationToken cancellationToken = default)
        {
            ThrowIfDisposed();
            if (_dtls is not null) throw new InvalidOperationException("The DTLS transport is already connected.");

            await _inner.ConnectAsync(cancellationToken).ConfigureAwait(false);
            var bridge = new BouncyCastleDatagramBridge(_inner);
            _bridge = bridge;

            var crypto = new BcTlsCrypto(new SecureRandom());
            // PSK (modern OpenConnect) wins when present; else legacy resumption / full handshake via DefaultDtlsClient.
            TlsClient client = _psk is not null
                ? new OpenConnectDtls12PskClient(crypto, _psk, _certificateValidationCallback)
                : new DefaultDtlsClient(crypto, _certificateValidationCallback, _resumption);
            var protocol = new DtlsClientProtocol();

            try
            {
                // The handshake is blocking (its retransmit timer drives the bridge's waitMillis Receive); run it off the
                // caller's thread and let cancellation abort it by closing the bridge so the blocking Receive returns.
                using (cancellationToken.Register(static b => ((BouncyCastleDatagramBridge)b!).Close(), bridge))
                {
                    _dtls = await Task.Run(() => protocol.Connect(client, bridge), cancellationToken).ConfigureAwait(false);
                }
            }
            catch
            {
                bridge.Close();
                _bridge = null;
                throw;
            }
        }

        /// <summary>Decrypted datagrams discarded because the receive queue was full (the oldest goes first, like a NIC ring).</summary>
        public long ReceiveDropped => Interlocked.Read(ref _receiveDropped);

        /// <summary>
        /// The next decrypted datagram, truncated to <paramref name="buffer"/> as before. Waits on the queue the dedicated
        /// receive thread fills, so no pool thread is parked while the link is idle; cancelling loses no datagram. A DTLS
        /// or transport error rethrows what the blocking receive threw; after dispose it throws
        /// <see cref="ObjectDisposedException"/>.
        /// </summary>
        public async ValueTask<int> ReceiveAsync(Memory<byte> buffer, CancellationToken cancellationToken = default)
        {
            ThrowIfDisposed();
            if (_dtls is null) throw new InvalidOperationException("The DTLS transport is not connected.");
            cancellationToken.ThrowIfCancellationRequested();
            EnsureReceiverStarted();

            byte[] datagram;
            try
            {
                datagram = await _inbound.Reader.ReadAsync(cancellationToken).ConfigureAwait(false);
            }
            catch (ChannelClosedException ex)
            {
                if (ex.InnerException is not null) ExceptionDispatchInfo.Capture(ex.InnerException).Throw();
                throw new ObjectDisposedException(nameof(DtlsDatagramTransport));
            }
            int n = Math.Min(datagram.Length, buffer.Length);
            datagram.AsSpan(0, n).CopyTo(buffer.Span);
            return n;
        }

        /// <summary>The dedicated receive thread, once the first receive started it (tests check it exits on dispose).</summary>
        internal Thread? ReceiverThread => _receiverThread;

        void EnsureReceiverStarted()
        {
            if (Interlocked.CompareExchange(ref _receiverStarted, 1, 0) != 0) return;
            var thread = new Thread(ReceiveLoop)
            {
                IsBackground = true,
                Name = "DtlsDatagramTransport receiver",
            };
            _receiverThread = thread;
            thread.Start();
        }

        /// <summary>
        /// Owns BouncyCastle's blocking <c>Receive</c> for the transport's life. The wait is bounded only so a dispose is
        /// noticed (the bridge's queue cannot be woken early); -1 just means "no record yet".
        /// </summary>
        void ReceiveLoop()
        {
            DtlsTransport dtls = _dtls!;
            ChannelWriter<byte[]> writer = _inbound.Writer;
            byte[] buffer = new byte[Math.Max(dtls.GetReceiveLimit(), 1)];
            try
            {
                while (Volatile.Read(ref _disposed) == 0)
                {
                    int read = dtls.Receive(buffer, 0, buffer.Length, ReceivePollMillis);
                    if (read < 0) continue;
                    writer.TryWrite(buffer.AsSpan(0, read).ToArray());   // DropOldest: never blocks this thread
                }
                writer.TryComplete();
            }
            catch (Exception ex)
            {
                // Disposing closes the bridge under the blocked Receive: that ends the loop, it is not a fault.
                writer.TryComplete(Volatile.Read(ref _disposed) != 0 ? null : ex);
            }
        }

        /// <summary>
        /// Encrypts and hands the record to the bridge inline: the bridge only queues it for its async send pump, so this
        /// never blocks on the network and needs no pool thread. Serialized by a lock (BouncyCastle's record layer is not
        /// safe for concurrent senders). Errors surface through the returned task, as before.
        /// </summary>
        public ValueTask SendAsync(ReadOnlyMemory<byte> datagram, CancellationToken cancellationToken = default)
        {
            DtlsTransport dtls = _dtls ?? throw new InvalidOperationException("The DTLS transport is not connected.");
            if (cancellationToken.IsCancellationRequested) return new ValueTask(Task.FromCanceled(cancellationToken));
            try
            {
                lock (_sendLock)
                {
                    if (MemoryMarshal.TryGetArray(datagram, out ArraySegment<byte> segment))
                        dtls.Send(segment.Array!, segment.Offset, segment.Count);
                    else
                    {
                        byte[] copy = datagram.ToArray(); // BouncyCastle Send takes a byte[]+offset+len; copy out of the Memory
                        dtls.Send(copy, 0, copy.Length);
                    }
                }
                return default;
            }
            catch (Exception ex)
            {
                return new ValueTask(Task.FromException(ex));
            }
        }

        /// <inheritdoc/>
        public async ValueTask DisposeAsync()
        {
            if (Interlocked.Exchange(ref _disposed, 1) != 0) return;
            lock (_sendLock)
            {
                try { _dtls?.Close(); } catch { } // sends a close_notify alert (best-effort)
            }
            _bridge?.Close();
            // The receiver notices within one poll; bounded so a wedged Receive cannot hang the caller.
            Thread? receiver = _receiverThread;
            if (receiver is not null && receiver != Thread.CurrentThread) receiver.Join(ReceiverStopTimeout);
            _inbound.Writer.TryComplete();
            if (_ownsInner)
                await _inner.DisposeAsync().ConfigureAwait(false);
        }

        void ThrowIfDisposed()
        {
            if (Volatile.Read(ref _disposed) != 0)
                throw new ObjectDisposedException(nameof(DtlsDatagramTransport));
        }
    }
}
