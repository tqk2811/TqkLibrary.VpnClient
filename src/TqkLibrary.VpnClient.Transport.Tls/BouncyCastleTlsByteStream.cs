using System.Collections.Concurrent;
using System.Net;
using System.Net.Security;
using System.Runtime.ExceptionServices;
using System.Security.Cryptography.X509Certificates;
using System.Threading.Channels;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Tls;
using Org.BouncyCastle.Tls.Crypto;
using Org.BouncyCastle.Tls.Crypto.Impl.BC;
using TqkLibrary.VpnClient.Abstractions.Net;
using TqkLibrary.VpnClient.Abstractions.Transport.Interfaces;
using TqkLibrary.VpnClient.Transport.Tcp;

namespace TqkLibrary.VpnClient.Transport.Tls
{
    /// <summary>
    /// A TLS 1.2 client byte stream backed by <b>BouncyCastle</b> (<see cref="TlsClientProtocol"/>) instead of the BCL
    /// <see cref="SslStream"/>. It exists for one reason the SslStream-based <see cref="TlsByteStream"/> cannot serve: it
    /// exposes an <b>RFC 5705 keying-material exporter</b> (<see cref="ExportKeyingMaterial"/>) over the finished TLS
    /// session — <see cref="SslStream"/> has no such API on <c>netstandard2.0</c>/<c>net8.0</c>. The first consumer is the
    /// OpenConnect (V.5) <b>DTLS 1.2 PSK</b> data path, whose 32-byte pre-shared key is exported from the CSTP
    /// control-channel TLS session (label <c>"EXPORTER-openconnect-psk"</c>, empty context).
    /// <para>
    /// It is otherwise a drop-in <see cref="ITlsByteStream"/>: it wraps a <see cref="TcpByteStream"/>, runs the client
    /// handshake (accept-any cert by default, captured into <see cref="RemoteCertificate"/>; an optional callback may
    /// reject), and reads/writes application data. SSTP/SoftEther keep using the SslStream <see cref="TlsByteStream"/> —
    /// only a caller that needs the exporter wires this one, so the live TLS data paths are unaffected.
    /// </para>
    /// <para>
    /// <b>Threading:</b> BouncyCastle's <see cref="TlsClientProtocol"/> drives a synchronous record layer over the inner
    /// <see cref="NetworkStream"/>. The blocking handshake runs once on a thread-pool thread inside
    /// <see cref="ConnectAsync"/>. Afterwards no pool thread is parked: one dedicated background thread blocks in the
    /// application-data <see cref="System.IO.Stream"/>'s <c>Read</c> and queues decrypted chunks for
    /// <see cref="ReadAsync"/>; a second dedicated thread drains a bounded queue that <see cref="WriteAsync"/> fills, so
    /// no caller ever blocks on a full send buffer (its record layer tolerates one concurrent reader and one concurrent
    /// writer — exactly these two threads).
    /// </para>
    /// </summary>
    public sealed class BouncyCastleTlsByteStream : ITlsByteStream, ITlsKeyingMaterialExporter, IDisposable
    {
        readonly TcpByteStream _tcp;
        readonly string _host;
        readonly RemoteCertificateValidationCallback? _certificateValidationCallback;
        readonly List<KeyingMaterialRequest> _pendingExports = new();

        TlsClientProtocol? _protocol;
        Stream? _appData; // protocol.Stream — the decrypted application-data pipe
        ExporterTlsClient? _client;

        const int ReadChunkSize = 16 * 1024;     // one TLS record's worth of plaintext
        const int MaxQueuedChunks = 64;
        static readonly TimeSpan ReaderStopTimeout = TimeSpan.FromSeconds(2);

        // Read side: one dedicated thread (started on the first ReadAsync) owns the blocking BC Read and hands chunks
        // over this queue; _freeChunks bounds it. _leftover is the part of the last chunk the caller has not read yet.
        readonly Channel<byte[]> _inbound = Channel.CreateUnbounded<byte[]>(new UnboundedChannelOptions
        {
            SingleReader = true,
            SingleWriter = true,
        });
        readonly SemaphoreSlim _freeChunks = new(MaxQueuedChunks, MaxQueuedChunks);
        readonly CancellationTokenSource _disposeCts = new();
        readonly object _writeLock = new();

        // Write side: WriteAsync copies the caller's bytes into this queue and returns; one dedicated thread (started on
        // the first write) encrypts and sends them in order. _freeWriteSlots bounds the queue (no max count, so a write
        // fault can wake every waiter); _queuedWrites counts what the writer may take and is waited on synchronously.
        const int MaxQueuedWrites = 64;
        readonly ConcurrentQueue<byte[]> _outbound = new();
        readonly SemaphoreSlim _freeWriteSlots = new(MaxQueuedWrites);
        readonly SemaphoreSlim _queuedWrites = new(0);
        volatile Exception? _writeFault;
        volatile bool _writerCompleting;

        // Both threads are created and published under this lock, and Dispose reads them under it after setting
        // _disposed, so a thread is either joined by Dispose or never started.
        readonly object _threadLock = new();
        Thread? _readerThread;
        Thread? _writerThread;
        int _disposed;
        byte[]? _leftover;
        int _leftoverOffset;

        /// <summary>
        /// Creates a BouncyCastle TLS byte stream to <paramref name="host"/>:<paramref name="port"/> (not yet connected).
        /// See the type summary for the certificate-validation semantics (accept-any by default; the cert is captured
        /// into <see cref="RemoteCertificate"/> either way). <paramref name="addressFamilyPreference"/> selects IPv4/IPv6
        /// for the inner TCP connection; <paramref name="hostResolver"/> performs the name→address lookup (default DNS).
        /// </summary>
        public BouncyCastleTlsByteStream(string host, int port = 443,
            RemoteCertificateValidationCallback? certificateValidationCallback = null,
            AddressFamilyPreference addressFamilyPreference = AddressFamilyPreference.Auto, IHostResolver? hostResolver = null)
        {
            _host = host ?? throw new ArgumentNullException(nameof(host));
            _tcp = new TcpByteStream(host, port, addressFamilyPreference, hostResolver);
            _certificateValidationCallback = certificateValidationCallback;
        }

        /// <summary>
        /// Creates a BouncyCastle TLS byte stream over an already-resolved <paramref name="remote"/> endpoint, keeping
        /// <paramref name="host"/> as the TLS TargetHost (SNI). Used when the caller resolves the address itself (e.g. to
        /// correlate a parallel DTLS path).
        /// </summary>
        public BouncyCastleTlsByteStream(string host, IPEndPoint remote,
            RemoteCertificateValidationCallback? certificateValidationCallback = null)
        {
            _host = host ?? throw new ArgumentNullException(nameof(host));
            _tcp = new TcpByteStream(remote);
            _certificateValidationCallback = certificateValidationCallback;
        }

        /// <inheritdoc/>
        public X509Certificate2? RemoteCertificate { get; private set; }

        /// <summary>
        /// Registers an RFC 5705 keying-material export to be computed <b>during</b> the handshake (before
        /// <see cref="ConnectAsync"/>). BouncyCastle clears the TLS master secret as soon as the handshake completes, so
        /// any export must be captured while it is still alive; this queues the request and <see cref="ConnectAsync"/>
        /// fulfils it at handshake-complete, caching the bytes for <see cref="ExportKeyingMaterial"/> to return. The
        /// OpenConnect DTLS-PSK path registers its single export (label <c>"EXPORTER-openconnect-psk"</c>, empty context,
        /// 32 bytes) up front.
        /// </summary>
        public void RequestKeyingMaterialExport(string label, ReadOnlySpan<byte> context, int length)
        {
            if (_protocol is not null) throw new InvalidOperationException("Keying-material exports must be requested before connecting.");
            _pendingExports.Add(new KeyingMaterialRequest(label, context.ToArray(), length));
        }

        /// <inheritdoc/>
        public async ValueTask ConnectAsync(CancellationToken cancellationToken = default)
        {
            await _tcp.ConnectAsync(cancellationToken).ConfigureAwait(false);

            var crypto = new BcTlsCrypto(new SecureRandom());
            var client = new ExporterTlsClient(crypto, _host, _certificateValidationCallback,
                cert => RemoteCertificate = cert, _pendingExports);
            var protocol = new TlsClientProtocol(_tcp.Stream);

            try
            {
                // The BC handshake is blocking (it reads/writes the inner NetworkStream inline); run it off the caller's
                // thread and abort it by disposing the inner socket so the blocking read returns.
                using (cancellationToken.Register(static s => ((TcpByteStream)s!).Dispose(), _tcp))
                {
                    await Task.Run(() => protocol.Connect(client), cancellationToken).ConfigureAwait(false);
                }
            }
            catch
            {
                try { protocol.Close(); } catch { }
                throw;
            }

            _client = client;
            _protocol = protocol;
            _appData = protocol.Stream;
        }

        /// <summary>
        /// Reads decrypted application data. Served from the chunk the reader thread delivered last before waiting for
        /// the next one, so a byte-at-a-time caller (the OpenConnect header parser) never over-reads into the next CSTP
        /// frame. Cancelling a pending read loses no bytes: the chunk stays queued for the next call. End of stream from
        /// the peer (close_notify / FIN) returns 0; a TLS or socket error rethrows what the blocking read threw. Once this
        /// stream is disposed — including a read pending at that moment, after any data already queued — it throws
        /// <see cref="ObjectDisposedException"/> rather than returning 0, so a driver's read loop does not mistake its own
        /// teardown for the peer closing the session (OpenConnect's CSTP loop treats 0 as "gateway closed" and
        /// reconnects; a fault just ends the loop). Not safe for concurrent readers (one read loop per stream).
        /// </summary>
        public async ValueTask<int> ReadAsync(Memory<byte> buffer, CancellationToken cancellationToken = default)
        {
            if (_appData is null) throw new InvalidOperationException("The TLS stream is not connected.");
            if (Volatile.Read(ref _disposed) != 0) throw new ObjectDisposedException(nameof(BouncyCastleTlsByteStream));
            cancellationToken.ThrowIfCancellationRequested();
            if (buffer.Length == 0) return 0;
            if (_leftover is not null) return TakeLeftover(buffer.Span);

            EnsureReaderStarted();
            byte[] chunk;
            try
            {
                chunk = await _inbound.Reader.ReadAsync(cancellationToken).ConfigureAwait(false);
            }
            catch (ChannelClosedException ex)
            {
                if (ex.InnerException is null) return 0;   // clean end of stream
                ExceptionDispatchInfo.Capture(ex.InnerException).Throw();
                throw;   // unreachable
            }
            _freeChunks.Release();   // the reader thread may queue another chunk

            _leftover = chunk;
            _leftoverOffset = 0;
            return TakeLeftover(buffer.Span);
        }

        int TakeLeftover(Span<byte> destination)
        {
            byte[] chunk = _leftover!;
            int n = Math.Min(destination.Length, chunk.Length - _leftoverOffset);
            chunk.AsSpan(_leftoverOffset, n).CopyTo(destination);
            _leftoverOffset += n;
            if (_leftoverOffset == chunk.Length) _leftover = null;
            return n;
        }

        /// <summary>The dedicated reader thread, once the first read started it (tests check it exits on dispose).</summary>
        internal Thread? ReaderThread => _readerThread;

        /// <summary>The dedicated writer thread, once the first write started it (tests check it exits on dispose).</summary>
        internal Thread? WriterThread => _writerThread;

        void EnsureReaderStarted()
        {
            if (Volatile.Read(ref _readerThread) is not null) return;
            lock (_threadLock)
            {
                if (Volatile.Read(ref _disposed) != 0) throw new ObjectDisposedException(nameof(BouncyCastleTlsByteStream));
                if (_readerThread is not null) return;
                var thread = new Thread(ReadLoop) { IsBackground = true, Name = "BouncyCastleTlsByteStream reader" };
                thread.Start();
                Volatile.Write(ref _readerThread, thread);
            }
        }

        void EnsureWriterStarted()
        {
            if (Volatile.Read(ref _writerThread) is not null) return;
            lock (_threadLock)
            {
                if (Volatile.Read(ref _disposed) != 0) throw new ObjectDisposedException(nameof(BouncyCastleTlsByteStream));
                if (_writerThread is not null) return;
                var thread = new Thread(WriteLoop) { IsBackground = true, Name = "BouncyCastleTlsByteStream writer" };
                thread.Start();
                Volatile.Write(ref _writerThread, thread);
            }
        }

        /// <summary>
        /// The dedicated reader: blocks in BouncyCastle's synchronous <c>Read</c> (which is where a pool thread used to
        /// be parked for the tunnel's whole life) and queues a copy of every decrypted chunk. Backpressure without the
        /// pool: a <see cref="SemaphoreSlim"/> counts free queue slots and this thread blocks synchronously on it
        /// (Monitor-based, woken inline by the consumer's <c>Release</c>) — awaiting a bounded channel's
        /// <c>WaitToWriteAsync</c> here would instead need a pool thread to run the wake-up continuation. While the
        /// queue is full this thread stops reading, the TCP receive window closes, and the server slows down.
        /// </summary>
        void ReadLoop()
        {
            Stream appData = _appData!;
            ChannelWriter<byte[]> writer = _inbound.Writer;
            byte[] buffer = new byte[ReadChunkSize];
            try
            {
                while (true)
                {
                    int read = appData.Read(buffer, 0, buffer.Length);
                    if (read <= 0) break;
                    _freeChunks.Wait(_disposeCts.Token);
                    writer.TryWrite(buffer.AsSpan(0, read).ToArray());   // unbounded underneath: the semaphore bounds it
                }
                writer.TryComplete(DisposedOrNull());
            }
            catch (Exception ex)
            {
                // Disposing closes the socket under the blocked Read: that is this stream's teardown, not a TLS fault.
                writer.TryComplete(DisposedOrNull() ?? ex);
            }
        }

        Exception? DisposedOrNull()
            => Volatile.Read(ref _disposed) != 0 ? new ObjectDisposedException(nameof(BouncyCastleTlsByteStream)) : null;

        /// <summary>
        /// Queues a copy of <paramref name="buffer"/> for the dedicated writer thread and returns; the writer encrypts
        /// and sends chunks in call order under <c>_writeLock</c> (BouncyCastle's record layer is not safe for concurrent
        /// writers). The caller therefore never blocks on a full kernel send buffer — the caller can be the IP stack's
        /// egress path on a pool thread. Backpressure: at most <see cref="MaxQueuedWrites"/> chunks wait; beyond that the
        /// call awaits a free slot asynchronously. A send failure is stored; the next call throws
        /// <see cref="IOException"/> wrapping it (the bytes of a failed or still-queued write are lost, as on a dead link).
        /// </summary>
        public ValueTask WriteAsync(ReadOnlyMemory<byte> buffer, CancellationToken cancellationToken = default)
        {
            if (_appData is null) throw new InvalidOperationException("The TLS stream is not connected.");
            if (cancellationToken.IsCancellationRequested) return new ValueTask(Task.FromCanceled(cancellationToken));
            try
            {
                ThrowIfWriteUnavailable();
                EnsureWriterStarted();
                byte[] copy = buffer.ToArray();   // the caller may reuse its buffer as soon as this returns
                if (_freeWriteSlots.Wait(0))
                {
                    EnqueueWrite(copy);
                    return default;
                }
                return WriteSlowAsync(copy, cancellationToken);
            }
            catch (Exception ex)
            {
                return new ValueTask(Task.FromException(ex));
            }
        }

        async ValueTask WriteSlowAsync(byte[] copy, CancellationToken cancellationToken)
        {
            using var linked = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken, _disposeCts.Token);
            try
            {
                await _freeWriteSlots.WaitAsync(linked.Token).ConfigureAwait(false);
            }
            catch (OperationCanceledException) when (!cancellationToken.IsCancellationRequested)
            {
                throw new ObjectDisposedException(nameof(BouncyCastleTlsByteStream));
            }
            ThrowIfWriteUnavailable();   // a fault releases every waiter so it can surface here
            EnqueueWrite(copy);
        }

        void EnqueueWrite(byte[] copy)
        {
            _outbound.Enqueue(copy);
            _queuedWrites.Release();
        }

        void ThrowIfWriteUnavailable()
        {
            if (Volatile.Read(ref _disposed) != 0) throw new ObjectDisposedException(nameof(BouncyCastleTlsByteStream));
            Exception? fault = _writeFault;
            if (fault is not null) throw new IOException("A previous TLS write failed; the stream can no longer send.", fault);
        }

        /// <summary>
        /// The dedicated writer: takes queued chunks in order and writes them through BouncyCastle's blocking record
        /// layer. It is the only thread that blocks on a full kernel send buffer. On Dispose it first drains what is
        /// already queued (bounded by Dispose's join), so a final control frame (e.g. CSTP DISCONNECT) still goes out.
        /// </summary>
        void WriteLoop()
        {
            Stream appData = _appData!;
            try
            {
                while (true)
                {
                    _queuedWrites.Wait(_disposeCts.Token);
                    if (!_outbound.TryDequeue(out byte[]? chunk))
                    {
                        if (_writerCompleting) return;   // the wake-up Dispose posted after the last chunk
                        continue;
                    }
                    lock (_writeLock) appData.Write(chunk, 0, chunk.Length);
                    _freeWriteSlots.Release();
                }
            }
            catch (OperationCanceledException) when (_disposeCts.IsCancellationRequested)
            {
            }
            catch (Exception ex)
            {
                if (Volatile.Read(ref _disposed) == 0) _writeFault = ex;
                _freeWriteSlots.Release(MaxQueuedWrites);   // wake writers waiting for a slot: they see the fault
            }
        }

        /// <inheritdoc/>
        public byte[] ExportKeyingMaterial(string label, ReadOnlySpan<byte> context, int length)
        {
            ExporterTlsClient client = _client ?? throw new InvalidOperationException("The TLS stream is not connected.");
            // The master secret is gone after the handshake, so the value must have been pre-registered via
            // RequestKeyingMaterialExport and captured at handshake-complete; return that cached result.
            if (client.TryGetCachedExport(label, context, length, out byte[] result)) return result;
            throw new InvalidOperationException(
                $"No keying-material export was registered for label '{label}'; call {nameof(RequestKeyingMaterialExport)} before {nameof(ConnectAsync)}.");
        }

        /// <summary>A queued/cached RFC 5705 export: the label, context and length, plus the captured output once computed.</summary>
        sealed class KeyingMaterialRequest
        {
            public KeyingMaterialRequest(string label, byte[] context, int length)
            {
                Label = label;
                Context = context;
                Length = length;
            }

            public string Label { get; }
            public byte[] Context { get; }
            public int Length { get; }
            public byte[]? Output { get; set; }

            public bool Matches(string label, ReadOnlySpan<byte> context, int length)
                => Length == length && Label == label && context.SequenceEqual(Context);
        }

        /// <inheritdoc/>
        public ValueTask DisposeAsync()
        {
            Dispose();
            return default;
        }

        /// <inheritdoc/>
        public void Dispose()
        {
            Thread? reader, writer;
            lock (_threadLock)
            {
                if (Interlocked.Exchange(ref _disposed, 1) != 0) return;
                reader = _readerThread;   // no thread can be started after this point
                writer = _writerThread;
            }
            // Let the writer flush what is already queued (a final control frame), bounded: it may be stuck on a full
            // send buffer, in which case the socket close below unblocks it.
            _writerCompleting = true;
            _queuedWrites.Release();
            if (writer is not null && writer != Thread.CurrentThread) writer.Join(ReaderStopTimeout);
            _disposeCts.Cancel();   // a reader parked on a full queue, a writer still waiting, WriteAsync callers waiting for a slot
            // close_notify (best-effort), but never behind a write stuck on a full send buffer.
            if (Monitor.TryEnter(_writeLock, writer is { IsAlive: true } ? TimeSpan.Zero : ReaderStopTimeout))
            {
                try { _protocol?.Close(); } catch { }
                finally { Monitor.Exit(_writeLock); }
            }
            _tcp.Dispose();         // a reader blocked in Read (or a writer in Write) returns (throws) and ends its loop
            if (reader is not null && reader != Thread.CurrentThread) reader.Join(ReaderStopTimeout);
            if (writer is not null && writer != Thread.CurrentThread) writer.Join(ReaderStopTimeout);
            _inbound.Writer.TryComplete(new ObjectDisposedException(nameof(BouncyCastleTlsByteStream)));
            RemoteCertificate?.Dispose();
        }

        /// <summary>
        /// The TLS 1.2 client: pins the protocol version (DTLS-free interop is simplest at TLS 1.2), accepts the server
        /// certificate (capturing it and applying the optional validation callback), supplies no client credentials, and
        /// captures its <see cref="TlsClientContext"/> so the RFC 5705 exporter can run after the handshake.
        /// </summary>
        sealed class ExporterTlsClient : DefaultTlsClient
        {
            readonly string _host;
            readonly RemoteCertificateValidationCallback? _validation;
            readonly Action<X509Certificate2?> _onCertificate;
            readonly List<KeyingMaterialRequest> _exports;

            public ExporterTlsClient(TlsCrypto crypto, string host,
                RemoteCertificateValidationCallback? validation, Action<X509Certificate2?> onCertificate,
                List<KeyingMaterialRequest> exports)
                : base(crypto)
            {
                _host = host;
                _validation = validation;
                _onCertificate = onCertificate;
                _exports = exports;
            }

            // TLS 1.2 only — matches the DTLS client's version pinning and keeps interop with ocserv simple.
            protected override ProtocolVersion[] GetSupportedVersions() => ProtocolVersion.TLSv12.Only();

            // Compute every registered RFC 5705 export here, while the master secret is still alive — BouncyCastle clears
            // it as soon as the handshake completes. We do NOT use TlsContext.ExportKeyingMaterial: it refuses a
            // non-extended-master-secret TLS 1.2 session, but ocserv (gnutls) negotiates the OpenConnect CSTP session
            // WITHOUT EMS yet still derives the PSK from it (gnutls's plain TLS 1.2 PRF over the master secret, not the
            // EMS-gated path). So compute the exporter directly — PRF(master_secret, label, client_random + server_random
            // [+ uint16 len + ctx]) — matching gnutls and sidestepping the EMS guard. This is the legacy RFC 5705
            // exporter behaviour AnyConnect interop requires.
            public override void NotifyHandshakeComplete()
            {
                base.NotifyHandshakeComplete();
                if (_exports.Count == 0) return;
                TlsClientContext ctx = m_context ?? throw new InvalidOperationException("TLS context not initialised.");
                SecurityParameters sp = ctx.SecurityParameters;
                TlsSecret? masterSecret = sp.MasterSecret;
                if (masterSecret is null || !masterSecret.IsAlive()) return; // leaves outputs null ⇒ export throws later

                byte[] clientRandom = sp.ClientRandom;
                byte[] serverRandom = sp.ServerRandom;
                int prf = sp.PrfAlgorithm;
                foreach (KeyingMaterialRequest req in _exports)
                {
                    bool hasContext = req.Context.Length > 0;
                    int seedLen = clientRandom.Length + serverRandom.Length + (hasContext ? 2 + req.Context.Length : 0);
                    byte[] seed = new byte[seedLen];
                    int p = 0;
                    Buffer.BlockCopy(clientRandom, 0, seed, p, clientRandom.Length); p += clientRandom.Length;
                    Buffer.BlockCopy(serverRandom, 0, seed, p, serverRandom.Length); p += serverRandom.Length;
                    if (hasContext)
                    {
                        seed[p++] = (byte)(req.Context.Length >> 8);
                        seed[p++] = (byte)req.Context.Length;
                        Buffer.BlockCopy(req.Context, 0, seed, p, req.Context.Length);
                    }
                    req.Output = masterSecret.DeriveUsingPrf(prf, req.Label, seed, req.Length).Extract();
                }
            }

            // Returns a cached export captured at handshake-complete (the master secret is gone by now).
            public bool TryGetCachedExport(string label, ReadOnlySpan<byte> context, int length, out byte[] output)
            {
                foreach (KeyingMaterialRequest req in _exports)
                    if (req.Output is not null && req.Matches(label, context, length))
                    {
                        output = req.Output;
                        return true;
                    }
                output = Array.Empty<byte>();
                return false;
            }

            public override TlsAuthentication GetAuthentication()
                => new CallbackAuthentication(_host, _validation, _onCertificate);

            sealed class CallbackAuthentication : TlsAuthentication
            {
                readonly string _host;
                readonly RemoteCertificateValidationCallback? _validation;
                readonly Action<X509Certificate2?> _onCertificate;

                public CallbackAuthentication(string host, RemoteCertificateValidationCallback? validation,
                    Action<X509Certificate2?> onCertificate)
                {
                    _host = host;
                    _validation = validation;
                    _onCertificate = onCertificate;
                }

                public void NotifyServerCertificate(TlsServerCertificate serverCertificate)
                {
                    X509Certificate2? leaf = null;
                    TlsCertificate[] chain = serverCertificate.Certificate.GetCertificateList();
                    if (chain.Length > 0)
                        leaf = new X509Certificate2(chain[0].GetEncoded());
                    _onCertificate(leaf);

                    // No callback ⇒ accept any (identity is bound by the OpenConnect cookie, not PKI). A callback may
                    // reject; we have no SslPolicyErrors/chain here, so pass the leaf + None and let the callback decide.
                    if (_validation is null) return;
                    bool ok = _validation(_host, leaf, chain: null, System.Net.Security.SslPolicyErrors.None);
                    if (!ok) throw new TlsFatalAlert(AlertDescription.bad_certificate);
                }

                public TlsCredentials? GetClientCredentials(Org.BouncyCastle.Tls.CertificateRequest certificateRequest) => null; // anonymous client
            }
        }
    }
}
