using System.Buffers;

namespace TqkLibrary.VpnClient.OpenVpn
{
    /// <summary>
    /// The in-memory <see cref="Stream"/> that an <see cref="System.Net.Security.SslStream"/> runs on so TLS flows
    /// <em>inside</em> the OpenVPN control channel: writes from TLS are fragmented + sent reliably (the owner's write
    /// callback), and reads return the in-order payloads the owner delivers from the receive window. There is a single
    /// reader (the SslStream) so the inbound path is serialised; the owning <see cref="OpenVpnControlChannel"/> feeds it
    /// from its receive loop via <see cref="EnqueueInbound"/>.
    /// <para>
    /// Both the async and the synchronous surface are real: the blocking BouncyCastle <c>TlsClientProtocol</c> (tls-ekm)
    /// drives <see cref="Read(byte[],int,int)"/>/<see cref="Write(byte[],int,int)"/> on its own thread. A sync read
    /// parks on <see cref="Monitor.Wait(object)"/> over the same inbound queue the async read awaits. A sync
    /// <c>Write</c> calls the owner's SYNC sender on the caller's thread (the sender itself blocks on the send window),
    /// while <c>WriteAsync</c> awaits the async sender; one gate (<see cref="SemaphoreSlim"/>, <c>Wait</c> /
    /// <c>WaitAsync</c>) keeps concurrent writers from interleaving records. The first send failure faults the stream
    /// (later writes throw <see cref="IOException"/>); an async write cancelled after it started sending faults it too,
    /// since a partial record may already be on the wire.
    /// </para>
    /// </summary>
    internal sealed class OpenVpnTlsBridgeStream : Stream
    {
        /// <summary>Synchronous send callback (a delegate type because <see cref="ReadOnlySpan{T}"/> can't be a generic argument).</summary>
        public delegate void SendTlsSync(ReadOnlySpan<byte> buffer);

        readonly SendTlsSync _writeTlsSync;
        readonly Func<ReadOnlyMemory<byte>, CancellationToken, Task> _writeTlsAsync;
        readonly object _gate = new();
        readonly Queue<byte[]> _inbound = new();
        byte[]? _partial;
        int _partialPos;
        bool _completed;
        TaskCompletionSource<bool>? _waiter;

        // One writer at a time (sync or async) so TLS records never interleave. Never disposed: see ReleaseGate.
        readonly SemaphoreSlim _writeGate = new(1, 1);
        // Not disposed on purpose: writers racing Dispose may still observe its token.
        readonly CancellationTokenSource _disposeCts = new();
        Exception? _writeFault; // first failure of a send; later writes fail fast with it
        int _disposed;

        public OpenVpnTlsBridgeStream(SendTlsSync writeTlsSync, Func<ReadOnlyMemory<byte>, CancellationToken, Task> writeTlsAsync)
        {
            _writeTlsSync = writeTlsSync ?? throw new ArgumentNullException(nameof(writeTlsSync));
            _writeTlsAsync = writeTlsAsync ?? throw new ArgumentNullException(nameof(writeTlsAsync));
        }

        /// <summary>Hands an in-order TLS record fragment to the reader (the SslStream). Empty inputs are ignored.</summary>
        public void EnqueueInbound(byte[] data)
        {
            if (data.Length == 0) return;
            TaskCompletionSource<bool>? toSignal;
            lock (_gate)
            {
                _inbound.Enqueue(data);
                toSignal = _waiter;
                _waiter = null;
                Monitor.PulseAll(_gate); // wake a blocked sync Read
            }
            toSignal?.TrySetResult(true);
        }

        /// <summary>Signals end-of-stream so a pending/next read returns 0 instead of blocking forever.</summary>
        public void CompleteInbound()
        {
            TaskCompletionSource<bool>? toSignal;
            lock (_gate)
            {
                _completed = true;
                toSignal = _waiter;
                _waiter = null;
                Monitor.PulseAll(_gate); // wake a blocked sync Read
            }
            toSignal?.TrySetResult(true);
        }

        // Copies buffered inbound bytes into buffer; false when nothing is buffered. Caller holds _gate.
        bool TryReadLocked(byte[] buffer, int offset, int count, out int read)
        {
            if (_partial is null && _inbound.Count > 0)
            {
                _partial = _inbound.Dequeue();
                _partialPos = 0;
            }
            if (_partial is null) { read = 0; return false; }
            read = Math.Min(count, _partial.Length - _partialPos);
            Array.Copy(_partial, _partialPos, buffer, offset, read);
            _partialPos += read;
            if (_partialPos >= _partial.Length) _partial = null;
            return true;
        }

        async Task<int> ReadCoreAsync(byte[] buffer, int offset, int count, CancellationToken cancellationToken)
        {
            while (true)
            {
                TaskCompletionSource<bool> tcs;
                lock (_gate)
                {
                    if (TryReadLocked(buffer, offset, count, out int n)) return n;
                    if (_completed) return 0;
                    _waiter ??= new TaskCompletionSource<bool>(TaskCreationOptions.RunContinuationsAsynchronously);
                    tcs = _waiter;
                }
                using (cancellationToken.Register(() => tcs.TrySetCanceled()))
                    await tcs.Task.ConfigureAwait(false);
            }
        }

        public override bool CanRead => true;
        public override bool CanWrite => true;
        public override bool CanSeek => false;

        public override void Flush() { }
        public override Task FlushAsync(CancellationToken cancellationToken) => Task.CompletedTask;

        public override int Read(byte[] buffer, int offset, int count)
        {
            // Real blocking read: wait on the gate's monitor; EnqueueInbound/CompleteInbound/Dispose PulseAll it.
            lock (_gate)
            {
                while (true)
                {
                    if (TryReadLocked(buffer, offset, count, out int n)) return n;
                    if (_completed) return 0;
                    Monitor.Wait(_gate);
                }
            }
        }

        public override Task<int> ReadAsync(byte[] buffer, int offset, int count, CancellationToken cancellationToken)
            => ReadCoreAsync(buffer, offset, count, cancellationToken);

        public override void Write(byte[] buffer, int offset, int count)
        {
            // Real sync path: take the gate (a blocking wait, not a task) and call the SYNC sender on this very thread;
            // it blocks on the send window (backpressure) and its exception surfaces on this call.
            ThrowIfDisposed();
            try { _writeGate.Wait(_disposeCts.Token); }
            catch (OperationCanceledException) { throw new ObjectDisposedException(nameof(OpenVpnTlsBridgeStream)); }
            try
            {
                ThrowIfFaulted();
                try { _writeTlsSync(new ReadOnlySpan<byte>(buffer, offset, count)); }
                catch (Exception ex) { RecordFault(ex); throw; }
            }
            finally { ReleaseGate(); }
        }

        public override Task WriteAsync(byte[] buffer, int offset, int count, CancellationToken cancellationToken)
            => WriteCoreAsync(new ReadOnlyMemory<byte>(buffer, offset, count), cancellationToken);

#if NET5_0_OR_GREATER
        public override async ValueTask<int> ReadAsync(Memory<byte> buffer, CancellationToken cancellationToken = default)
        {
            byte[] tmp = ArrayPool<byte>.Shared.Rent(buffer.Length);
            try
            {
                int n = await ReadCoreAsync(tmp, 0, buffer.Length, cancellationToken).ConfigureAwait(false);
                new ReadOnlyMemory<byte>(tmp, 0, n).CopyTo(buffer);
                return n;
            }
            finally { ArrayPool<byte>.Shared.Return(tmp); }
        }

        public override ValueTask WriteAsync(ReadOnlyMemory<byte> buffer, CancellationToken cancellationToken = default)
            => new ValueTask(WriteCoreAsync(buffer, cancellationToken));
#endif

        async Task WriteCoreAsync(ReadOnlyMemory<byte> buffer, CancellationToken cancellationToken)
        {
            ThrowIfDisposed();
            cancellationToken.ThrowIfCancellationRequested();
            // Cancelled while queued on the gate ⇒ nothing was sent: plain OperationCanceledException, no fault.
            using (var linked = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken, _disposeCts.Token))
            {
                try { await _writeGate.WaitAsync(linked.Token).ConfigureAwait(false); }
                catch (OperationCanceledException) when (_disposeCts.IsCancellationRequested && !cancellationToken.IsCancellationRequested)
                {
                    throw new ObjectDisposedException(nameof(OpenVpnTlsBridgeStream));
                }
            }
            try
            {
                ThrowIfFaulted();
                cancellationToken.ThrowIfCancellationRequested();
                // Once the sender started, a cancel may leave a partial TLS record on the wire: the stream is corrupt, so
                // ANY failure here (cancellation included) faults it.
                try { await _writeTlsAsync(buffer, cancellationToken).ConfigureAwait(false); }
                catch (Exception ex) { RecordFault(ex); throw; }
            }
            finally { ReleaseGate(); }
        }

        void ThrowIfDisposed()
        {
            if (Volatile.Read(ref _disposed) != 0) throw new ObjectDisposedException(nameof(OpenVpnTlsBridgeStream));
        }

        void ThrowIfFaulted()
        {
            Exception? fault = Volatile.Read(ref _writeFault);
            if (fault != null) throw new IOException("An earlier write on the OpenVPN TLS bridge failed.", fault);
        }

        void RecordFault(Exception ex) => Interlocked.CompareExchange(ref _writeFault, ex, null);

        // The gate is never disposed (a writer may finish after Dispose), so releasing it is always safe.
        void ReleaseGate() => _writeGate.Release();

        protected override void Dispose(bool disposing)
        {
            if (Interlocked.Exchange(ref _disposed, 1) == 0)
            {
                try { _disposeCts.Cancel(); } catch { } // writers queued on the gate throw ObjectDisposedException
                CompleteInbound(); // a blocked Read (sync or async) returns 0 instead of hanging
            }
            base.Dispose(disposing);
        }

        public override long Length => throw new NotSupportedException();
        public override long Position { get => throw new NotSupportedException(); set => throw new NotSupportedException(); }
        public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();
        public override void SetLength(long value) => throw new NotSupportedException();
    }
}
