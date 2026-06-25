namespace TqkLibrary.VpnClient.OpenVpn.Tests
{
    /// <summary>
    /// The server side's in-memory duplex stream for a BouncyCastle <see cref="Org.BouncyCastle.Tls.TlsServerProtocol"/>
    /// over the OpenVPN reliability layer: writes go out via <see cref="Send"/> (the harness fragments + sends them as
    /// control packets), reads return the in-order payloads the harness delivers from the client. Single reader (the BC
    /// protocol thread). Test-only.
    /// </summary>
    sealed class ServerBridgeStream : Stream
    {
        readonly object _gate = new();
        readonly Queue<byte[]> _inbound = new();
        byte[]? _partial;
        int _partialPos;
        bool _completed;
        TaskCompletionSource<bool>? _waiter;

        public Action<byte[]>? Send;

        public void EnqueueInbound(byte[] data)
        {
            TaskCompletionSource<bool>? signal;
            lock (_gate) { _inbound.Enqueue(data); signal = _waiter; _waiter = null; }
            signal?.TrySetResult(true);
        }

        public void CompleteInbound()
        {
            TaskCompletionSource<bool>? signal;
            lock (_gate) { _completed = true; signal = _waiter; _waiter = null; }
            signal?.TrySetResult(true);
        }

        int ReadCore(byte[] buffer, int offset, int count)
        {
            while (true)
            {
                TaskCompletionSource<bool> tcs;
                lock (_gate)
                {
                    if (_partial is null && _inbound.Count > 0) { _partial = _inbound.Dequeue(); _partialPos = 0; }
                    if (_partial is not null)
                    {
                        int n = Math.Min(count, _partial.Length - _partialPos);
                        Array.Copy(_partial, _partialPos, buffer, offset, n);
                        _partialPos += n;
                        if (_partialPos >= _partial.Length) _partial = null;
                        return n;
                    }
                    if (_completed) return 0;
                    _waiter ??= new TaskCompletionSource<bool>(TaskCreationOptions.RunContinuationsAsynchronously);
                    tcs = _waiter;
                }
                tcs.Task.GetAwaiter().GetResult();
            }
        }

        public override bool CanRead => true;
        public override bool CanWrite => true;
        public override bool CanSeek => false;
        public override void Flush() { }
        public override int Read(byte[] buffer, int offset, int count) => ReadCore(buffer, offset, count);
        public override void Write(byte[] buffer, int offset, int count)
        {
            byte[] c = new byte[count];
            Array.Copy(buffer, offset, c, 0, count);
            Send?.Invoke(c);
        }
        public override long Length => throw new NotSupportedException();
        public override long Position { get => throw new NotSupportedException(); set => throw new NotSupportedException(); }
        public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();
        public override void SetLength(long value) => throw new NotSupportedException();
    }
}
