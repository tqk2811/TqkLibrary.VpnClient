using System.Collections.Generic;
using System.IO;
using System.Text;
using TqkLibrary.VpnClient.Abstractions.Transport.Interfaces;
using TqkLibrary.VpnClient.Transport.Tcp;
using TqkLibrary.VpnClient.Transport.Tls;

namespace TqkLibrary.VpnClient.Transport.WebSocket
{
    /// <summary>
    /// A client-side WebSocket (RFC 6455) byte stream: an <see cref="IByteStreamTransport"/> that wraps an inner
    /// <see cref="IByteStreamTransport"/> (plain TCP for <c>ws://</c>, a TLS byte stream for <c>wss://</c>), performs the
    /// §4 HTTP Upgrade handshake on connect, then tunnels application bytes as §5 <b>binary</b> frames. Because the
    /// framing is hand-rolled (not <c>System.Net.WebSockets.ClientWebSocket</c>), it rides any inner transport and behaves
    /// identically on <c>netstandard2.0</c> and <c>net8.0</c> — the foundation for wstunnel-style anti-DPI wrappers that
    /// make a tunnel "look like WebSocket/HTTPS".
    /// <para>
    /// Outbound writes are masked (§5.3, mandatory for a client); inbound frames are un-masked by the codec, fragmented
    /// data messages (§5.4) are reassembled, and control frames are handled inline: a <b>ping</b> is answered with a
    /// <b>pong</b> carrying the same payload, a <b>pong</b> is ignored, and a <b>close</b> makes <see cref="ReadAsync"/>
    /// return 0 (end of stream). A single <see cref="SemaphoreSlim"/> serialises all inner writes so an auto-pong from the
    /// read path never interleaves on the wire with an application write.
    /// </para>
    /// </summary>
    public sealed class WebSocketByteStream : IByteStreamTransport
    {
        const int MaxHandshakeResponseBytes = 16 * 1024;

        readonly IByteStreamTransport _inner;
        readonly string _host;
        readonly string _path;
        readonly string? _subProtocol;
        readonly IWebSocketRandom _random;
        readonly bool _sendCloseOnDispose;

        readonly Rfc6455FrameReassembler _reassembler = new();
        readonly byte[] _readBuffer = new byte[8192];
        readonly SemaphoreSlim _writeLock = new(1, 1);
        readonly List<byte> _fragmentBuffer = new();

        bool _fragmentInProgress;
        ReadOnlyMemory<byte> _pendingData = ReadOnlyMemory<byte>.Empty;
        bool _connected;
        bool _closed;

        /// <summary>
        /// Wraps an existing <paramref name="inner"/> byte stream (injectable for a plain <see cref="TcpByteStream"/>, a
        /// <see cref="TlsByteStream"/>, or an in-memory loopback in tests). <paramref name="host"/> is sent as the HTTP
        /// <c>Host</c> header; <paramref name="path"/> (default <c>"/"</c>) is the request resource; optional
        /// <paramref name="subProtocol"/> is offered via <c>Sec-WebSocket-Protocol</c>. <paramref name="random"/> supplies
        /// the handshake key and mask keys (default <see cref="CryptoWebSocketRandom.Default"/>); when
        /// <paramref name="sendCloseOnDispose"/> is <c>true</c> a best-effort close frame is sent on
        /// <see cref="DisposeAsync"/>. Ownership of <paramref name="inner"/> transfers here.
        /// </summary>
        public WebSocketByteStream(IByteStreamTransport inner, string host, string path = "/", string? subProtocol = null,
            IWebSocketRandom? random = null, bool sendCloseOnDispose = true)
        {
            _inner = inner ?? throw new ArgumentNullException(nameof(inner));
            _host = host ?? throw new ArgumentNullException(nameof(host));
            _path = string.IsNullOrEmpty(path) ? "/" : path;
            _subProtocol = subProtocol;
            _random = random ?? CryptoWebSocketRandom.Default;
            _sendCloseOnDispose = sendCloseOnDispose;
        }

        /// <summary>
        /// Convenience constructor that builds its own inner byte stream to <paramref name="host"/>:<paramref name="port"/>:
        /// a <see cref="TlsByteStream"/> when <paramref name="useTls"/> is <c>true</c> (<c>wss://</c>), otherwise a plain
        /// <see cref="TcpByteStream"/> (<c>ws://</c>).
        /// </summary>
        public WebSocketByteStream(string host, int port, bool useTls, string path = "/", string? subProtocol = null,
            IWebSocketRandom? random = null)
            : this(useTls ? new TlsByteStream(host, port) : (IByteStreamTransport)new TcpByteStream(host, port),
                  host, path, subProtocol, random)
        {
        }

        /// <inheritdoc/>
        public async ValueTask ConnectAsync(CancellationToken cancellationToken = default)
        {
            await _inner.ConnectAsync(cancellationToken).ConfigureAwait(false);

            // §4.1: a fresh random 16-byte nonce, base64-encoded, as Sec-WebSocket-Key.
            string key = Convert.ToBase64String(_random.NextBytes(16));
            byte[] request = WebSocketHandshake.BuildClientRequest(_host, _path, key, _subProtocol);
            await _inner.WriteAsync(request, cancellationToken).ConfigureAwait(false);

            string expectedAccept = WebSocketHandshake.ComputeAccept(key);

            // Read the HTTP response headers until the CRLFCRLF terminator (§4.2.2).
            var received = new List<byte>();
            int headerEnd;
            while ((headerEnd = IndexOfHeaderTerminator(received)) < 0)
            {
                int read = await _inner.ReadAsync(_readBuffer, cancellationToken).ConfigureAwait(false);
                if (read == 0)
                    throw new IOException("The WebSocket handshake connection closed before a complete HTTP response arrived.");
                for (int i = 0; i < read; i++) received.Add(_readBuffer[i]);
                if (received.Count > MaxHandshakeResponseBytes)
                    throw new IOException("The WebSocket handshake HTTP response exceeded the maximum size without terminating.");
            }

            int headerLength = headerEnd + 4; // include the CRLFCRLF
            string headerText = Encoding.ASCII.GetString(received.GetRange(0, headerLength).ToArray());
            if (!WebSocketHandshake.TryParseResponse(headerText, expectedAccept))
                throw new IOException("The WebSocket server did not complete a valid 101 handshake (missing/mismatched Sec-WebSocket-Accept).");

            // Any bytes past the header already belong to the framed stream (a server may pipeline a frame right after 101).
            if (received.Count > headerLength)
                _reassembler.Append(received.GetRange(headerLength, received.Count - headerLength).ToArray());

            _connected = true;
        }

        /// <inheritdoc/>
        public async ValueTask WriteAsync(ReadOnlyMemory<byte> buffer, CancellationToken cancellationToken = default)
        {
            // §5.2/§5.6: one masked binary frame per write (FIN = 1).
            byte[] maskKey = _random.NextBytes(Rfc6455Frame.MaskingKeyLength);
            byte[] frame = Rfc6455Frame.EncodeClientFrame(Rfc6455Opcode.Binary, buffer.Span, maskKey);
            await SendRawAsync(frame, cancellationToken).ConfigureAwait(false);
        }

        /// <inheritdoc/>
        public async ValueTask<int> ReadAsync(Memory<byte> buffer, CancellationToken cancellationToken = default)
        {
            while (true)
            {
                if (!_pendingData.IsEmpty)
                {
                    int n = Math.Min(buffer.Length, _pendingData.Length);
                    _pendingData.Slice(0, n).CopyTo(buffer);
                    _pendingData = _pendingData.Slice(n);
                    return n;
                }
                if (_closed) return 0;

                (bool ok, bool fin, Rfc6455Opcode opcode, byte[] payload) = await ReadFrameAsync(cancellationToken).ConfigureAwait(false);
                if (!ok)
                {
                    _closed = true;
                    return 0; // inner byte stream closed ⇒ end of stream
                }

                switch (opcode)
                {
                    case Rfc6455Opcode.Binary:
                    case Rfc6455Opcode.Text:
                        if (_fragmentInProgress)
                            throw new InvalidOperationException("RFC 6455: a new data frame arrived while a fragmented message was in progress.");
                        if (fin)
                        {
                            _pendingData = payload; // delivered on the next loop iteration
                        }
                        else
                        {
                            _fragmentBuffer.Clear();
                            _fragmentBuffer.AddRange(payload);
                            _fragmentInProgress = true;
                        }
                        break;

                    case Rfc6455Opcode.Continuation:
                        if (!_fragmentInProgress)
                            throw new InvalidOperationException("RFC 6455: a continuation frame arrived with no fragmented message in progress.");
                        _fragmentBuffer.AddRange(payload);
                        if (fin)
                        {
                            _pendingData = _fragmentBuffer.ToArray();
                            _fragmentBuffer.Clear();
                            _fragmentInProgress = false;
                        }
                        break;

                    case Rfc6455Opcode.Ping:
                        // §5.5.2: answer with a pong carrying the same application data.
                        await SendControlAsync(Rfc6455Opcode.Pong, payload, cancellationToken).ConfigureAwait(false);
                        break;

                    case Rfc6455Opcode.Pong:
                        break; // §5.5.3: unsolicited pong ⇒ ignore

                    case Rfc6455Opcode.Close:
                        // §5.5.1: echo a close (best-effort) and report end of stream.
                        _closed = true;
                        await TrySendCloseAsync(cancellationToken).ConfigureAwait(false);
                        return 0;

                    default:
                        throw new InvalidOperationException($"RFC 6455: unsupported frame opcode 0x{(byte)opcode:X}.");
                }
            }
        }

        // Reads the next whole frame, pumping the inner stream as needed. ok = false when the inner stream closes.
        async ValueTask<(bool ok, bool fin, Rfc6455Opcode opcode, byte[] payload)> ReadFrameAsync(CancellationToken cancellationToken)
        {
            bool fin;
            Rfc6455Opcode opcode;
            byte[] payload;
            while (!_reassembler.TryReadFrame(out fin, out opcode, out payload))
            {
                int read = await _inner.ReadAsync(_readBuffer, cancellationToken).ConfigureAwait(false);
                if (read == 0) return (false, false, default, Array.Empty<byte>());
                _reassembler.Append(_readBuffer.AsSpan(0, read));
            }
            return (true, fin, opcode, payload);
        }

        async ValueTask SendControlAsync(Rfc6455Opcode opcode, byte[] payload, CancellationToken cancellationToken)
        {
            byte[] maskKey = _random.NextBytes(Rfc6455Frame.MaskingKeyLength);
            byte[] frame = Rfc6455Frame.EncodeClientFrame(opcode, payload, maskKey);
            await SendRawAsync(frame, cancellationToken).ConfigureAwait(false);
        }

        async ValueTask TrySendCloseAsync(CancellationToken cancellationToken)
        {
            try { await SendControlAsync(Rfc6455Opcode.Close, Array.Empty<byte>(), cancellationToken).ConfigureAwait(false); }
            catch { /* best-effort: the peer may already be gone */ }
        }

        async ValueTask SendRawAsync(byte[] frame, CancellationToken cancellationToken)
        {
            await _writeLock.WaitAsync(cancellationToken).ConfigureAwait(false);
            try { await _inner.WriteAsync(frame, cancellationToken).ConfigureAwait(false); }
            finally { _writeLock.Release(); }
        }

        static int IndexOfHeaderTerminator(List<byte> data)
        {
            for (int i = 0; i + 3 < data.Count; i++)
            {
                if (data[i] == 0x0D && data[i + 1] == 0x0A && data[i + 2] == 0x0D && data[i + 3] == 0x0A)
                    return i;
            }
            return -1;
        }

        /// <inheritdoc/>
        public async ValueTask DisposeAsync()
        {
            if (_sendCloseOnDispose && _connected && !_closed)
            {
                _closed = true;
                await TrySendCloseAsync(CancellationToken.None).ConfigureAwait(false);
            }
            await _inner.DisposeAsync().ConfigureAwait(false);
            _writeLock.Dispose();
        }
    }
}
