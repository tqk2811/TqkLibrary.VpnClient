using System.Buffers.Binary;

namespace TqkLibrary.VpnClient.Tailscale.Control.Noise
{
    /// <summary>
    /// A duplex <see cref="Stream"/> that runs the ts2021 transport record layer over an inner byte stream (the TCP
    /// connection after the <c>POST /ts2021</c> upgrade). Writes split the plaintext into ≤
    /// <see cref="Ts2021Transport.MaxPlaintextSize"/> records, each sealed with the send transport and framed as
    /// <c>[type=4][len:u16][ciphertext+tag]</c>; reads pull record frames off the inner stream, open them with the
    /// receive transport and hand back the recovered plaintext.
    /// <para>
    /// This is the stream an <see cref="System.Net.Http.SocketsHttpHandler"/> <c>ConnectCallback</c> returns so that
    /// HttpClient speaks HTTP/2 (h2c, prior knowledge) <i>inside</i> the encrypted control channel — Headscale serves
    /// <c>/machine/register</c> and <c>/machine/map</c> over h2c on this channel. The 9-byte <c>EarlyNoise</c> header
    /// the server may send first (magic <c>\xff\xff\xffTS</c> + 4-byte big-endian length + JSON) is consumed by
    /// <see cref="SkipEarlyNoiseAsync"/> before HttpClient sees the stream.
    /// </para>
    /// </summary>
    public sealed class Ts2021NoiseStream : Stream
    {
        static readonly byte[] EarlyNoiseMagic = { 0xFF, 0xFF, 0xFF, (byte)'T', (byte)'S' };
        const int EarlyNoiseHeaderLength = 9; // 5-byte magic + 4-byte length

        readonly Stream _inner;
        readonly Ts2021Transport _send;
        readonly Ts2021Transport _receive;
        readonly byte[] _readHeader = new byte[Ts2021FrameCodec.HeaderLength];

        byte[] _readBuffer = Array.Empty<byte>(); // decrypted plaintext not yet consumed by the reader
        int _readOffset;
        bool _disposed;

        /// <summary>
        /// Wraps <paramref name="inner"/> (the upgraded TCP stream). <paramref name="sendTransport"/> seals outbound
        /// records (client send key); <paramref name="receiveTransport"/> opens inbound records (client receive key).
        /// </summary>
        public Ts2021NoiseStream(Stream inner, Ts2021Transport sendTransport, Ts2021Transport receiveTransport)
        {
            _inner = inner ?? throw new ArgumentNullException(nameof(inner));
            _send = sendTransport ?? throw new ArgumentNullException(nameof(sendTransport));
            _receive = receiveTransport ?? throw new ArgumentNullException(nameof(receiveTransport));
        }

        /// <summary>
        /// Consumes the optional 9-byte <c>EarlyNoise</c> header at the start of the decrypted stream. If the first
        /// 9 decrypted bytes are the magic + length, reads and returns the JSON early-payload bytes; otherwise the
        /// peeked bytes are pushed back so the HTTP/2 layer sees them unchanged, and an empty array is returned. Must be
        /// called once before handing the stream to HttpClient.
        /// </summary>
        public async Task<byte[]> SkipEarlyNoiseAsync(CancellationToken cancellationToken = default)
        {
            byte[] header = new byte[EarlyNoiseHeaderLength];
            await ReadExactDecryptedAsync(header, cancellationToken).ConfigureAwait(false);

            bool isEarly = true;
            for (int i = 0; i < EarlyNoiseMagic.Length; i++)
                if (header[i] != EarlyNoiseMagic[i]) { isEarly = false; break; }

            if (!isEarly)
            {
                // Not an early-payload header: push the 9 bytes back in front of the decrypted buffer.
                Prepend(header);
                return Array.Empty<byte>();
            }

            int length = (int)BinaryPrimitives.ReadUInt32BigEndian(header.AsSpan(EarlyNoiseMagic.Length));
            byte[] payload = new byte[length];
            if (length > 0) await ReadExactDecryptedAsync(payload, cancellationToken).ConfigureAwait(false);
            return payload;
        }

        // ---- Stream surface (HttpClient drives these) ----

        /// <inheritdoc/>
        public override bool CanRead => true;
        /// <inheritdoc/>
        public override bool CanWrite => true;
        /// <inheritdoc/>
        public override bool CanSeek => false;
        /// <inheritdoc/>
        public override long Length => throw new NotSupportedException();
        /// <inheritdoc/>
        public override long Position { get => throw new NotSupportedException(); set => throw new NotSupportedException(); }
        /// <inheritdoc/>
        public override void Flush() { }
        /// <inheritdoc/>
        public override Task FlushAsync(CancellationToken cancellationToken) => Task.CompletedTask;
        /// <inheritdoc/>
        public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();
        /// <inheritdoc/>
        public override void SetLength(long value) => throw new NotSupportedException();

        /// <inheritdoc/>
        public override int Read(byte[] buffer, int offset, int count)
            => ReadAsync(buffer, offset, count, CancellationToken.None).GetAwaiter().GetResult();

        /// <inheritdoc/>
        public override async Task<int> ReadAsync(byte[] buffer, int offset, int count, CancellationToken cancellationToken)
        {
            if (count == 0) return 0;
            if (_readOffset >= _readBuffer.Length)
            {
                byte[]? plaintext = await ReadNextRecordAsync(cancellationToken).ConfigureAwait(false);
                if (plaintext is null) return 0; // EOF
                _readBuffer = plaintext;
                _readOffset = 0;
            }
            int available = _readBuffer.Length - _readOffset;
            int n = Math.Min(available, count);
            Buffer.BlockCopy(_readBuffer, _readOffset, buffer, offset, n);
            _readOffset += n;
            return n;
        }

        /// <inheritdoc/>
        public override void Write(byte[] buffer, int offset, int count)
            => WriteAsync(buffer, offset, count, CancellationToken.None).GetAwaiter().GetResult();

        /// <inheritdoc/>
        public override async Task WriteAsync(byte[] buffer, int offset, int count, CancellationToken cancellationToken)
        {
            int sent = 0;
            while (sent < count)
            {
                int chunk = Math.Min(Ts2021Transport.MaxPlaintextSize, count - sent);
                byte[] sealedRecord = _send.Seal(buffer.AsSpan(offset + sent, chunk));
                byte[] frame = Ts2021FrameCodec.EncodeFrame(Ts2021FrameType.Record, sealedRecord);
                await _inner.WriteAsync(frame, 0, frame.Length, cancellationToken).ConfigureAwait(false);
                sent += chunk;
            }
            await _inner.FlushAsync(cancellationToken).ConfigureAwait(false);
        }

        // ---- record reassembly ----

        // Read one full record frame off the inner stream and return its decrypted plaintext, or null at EOF.
        async Task<byte[]?> ReadNextRecordAsync(CancellationToken cancellationToken)
        {
            if (!await ReadInnerExactAsync(_readHeader, cancellationToken).ConfigureAwait(false)) return null;
            if (!Ts2021FrameCodec.TryDecodeHeader(_readHeader, out Ts2021FrameType type, out int payloadLength))
                throw new IOException("Malformed ts2021 frame header.");
            if (type == Ts2021FrameType.Error)
            {
                byte[] err = new byte[payloadLength];
                await ReadInnerExactAsync(err, cancellationToken).ConfigureAwait(false);
                throw new IOException("ts2021 control error: " + System.Text.Encoding.ASCII.GetString(err));
            }
            if (type != Ts2021FrameType.Record)
                throw new IOException($"Unexpected ts2021 frame type {(byte)type} on the transport channel.");

            byte[] ciphertext = new byte[payloadLength];
            if (!await ReadInnerExactAsync(ciphertext, cancellationToken).ConfigureAwait(false))
                throw new EndOfStreamException("Truncated ts2021 record body.");
            byte[]? plaintext = _receive.Open(ciphertext);
            if (plaintext is null) throw new IOException("ts2021 record failed to authenticate.");
            return plaintext;
        }

        // Decrypted-stream read used by the early-noise probe (pulls whole records, buffers the remainder).
        async Task ReadExactDecryptedAsync(byte[] destination, CancellationToken cancellationToken)
        {
            int read = 0;
            while (read < destination.Length)
            {
                if (_readOffset >= _readBuffer.Length)
                {
                    byte[]? plaintext = await ReadNextRecordAsync(cancellationToken).ConfigureAwait(false);
                    if (plaintext is null) throw new EndOfStreamException("ts2021 stream closed before the early-noise header.");
                    _readBuffer = plaintext;
                    _readOffset = 0;
                }
                int n = Math.Min(_readBuffer.Length - _readOffset, destination.Length - read);
                Buffer.BlockCopy(_readBuffer, _readOffset, destination, read, n);
                _readOffset += n;
                read += n;
            }
        }

        // Prepend leftover decrypted bytes ahead of the current read buffer (used to push back the early-noise probe).
        void Prepend(byte[] bytes)
        {
            int remaining = _readBuffer.Length - _readOffset;
            byte[] merged = new byte[bytes.Length + remaining];
            Buffer.BlockCopy(bytes, 0, merged, 0, bytes.Length);
            if (remaining > 0) Buffer.BlockCopy(_readBuffer, _readOffset, merged, bytes.Length, remaining);
            _readBuffer = merged;
            _readOffset = 0;
        }

        async Task<bool> ReadInnerExactAsync(byte[] destination, CancellationToken cancellationToken)
        {
            int read = 0;
            while (read < destination.Length)
            {
                int n = await _inner.ReadAsync(destination, read, destination.Length - read, cancellationToken).ConfigureAwait(false);
                if (n == 0) return read != 0 ? throw new EndOfStreamException("Truncated ts2021 frame.") : false;
                read += n;
            }
            return true;
        }

        /// <inheritdoc/>
        protected override void Dispose(bool disposing)
        {
            if (!_disposed)
            {
                _disposed = true;
                if (disposing) _inner.Dispose();
            }
            base.Dispose(disposing);
        }
    }
}
