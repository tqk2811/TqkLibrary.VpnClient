using System.Text;

namespace TqkLibrary.VpnClient.SoftEther
{
    /// <summary>
    /// Builds the SoftEther "watermark" HTTP POST that opens an SSL-VPN session — the very first thing a client sends
    /// over the established TLS byte stream (transport reused via <c>IByteStreamTransport</c> / F.1). Re-implemented
    /// from the protocol behavior (spec doc <c>07</c>): a <c>POST /vpnsvc/connect.cgi HTTP/1.1</c> request whose body
    /// is a fixed watermark signature blob followed by random padding.
    /// <para>
    /// The genuine watermark blob lives in the GPL <c>src/Cedar/Watermark.c</c> and <b>must not be copied</b>. This
    /// type therefore exposes the watermark as a caller-supplied (or deterministically generated) blob: the
    /// <see cref="Signature"/> bytes are reproduced byte-exact from a documented constant so an offline stub server can
    /// validate them, while interop with a real server is achieved by handing the real blob in via
    /// <see cref="WithSignature"/>. The request <i>framing</i> (request line, headers, body length) is byte-exact and
    /// protocol-correct regardless.
    /// </para>
    /// Pure builder: no socket I/O. <see cref="BuildRequest"/> returns the exact bytes to write to the stream.
    /// </summary>
    public sealed class SoftEtherWatermark
    {
        /// <summary>
        /// The default placeholder watermark signature: a fixed, byte-exact, reproducible blob (an ASCII tag plus a
        /// keystream derived from it) used by offline tests. <b>Not</b> the genuine GPL blob — supply that via
        /// <see cref="WithSignature"/> when talking to a real server.
        /// </summary>
        public static readonly byte[] DefaultSignature = BuildDefaultSignature();

        readonly byte[] _signature;
        readonly byte[] _padding;

        /// <summary>The watermark signature blob written at the start of the POST body.</summary>
        public IReadOnlyList<byte> Signature => _signature;

        /// <summary>The random padding appended after the signature.</summary>
        public IReadOnlyList<byte> Padding => _padding;

        /// <summary>The total POST body length (signature + padding) in bytes.</summary>
        public int BodyLength => _signature.Length + _padding.Length;

        /// <summary>Creates a watermark with the <see cref="DefaultSignature"/> and no padding.</summary>
        public SoftEtherWatermark() : this(DefaultSignature, Array.Empty<byte>()) { }

        /// <summary>Creates a watermark with an explicit signature and padding (both referenced, not copied).</summary>
        public SoftEtherWatermark(byte[] signature, byte[] padding)
        {
            _signature = signature ?? throw new ArgumentNullException(nameof(signature));
            _padding = padding ?? throw new ArgumentNullException(nameof(padding));
        }

        /// <summary>Returns a copy of this watermark using a different signature blob (e.g. the genuine server blob).</summary>
        public SoftEtherWatermark WithSignature(byte[] signature) => new(signature, _padding);

        /// <summary>
        /// Returns a copy of this watermark with <paramref name="length"/> bytes of random padding appended after the
        /// signature, drawn from <paramref name="random"/> (a caller-supplied RNG; injectable so tests are deterministic).
        /// </summary>
        public SoftEtherWatermark WithRandomPadding(int length, Random random)
        {
            if (length < 0) throw new ArgumentOutOfRangeException(nameof(length));
            if (random is null) throw new ArgumentNullException(nameof(random));
            var pad = new byte[length];
            random.NextBytes(pad);
            return new SoftEtherWatermark(_signature, pad);
        }

        /// <summary>
        /// Builds the exact bytes of the watermark <c>POST /vpnsvc/connect.cgi HTTP/1.1</c> request: the request line,
        /// the headers (<c>Host</c>, <c>Content-Type: image/jpeg</c>, <c>Content-Length</c>, <c>Connection: Keep-Alive</c>),
        /// a blank line, then the body (signature ‖ padding). The headers are ASCII; the body is raw bytes.
        /// </summary>
        /// <param name="host">The value of the <c>Host:</c> header (the server hostname).</param>
        public byte[] BuildRequest(string host)
        {
            if (string.IsNullOrEmpty(host)) throw new ArgumentException("host must be non-empty.", nameof(host));

            var head = new StringBuilder();
            head.Append("POST ").Append(SoftEtherProtocol.ConnectTarget).Append(" HTTP/1.1\r\n");
            head.Append("Host: ").Append(host).Append("\r\n");
            head.Append("Content-Type: image/jpeg\r\n");
            head.Append("Content-Length: ").Append(BodyLength).Append("\r\n");
            head.Append("Connection: Keep-Alive\r\n");
            head.Append("\r\n");

            byte[] headBytes = Encoding.ASCII.GetBytes(head.ToString());
            var request = new byte[headBytes.Length + BodyLength];
            Buffer.BlockCopy(headBytes, 0, request, 0, headBytes.Length);
            Buffer.BlockCopy(_signature, 0, request, headBytes.Length, _signature.Length);
            Buffer.BlockCopy(_padding, 0, request, headBytes.Length + _signature.Length, _padding.Length);
            return request;
        }

        /// <summary>
        /// True if <paramref name="body"/> begins with this watermark's signature — the check a server does on the
        /// received POST body (an offline stub uses this to validate the client's watermark byte-exactly).
        /// </summary>
        public bool Matches(ReadOnlySpan<byte> body)
        {
            if (body.Length < _signature.Length) return false;
            return body.Slice(0, _signature.Length).SequenceEqual(_signature);
        }

        static byte[] BuildDefaultSignature()
        {
            // Deterministic placeholder blob: a fixed ASCII tag followed by a keystream folded from it. Byte-exact and
            // reproducible (so a stub server can match it) yet carries no bytes from the GPL Watermark.c.
            byte[] tag = Encoding.ASCII.GetBytes("SE-VPN4-WATERMARK");
            var blob = new byte[128];
            Buffer.BlockCopy(tag, 0, blob, 0, tag.Length);
            byte acc = 0x5A;
            for (int i = tag.Length; i < blob.Length; i++)
            {
                acc = (byte)((acc * 31 + i * 7 + tag[i % tag.Length]) & 0xFF);
                blob[i] = acc;
            }
            return blob;
        }
    }
}
