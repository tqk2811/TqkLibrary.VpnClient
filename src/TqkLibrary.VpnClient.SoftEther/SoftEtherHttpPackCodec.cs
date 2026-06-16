using System.Buffers.Binary;
using System.Text;

namespace TqkLibrary.VpnClient.SoftEther
{
    /// <summary>
    /// Pure codec for carrying a <see cref="Pack"/> inside one HTTP message over the SoftEther control channel. After
    /// the watermark POST, SoftEther exchanges every control PACK as the body of an HTTP <c>POST /vpnsvc/vpn.cgi</c>
    /// (client → server) / <c>200 OK</c> (server → client); the body is the PACK bytes prefixed by a big-endian
    /// <c>uint32</c> length. Re-implemented from the protocol behavior (spec doc <c>07</c>) — not copied from the GPL
    /// source. No I/O: this builds/parses byte buffers so it is fully offline-testable; the streaming reader lives in
    /// <see cref="SoftEtherHandshake"/>.
    /// </summary>
    public static class SoftEtherHttpPackCodec
    {
        const string ContentType = "application/octet-stream";

        /// <summary>
        /// Frames a PACK as the body: a big-endian <c>uint32</c> length prefix followed by the PACK bytes. This is the
        /// HTTP entity body for both directions.
        /// </summary>
        public static byte[] FrameBody(Pack pack)
        {
            if (pack is null) throw new ArgumentNullException(nameof(pack));
            byte[] packBytes = pack.ToBytes();
            var body = new byte[4 + packBytes.Length];
            BinaryPrimitives.WriteUInt32BigEndian(body, (uint)packBytes.Length);
            Buffer.BlockCopy(packBytes, 0, body, 4, packBytes.Length);
            return body;
        }

        /// <summary>Parses a framed body (<c>uint32</c> length ‖ PACK bytes) back into a <see cref="Pack"/>.</summary>
        public static Pack ParseBody(ReadOnlySpan<byte> body)
        {
            if (body.Length < 4)
                throw new FormatException("SoftEther HTTP body too short for a length prefix.");
            uint length = BinaryPrimitives.ReadUInt32BigEndian(body);
            if (length > body.Length - 4)
                throw new FormatException($"SoftEther HTTP body declares {length} PACK bytes but only {body.Length - 4} follow.");
            return Pack.Parse(body.Slice(4, (int)length));
        }

        /// <summary>
        /// Builds the bytes of a client <c>POST /vpnsvc/vpn.cgi HTTP/1.1</c> request carrying <paramref name="pack"/> in
        /// its body. ASCII headers (<c>Host</c>, <c>Content-Type</c>, <c>Content-Length</c>, <c>Connection: Keep-Alive</c>),
        /// a blank line, then the framed body.
        /// </summary>
        public static byte[] BuildPostRequest(string host, Pack pack)
        {
            if (string.IsNullOrEmpty(host)) throw new ArgumentException("host must be non-empty.", nameof(host));
            byte[] body = FrameBody(pack);

            var head = new StringBuilder();
            head.Append("POST ").Append(SoftEtherProtocol.VpnTarget).Append(" HTTP/1.1\r\n");
            head.Append("Host: ").Append(host).Append("\r\n");
            head.Append("Content-Type: ").Append(ContentType).Append("\r\n");
            head.Append("Content-Length: ").Append(body.Length).Append("\r\n");
            head.Append("Connection: Keep-Alive\r\n");
            head.Append("\r\n");
            return ConcatHeadBody(Encoding.ASCII.GetBytes(head.ToString()), body);
        }

        /// <summary>
        /// Builds the bytes of a server <c>HTTP/1.1 200 OK</c> response carrying <paramref name="pack"/> in its body
        /// (used by the offline stub server in tests).
        /// </summary>
        public static byte[] BuildOkResponse(Pack pack)
        {
            byte[] body = FrameBody(pack);
            var head = new StringBuilder();
            head.Append("HTTP/1.1 200 OK\r\n");
            head.Append("Content-Type: ").Append(ContentType).Append("\r\n");
            head.Append("Content-Length: ").Append(body.Length).Append("\r\n");
            head.Append("Connection: Keep-Alive\r\n");
            head.Append("\r\n");
            return ConcatHeadBody(Encoding.ASCII.GetBytes(head.ToString()), body);
        }

        static byte[] ConcatHeadBody(byte[] head, byte[] body)
        {
            var buffer = new byte[head.Length + body.Length];
            Buffer.BlockCopy(head, 0, buffer, 0, head.Length);
            Buffer.BlockCopy(body, 0, buffer, head.Length, body.Length);
            return buffer;
        }
    }
}
