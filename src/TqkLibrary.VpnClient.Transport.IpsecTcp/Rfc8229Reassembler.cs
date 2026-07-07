using System.Collections.Generic;

namespace TqkLibrary.VpnClient.Transport.IpsecTcp
{
    /// <summary>
    /// Stateful receive-side reassembler for RFC 8229 framing: buffers received byte-stream chunks and hands back whole
    /// IKE/ESP messages as their Length-delimited boundaries complete, across arbitrary read splits (a chunk may cut
    /// through the Length field, through a message, or carry several messages). Mirrors the streaming pattern of
    /// <c>PptpControlCodec</c> / <c>CstpFraming</c> without copying them.
    /// <para>
    /// <b>Direction matters (RFC 8229 §3).</b> Only the initiator (client) sends the <c>"IKETCP"</c> stream prefix, once.
    /// A reassembler reading the <b>client→server</b> direction must therefore consume that leading prefix
    /// (<paramref name="expectStreamPrefix"/> = <c>true</c>); one reading the <b>server→client</b> direction must not
    /// (<c>false</c>, the default) because the responder never sends it.
    /// </para>
    /// </summary>
    public sealed class Rfc8229Reassembler
    {
        readonly List<byte> _buffer = new();
        readonly bool _expectStreamPrefix;
        bool _prefixConsumed;

        /// <param name="expectStreamPrefix">
        /// When <c>true</c>, the first <see cref="Rfc8229Framing.StreamPrefixLength"/> bytes must be the RFC 8229 §3
        /// stream prefix and are consumed before any message; used by a responder reading the initiator's stream.
        /// </param>
        public Rfc8229Reassembler(bool expectStreamPrefix = false)
        {
            _expectStreamPrefix = expectStreamPrefix;
        }

        /// <summary>True while any bytes are still buffered (a partial prefix or a partial frame not yet completed).</summary>
        public bool HasBufferedData => _buffer.Count > 0;

        /// <summary>Feeds a chunk of received byte-stream bytes into the reassembly buffer.</summary>
        public void Append(ReadOnlySpan<byte> chunk)
        {
            // List<byte>.AddRange(ReadOnlySpan<byte>) is unavailable on netstandard2.0; a per-byte append keeps both
            // TFMs identical (zero-alloc streaming would be a later optimisation, not a correctness concern).
            foreach (byte b in chunk) _buffer.Add(b);
        }

        /// <summary>
        /// Pulls the next fully-received message if one is buffered; call in a loop after each <see cref="Append"/>.
        /// Returns <c>false</c> (leaving partial bytes buffered) until a whole frame has arrived. Throws
        /// <see cref="FormatException"/> if a required stream prefix is corrupt or a frame Length is shorter than the
        /// 2-byte Length field (a desynced stream).
        /// </summary>
        public bool TryReadMessage(out byte[] message)
        {
            message = Array.Empty<byte>();

            // §3: strip the initiator's "IKETCP" prefix before the first frame (responder direction only).
            if (_expectStreamPrefix && !_prefixConsumed)
            {
                if (_buffer.Count < Rfc8229Framing.StreamPrefixLength) return false;
                ReadOnlySpan<byte> expected = Rfc8229Framing.StreamPrefix;
                for (int i = 0; i < Rfc8229Framing.StreamPrefixLength; i++)
                {
                    if (_buffer[i] != expected[i])
                        throw new FormatException("RFC 8229 stream prefix 'IKETCP' missing or corrupt on the received stream.");
                }
                _buffer.RemoveRange(0, Rfc8229Framing.StreamPrefixLength);
                _prefixConsumed = true;
            }

            // §2: a 16-bit big-endian Length that counts itself; the frame body is (Length - 2) bytes.
            if (_buffer.Count < Rfc8229Framing.LengthFieldSize) return false;
            int length = (_buffer[0] << 8) | _buffer[1];
            if (length < Rfc8229Framing.LengthFieldSize)
                throw new FormatException($"RFC 8229 frame length {length} is smaller than the {Rfc8229Framing.LengthFieldSize}-byte length field.");
            if (_buffer.Count < length) return false;

            int messageLength = length - Rfc8229Framing.LengthFieldSize;
            message = new byte[messageLength];
            for (int i = 0; i < messageLength; i++) message[i] = _buffer[Rfc8229Framing.LengthFieldSize + i];
            _buffer.RemoveRange(0, length);
            return true;
        }
    }
}
