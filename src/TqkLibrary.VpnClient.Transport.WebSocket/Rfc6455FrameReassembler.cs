using System.Collections.Generic;

namespace TqkLibrary.VpnClient.Transport.WebSocket
{
    /// <summary>
    /// Stateful receive-side reassembler for RFC 6455 framing: buffers received byte-stream chunks and hands back whole
    /// frames as their length-delimited boundaries complete, across arbitrary read splits (a chunk may cut through the
    /// length field, the mask key, the payload, or carry several frames). It only restores frame boundaries — combining
    /// the fragmented data frames of one message (§5.4) and answering control frames is the transport's job. Mirrors the
    /// streaming pattern of <c>Rfc8229Reassembler</c> without copying it.
    /// </summary>
    public sealed class Rfc6455FrameReassembler
    {
        readonly List<byte> _buffer = new();

        /// <summary>True while any bytes are still buffered (a partial frame not yet completed).</summary>
        public bool HasBufferedData => _buffer.Count > 0;

        /// <summary>Feeds a chunk of received byte-stream bytes into the reassembly buffer.</summary>
        public void Append(ReadOnlySpan<byte> chunk)
        {
            // List<byte>.AddRange(ReadOnlySpan<byte>) is unavailable on netstandard2.0; a per-byte append keeps both TFMs
            // identical (a zero-alloc streaming decoder would be a later optimisation, not a correctness concern).
            foreach (byte b in chunk) _buffer.Add(b);
        }

        /// <summary>
        /// Pulls the next fully-received frame if one is buffered; call in a loop after each <see cref="Append"/>. Returns
        /// <c>false</c> (leaving partial bytes buffered) until a whole frame has arrived.
        /// </summary>
        public bool TryReadFrame(out bool fin, out Rfc6455Opcode opcode, out byte[] payload)
        {
            fin = false;
            opcode = default;
            payload = Array.Empty<byte>();
            if (_buffer.Count == 0) return false;

            byte[] snapshot = _buffer.ToArray();
            if (!Rfc6455Frame.TryDecodeFrame(snapshot, out fin, out opcode, out payload, out int consumed))
                return false;

            _buffer.RemoveRange(0, consumed);
            return true;
        }
    }
}
