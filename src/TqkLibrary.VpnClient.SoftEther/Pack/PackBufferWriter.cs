using System.Buffers.Binary;
using System.Text;

namespace TqkLibrary.VpnClient.SoftEther
{
    /// <summary>
    /// Growable byte sink for the SoftEther serialized form. Mirrors the <c>WriteBuf*</c> primitives: big-endian
    /// fixed-width integers, length-prefixed blobs, and the "BufStr" form (a <c>uint32 = length + 1</c> prefix followed
    /// by exactly <c>length</c> bytes — the +1 is a SoftEther quirk; no NUL is written for a BufStr).
    /// </summary>
    public sealed class PackBufferWriter
    {
        readonly List<byte> _buffer;

        /// <summary>Creates an empty writer with an optional initial capacity.</summary>
        public PackBufferWriter(int capacity = 0)
        {
            _buffer = new List<byte>(capacity);
        }

        /// <summary>Number of bytes written so far.</summary>
        public int Length => _buffer.Count;

        /// <summary>Appends a big-endian 32-bit unsigned integer.</summary>
        public void WriteUInt32(uint value)
        {
            Span<byte> tmp = stackalloc byte[4];
            BinaryPrimitives.WriteUInt32BigEndian(tmp, value);
            AppendSpan(tmp);
        }

        /// <summary>Appends a big-endian 64-bit unsigned integer.</summary>
        public void WriteUInt64(ulong value)
        {
            Span<byte> tmp = stackalloc byte[8];
            BinaryPrimitives.WriteUInt64BigEndian(tmp, value);
            AppendSpan(tmp);
        }

        /// <summary>Appends raw bytes verbatim (no length prefix).</summary>
        public void WriteBytes(ReadOnlySpan<byte> bytes) => AppendSpan(bytes);

        /// <summary>
        /// Appends a "BufStr": a <c>uint32 = length + 1</c> prefix then exactly <c>length</c> bytes of the string in the
        /// given <paramref name="encoding"/> (UTF-8 by default). No trailing NUL is written (the +1 only inflates the
        /// prefix, matching SoftEther's <c>WriteBufStr</c>).
        /// </summary>
        public void WriteBufStr(string value, Encoding? encoding = null)
        {
            byte[] bytes = (encoding ?? Encoding.UTF8).GetBytes(value);
            WriteUInt32(checked((uint)bytes.Length + 1));
            AppendSpan(bytes);
        }

        /// <summary>Returns a fresh array copy of everything written.</summary>
        public byte[] ToArray() => _buffer.ToArray();

        void AppendSpan(ReadOnlySpan<byte> span)
        {
            // List<byte>.AddRange has no Span overload on netstandard2.0; append directly.
            _buffer.Capacity = Math.Max(_buffer.Capacity, _buffer.Count + span.Length);
            for (int i = 0; i < span.Length; i++)
                _buffer.Add(span[i]);
        }
    }
}
