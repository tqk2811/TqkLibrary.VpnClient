using System.Buffers.Binary;
using System.Text;

namespace TqkLibrary.VpnClient.SoftEther
{
    /// <summary>
    /// Forward-only cursor over a SoftEther serialized buffer. Mirrors the <c>ReadBuf*</c> primitives: big-endian
    /// fixed-width integers, length-prefixed blobs, and the "BufStr" form (a <c>uint32 = length + 1</c> prefix followed
    /// by exactly <c>length</c> bytes — the +1 is a SoftEther quirk; the implied NUL is <b>not</b> on the wire for a
    /// BufStr, unlike a <see cref="Enums.PackValueType.UniStr"/> value which does carry the trailing NUL).
    /// </summary>
    public ref struct PackBufferReader
    {
        readonly ReadOnlySpan<byte> _buffer;
        int _position;

        /// <summary>Creates a reader over <paramref name="buffer"/>, positioned at the start.</summary>
        public PackBufferReader(ReadOnlySpan<byte> buffer)
        {
            _buffer = buffer;
            _position = 0;
        }

        /// <summary>Number of bytes already consumed.</summary>
        public int Position => _position;

        /// <summary>Number of bytes left to read.</summary>
        public int Remaining => _buffer.Length - _position;

        ReadOnlySpan<byte> Take(int count)
        {
            if (count < 0 || _position + count > _buffer.Length)
                throw new FormatException($"PACK buffer underrun: need {count} byte(s) at offset {_position}, only {Remaining} left.");
            ReadOnlySpan<byte> slice = _buffer.Slice(_position, count);
            _position += count;
            return slice;
        }

        /// <summary>Reads a big-endian 32-bit unsigned integer.</summary>
        public uint ReadUInt32() => BinaryPrimitives.ReadUInt32BigEndian(Take(4));

        /// <summary>Reads a big-endian 64-bit unsigned integer.</summary>
        public ulong ReadUInt64() => BinaryPrimitives.ReadUInt64BigEndian(Take(8));

        /// <summary>Reads exactly <paramref name="count"/> raw bytes into a copied array.</summary>
        public byte[] ReadBytes(int count) => Take(count).ToArray();

        /// <summary>
        /// Reads a "BufStr": a <c>uint32 = length + 1</c> prefix then <c>length</c> raw bytes decoded as the given
        /// <paramref name="encoding"/> (UTF-8 by default). A zero prefix is invalid per the protocol.
        /// </summary>
        public string ReadBufStr(Encoding? encoding = null)
        {
            uint prefixed = ReadUInt32();
            if (prefixed == 0)
                throw new FormatException("PACK BufStr length prefix must be >= 1 (length + 1).");
            int length = checked((int)(prefixed - 1));
            return (encoding ?? Encoding.UTF8).GetString(Take(length).ToArray());
        }
    }
}
