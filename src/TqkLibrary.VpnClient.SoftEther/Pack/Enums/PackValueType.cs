namespace TqkLibrary.VpnClient.SoftEther.Enums
{
    /// <summary>
    /// SoftEther PACK <c>VALUE</c> type tag, serialized on the wire as a 32-bit big-endian integer right after the
    /// element name. Numeric values are fixed by the protocol (re-implemented from the SoftEther spec — not copied from
    /// the GPL <c>Pack.h</c>).
    /// </summary>
    public enum PackValueType : uint
    {
        /// <summary>32-bit unsigned integer (<c>VALUE_INT</c>). On the wire: a single big-endian <see cref="uint"/>.</summary>
        Int = 0,

        /// <summary>Raw byte blob (<c>VALUE_DATA</c>). On the wire: big-endian <see cref="uint"/> length then that many bytes.</summary>
        Data = 1,

        /// <summary>ANSI string (<c>VALUE_STR</c>). On the wire: big-endian <see cref="uint"/> byte-length (no +1) then the bytes.</summary>
        Str = 2,

        /// <summary>
        /// Unicode string (<c>VALUE_UNISTR</c>), stored as UTF-8 on the wire. On the wire: big-endian <see cref="uint"/>
        /// equal to <c>utf8-byte-length + 1</c>, then the UTF-8 bytes followed by a single trailing NUL byte.
        /// </summary>
        UniStr = 3,

        /// <summary>64-bit unsigned integer (<c>VALUE_INT64</c>). On the wire: a single big-endian <see cref="ulong"/>.</summary>
        Int64 = 4,
    }
}
