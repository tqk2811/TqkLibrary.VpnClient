using System.Text;
using TqkLibrary.VpnClient.SoftEther.Enums;

namespace TqkLibrary.VpnClient.SoftEther
{
    /// <summary>
    /// One typed value inside a <see cref="PackElement"/>. A value carries exactly one payload matching the element's
    /// <see cref="PackElement.Type"/>; the unused fields stay at their defaults. Factory methods build well-typed
    /// instances and the codec reads/writes the single relevant field.
    /// </summary>
    public sealed class PackValue
    {
        /// <summary>The <see cref="PackValueType.Int"/> payload (valid only when the element is an int).</summary>
        public uint IntValue { get; init; }

        /// <summary>The <see cref="PackValueType.Int64"/> payload (valid only when the element is an int64).</summary>
        public ulong Int64Value { get; init; }

        /// <summary>The <see cref="PackValueType.Data"/> payload (valid only when the element is data); never null for a data value.</summary>
        public byte[] Data { get; init; } = Array.Empty<byte>();

        /// <summary>
        /// The string payload for <see cref="PackValueType.Str"/> (ANSI) or <see cref="PackValueType.UniStr"/>
        /// (Unicode/UTF-8). Never null for a string value.
        /// </summary>
        public string StringValue { get; init; } = string.Empty;

        /// <summary>Wraps a 32-bit unsigned integer.</summary>
        public static PackValue FromInt(uint value) => new() { IntValue = value };

        /// <summary>Wraps a 64-bit unsigned integer.</summary>
        public static PackValue FromInt64(ulong value) => new() { Int64Value = value };

        /// <summary>Wraps a raw byte blob (the array is referenced, not copied).</summary>
        public static PackValue FromData(byte[] value) => new() { Data = value ?? throw new ArgumentNullException(nameof(value)) };

        /// <summary>Wraps an ANSI/Unicode string (the codec picks the encoding from the element type).</summary>
        public static PackValue FromString(string value) => new() { StringValue = value ?? throw new ArgumentNullException(nameof(value)) };

        internal void Write(PackBufferWriter writer, PackValueType type)
        {
            switch (type)
            {
                case PackValueType.Int:
                    writer.WriteUInt32(IntValue);
                    break;
                case PackValueType.Int64:
                    writer.WriteUInt64(Int64Value);
                    break;
                case PackValueType.Data:
                    writer.WriteUInt32(checked((uint)Data.Length));
                    writer.WriteBytes(Data);
                    break;
                case PackValueType.Str:
                    // ANSI string: uint32 byte-length (no +1) then the bytes (latin1/8-bit).
                    byte[] ansi = SoftEtherAnsi.GetBytes(StringValue);
                    writer.WriteUInt32(checked((uint)ansi.Length));
                    writer.WriteBytes(ansi);
                    break;
                case PackValueType.UniStr:
                    // Unicode string: stored UTF-8, prefix = utf8-length + 1, then the bytes AND a trailing NUL.
                    byte[] utf8 = Encoding.UTF8.GetBytes(StringValue);
                    writer.WriteUInt32(checked((uint)utf8.Length + 1));
                    writer.WriteBytes(utf8);
                    writer.WriteBytes(new byte[] { 0 });
                    break;
                default:
                    throw new ArgumentOutOfRangeException(nameof(type), type, "Unknown PACK value type.");
            }
        }

        internal static PackValue Read(ref PackBufferReader reader, PackValueType type)
        {
            switch (type)
            {
                case PackValueType.Int:
                    return FromInt(reader.ReadUInt32());
                case PackValueType.Int64:
                    return FromInt64(reader.ReadUInt64());
                case PackValueType.Data:
                {
                    uint size = reader.ReadUInt32();
                    if (size > PackConstants.MaxValueSize)
                        throw new FormatException($"PACK data value size {size} exceeds the {PackConstants.MaxValueSize}-byte limit.");
                    return FromData(reader.ReadBytes(checked((int)size)));
                }
                case PackValueType.Str:
                {
                    uint size = reader.ReadUInt32();
                    if (size > PackConstants.MaxValueSize)
                        throw new FormatException($"PACK string value size {size} exceeds the {PackConstants.MaxValueSize}-byte limit.");
                    byte[] ansi = reader.ReadBytes(checked((int)size));
                    return FromString(SoftEtherAnsi.GetString(ansi));
                }
                case PackValueType.UniStr:
                {
                    uint prefixed = reader.ReadUInt32();
                    if (prefixed == 0)
                        throw new FormatException("PACK unicode value length prefix must be >= 1 (utf8-length + 1).");
                    if (prefixed > PackConstants.MaxValueSize)
                        throw new FormatException($"PACK unicode value size {prefixed} exceeds the {PackConstants.MaxValueSize}-byte limit.");
                    // The prefix counts the trailing NUL; read that many bytes and drop the final NUL if present.
                    byte[] raw = reader.ReadBytes(checked((int)prefixed));
                    int len = raw.Length;
                    if (len > 0 && raw[len - 1] == 0) len--;
                    return FromString(Encoding.UTF8.GetString(raw, 0, len));
                }
                default:
                    throw new FormatException($"Unknown PACK value type {(uint)type}.");
            }
        }
    }
}
