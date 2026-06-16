using System.Text;
using TqkLibrary.VpnClient.SoftEther.Enums;

namespace TqkLibrary.VpnClient.SoftEther
{
    /// <summary>
    /// One named entry in a <see cref="Pack"/>: a <see cref="Name"/> (≤ <see cref="PackConstants.MaxElementNameLength"/>
    /// chars), a single <see cref="PackValueType"/> <see cref="Type"/>, and an ordered array of <see cref="PackValue"/>
    /// (length ≥ 1) all of that type. Wire layout: <c>BufStr(name) · uint32(type) · uint32(num_value) · value[]</c>,
    /// all integers big-endian.
    /// </summary>
    public sealed class PackElement
    {
        /// <summary>Element name (case-insensitive on lookup). Limited to <see cref="PackConstants.MaxElementNameLength"/> characters.</summary>
        public string Name { get; }

        /// <summary>The single value type shared by every entry in <see cref="Values"/>.</summary>
        public PackValueType Type { get; }

        /// <summary>The ordered values (≥ 1). Index 0 is the "primary" value used by single-value accessors.</summary>
        public IReadOnlyList<PackValue> Values { get; }

        /// <summary>Builds an element from a pre-made value list (must be non-empty and within the count limit).</summary>
        public PackElement(string name, PackValueType type, IReadOnlyList<PackValue> values)
        {
            if (name is null) throw new ArgumentNullException(nameof(name));
            if (name.Length > PackConstants.MaxElementNameLength)
                throw new ArgumentException($"PACK element name '{name}' exceeds {PackConstants.MaxElementNameLength} characters.", nameof(name));
            if (values is null) throw new ArgumentNullException(nameof(values));
            if (values.Count == 0)
                throw new ArgumentException("A PACK element must carry at least one value.", nameof(values));
            if (values.Count > PackConstants.MaxValueCount)
                throw new ArgumentException($"PACK element '{name}' has {values.Count} values, over the {PackConstants.MaxValueCount} limit.", nameof(values));

            Name = name;
            Type = type;
            Values = values;
        }

        /// <summary>Number of values in this element.</summary>
        public int ValueCount => Values.Count;

        internal void Write(PackBufferWriter writer)
        {
            // SoftEther writes the element name as a BufStr; protocol names are ASCII so UTF-8 == ASCII here.
            writer.WriteBufStr(Name, Encoding.ASCII);
            writer.WriteUInt32((uint)Type);
            writer.WriteUInt32((uint)Values.Count);
            foreach (PackValue value in Values)
                value.Write(writer, Type);
        }

        internal static PackElement Read(ref PackBufferReader reader)
        {
            string name = reader.ReadBufStr(Encoding.ASCII);
            var type = (PackValueType)reader.ReadUInt32();
            uint count = reader.ReadUInt32();
            if (count == 0)
                throw new FormatException($"PACK element '{name}' declares zero values.");
            if (count > PackConstants.MaxValueCount)
                throw new FormatException($"PACK element '{name}' declares {count} values, over the {PackConstants.MaxValueCount} limit.");

            var values = new PackValue[count];
            for (int i = 0; i < count; i++)
                values[i] = PackValue.Read(ref reader, type);
            return new PackElement(name, type, values);
        }
    }
}
