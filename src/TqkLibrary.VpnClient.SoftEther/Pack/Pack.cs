using TqkLibrary.VpnClient.SoftEther.Enums;

namespace TqkLibrary.VpnClient.SoftEther
{
    /// <summary>
    /// A SoftEther <c>PACK</c>: an ordered list of named, typed <see cref="PackElement"/>s — the binary message format
    /// used for every SoftEther control/RPC exchange (hello, login, welcome, …). Re-implemented from the protocol spec
    /// (not copied from the GPL <c>Pack.c</c>); a pure in-memory container plus the big-endian wire codec
    /// (<see cref="ToBytes"/> / <see cref="Parse(System.ReadOnlySpan{byte})"/>). No I/O.
    /// <para>
    /// Wire layout: <c>uint32(num_elements)</c> then, per element,
    /// <c>BufStr(name) · uint32(type) · uint32(num_value) · value[]</c>. <c>BufStr</c> is a <c>uint32 = len + 1</c>
    /// prefix followed by <c>len</c> raw bytes. All integers are big-endian.
    /// </para>
    /// <para>Element names are unique case-insensitively, mirroring SoftEther's <c>GetElement</c> lookup.</para>
    /// </summary>
    public sealed class Pack
    {
        readonly List<PackElement> _elements = new();
        readonly Dictionary<string, int> _index = new(StringComparer.OrdinalIgnoreCase);

        /// <summary>The elements in insertion order.</summary>
        public IReadOnlyList<PackElement> Elements => _elements;

        /// <summary>Number of elements.</summary>
        public int Count => _elements.Count;

        /// <summary>
        /// Adds an element. Throws if an element with the same name (case-insensitive) already exists or the
        /// per-PACK element limit is hit.
        /// </summary>
        public Pack Add(PackElement element)
        {
            if (element is null) throw new ArgumentNullException(nameof(element));
            if (_index.ContainsKey(element.Name))
                throw new ArgumentException($"A PACK element named '{element.Name}' already exists.", nameof(element));
            if (_elements.Count >= PackConstants.MaxElementCount)
                throw new InvalidOperationException($"PACK already holds the maximum {PackConstants.MaxElementCount} elements.");
            _index[element.Name] = _elements.Count;
            _elements.Add(element);
            return this;
        }

        /// <summary>Returns the element with <paramref name="name"/> (case-insensitive), or null if absent.</summary>
        public PackElement? GetElement(string name)
            => _index.TryGetValue(name, out int i) ? _elements[i] : null;

        /// <summary>True if an element named <paramref name="name"/> exists (case-insensitive).</summary>
        public bool Contains(string name) => _index.ContainsKey(name);

        // ---- Set helpers (one element, single value) -------------------------------------------------

        /// <summary>Adds a single-value <see cref="PackValueType.Int"/> element.</summary>
        public Pack SetInt(string name, uint value)
            => Add(new PackElement(name, PackValueType.Int, new[] { PackValue.FromInt(value) }));

        /// <summary>Adds a single-value <see cref="PackValueType.Int64"/> element.</summary>
        public Pack SetInt64(string name, ulong value)
            => Add(new PackElement(name, PackValueType.Int64, new[] { PackValue.FromInt64(value) }));

        /// <summary>Adds a single-value <see cref="PackValueType.Data"/> element (the array is referenced, not copied).</summary>
        public Pack SetData(string name, byte[] value)
            => Add(new PackElement(name, PackValueType.Data, new[] { PackValue.FromData(value) }));

        /// <summary>Adds a single-value <see cref="PackValueType.Str"/> (ANSI) element.</summary>
        public Pack SetStr(string name, string value)
            => Add(new PackElement(name, PackValueType.Str, new[] { PackValue.FromString(value) }));

        /// <summary>Adds a single-value <see cref="PackValueType.UniStr"/> (Unicode/UTF-8) element.</summary>
        public Pack SetUniStr(string name, string value)
            => Add(new PackElement(name, PackValueType.UniStr, new[] { PackValue.FromString(value) }));

        /// <summary>Adds a <see cref="PackValueType.Int"/> element that wraps a bool as 1/0 (SoftEther convention).</summary>
        public Pack SetBool(string name, bool value) => SetInt(name, value ? 1u : 0u);

        // ---- Set helpers (one element, multiple values) ----------------------------------------------

        /// <summary>Adds a multi-value <see cref="PackValueType.Int"/> element.</summary>
        public Pack SetIntArray(string name, IReadOnlyList<uint> values)
            => AddArray(name, PackValueType.Int, values, PackValue.FromInt);

        /// <summary>Adds a multi-value <see cref="PackValueType.Int64"/> element.</summary>
        public Pack SetInt64Array(string name, IReadOnlyList<ulong> values)
            => AddArray(name, PackValueType.Int64, values, PackValue.FromInt64);

        /// <summary>Adds a multi-value <see cref="PackValueType.Data"/> element.</summary>
        public Pack SetDataArray(string name, IReadOnlyList<byte[]> values)
            => AddArray(name, PackValueType.Data, values, PackValue.FromData);

        /// <summary>Adds a multi-value <see cref="PackValueType.Str"/> (ANSI) element.</summary>
        public Pack SetStrArray(string name, IReadOnlyList<string> values)
            => AddArray(name, PackValueType.Str, values, PackValue.FromString);

        /// <summary>Adds a multi-value <see cref="PackValueType.UniStr"/> (Unicode) element.</summary>
        public Pack SetUniStrArray(string name, IReadOnlyList<string> values)
            => AddArray(name, PackValueType.UniStr, values, PackValue.FromString);

        Pack AddArray<T>(string name, PackValueType type, IReadOnlyList<T> values, Func<T, PackValue> wrap)
        {
            if (values is null) throw new ArgumentNullException(nameof(values));
            var wrapped = new PackValue[values.Count];
            for (int i = 0; i < values.Count; i++)
                wrapped[i] = wrap(values[i]);
            return Add(new PackElement(name, type, wrapped));
        }

        // ---- Get helpers (by name + optional index) --------------------------------------------------

        /// <summary>Reads an int value (index defaults to 0); returns <paramref name="fallback"/> when absent/mismatched.</summary>
        public uint GetInt(string name, int index = 0, uint fallback = 0)
            => GetValue(name, PackValueType.Int, index)?.IntValue ?? fallback;

        /// <summary>Reads an int64 value (index defaults to 0); returns <paramref name="fallback"/> when absent/mismatched.</summary>
        public ulong GetInt64(string name, int index = 0, ulong fallback = 0)
            => GetValue(name, PackValueType.Int64, index)?.Int64Value ?? fallback;

        /// <summary>Reads a data value (index defaults to 0); returns null when absent/mismatched.</summary>
        public byte[]? GetData(string name, int index = 0)
            => GetValue(name, PackValueType.Data, index)?.Data;

        /// <summary>Reads an ANSI string value (index defaults to 0); returns null when absent/mismatched.</summary>
        public string? GetStr(string name, int index = 0)
            => GetValue(name, PackValueType.Str, index)?.StringValue;

        /// <summary>Reads a Unicode string value (index defaults to 0); returns null when absent/mismatched.</summary>
        public string? GetUniStr(string name, int index = 0)
            => GetValue(name, PackValueType.UniStr, index)?.StringValue;

        /// <summary>Reads an int value as a bool (≠ 0); returns <paramref name="fallback"/> when absent/mismatched.</summary>
        public bool GetBool(string name, int index = 0, bool fallback = false)
        {
            PackValue? v = GetValue(name, PackValueType.Int, index);
            return v is null ? fallback : v.IntValue != 0;
        }

        PackValue? GetValue(string name, PackValueType type, int index)
        {
            PackElement? element = GetElement(name);
            if (element is null || element.Type != type) return null;
            if (index < 0 || index >= element.Values.Count) return null;
            return element.Values[index];
        }

        // ---- Codec -----------------------------------------------------------------------------------

        /// <summary>Serializes this PACK to its big-endian wire representation.</summary>
        public byte[] ToBytes()
        {
            var writer = new PackBufferWriter();
            writer.WriteUInt32((uint)_elements.Count);
            foreach (PackElement element in _elements)
                element.Write(writer);
            return writer.ToArray();
        }

        /// <summary>
        /// Parses a PACK from its wire representation. Throws <see cref="FormatException"/> on malformed input
        /// (underrun, duplicate names, over-limit counts, unknown value type).
        /// </summary>
        public static Pack Parse(ReadOnlySpan<byte> buffer)
        {
            var reader = new PackBufferReader(buffer);
            uint count = reader.ReadUInt32();
            if (count > PackConstants.MaxElementCount)
                throw new FormatException($"PACK declares {count} elements, over the {PackConstants.MaxElementCount} limit.");

            var pack = new Pack();
            for (uint i = 0; i < count; i++)
            {
                PackElement element = PackElement.Read(ref reader);
                if (pack.Contains(element.Name))
                    throw new FormatException($"PACK contains a duplicate element name '{element.Name}'.");
                pack.Add(element);
            }
            return pack;
        }

        /// <summary>Parses a PACK from a byte array.</summary>
        public static Pack Parse(byte[] buffer)
            => Parse((buffer ?? throw new ArgumentNullException(nameof(buffer))).AsSpan());
    }
}
