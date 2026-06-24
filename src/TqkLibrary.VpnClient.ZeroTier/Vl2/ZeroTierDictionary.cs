using System.Collections.Generic;
using System.Text;

namespace TqkLibrary.VpnClient.ZeroTier.Vl2
{
    /// <summary>
    /// ZeroTier's simple serialised dictionary: a flat list of <c>key=value</c> entries each terminated by a newline
    /// (<c>\n</c>), with the whole blob optionally null-terminated. It is the container ZeroTier uses for a network
    /// configuration and for HELLO/NETWORK_CONFIG_REQUEST metadata. Keys are stored verbatim (no <c>=</c>, no control
    /// bytes); values are escaped so arbitrary binary (a certificate of membership, packed InetAddresses) survives the
    /// line-oriented format: <c>=</c>→<c>\e</c>, NUL→<c>\0</c>, CR→<c>\r</c>, LF→<c>\n</c>, <c>\</c>→<c>\\</c>.
    /// Integers are stored as unpadded lowercase hex. This is a faithful clean-room of <c>Dictionary::(de)serialize</c>.
    /// </summary>
    public sealed class ZeroTierDictionary
    {
        readonly Dictionary<string, byte[]> _entries = new Dictionary<string, byte[]>();

        /// <summary>The keys present in the dictionary.</summary>
        public IEnumerable<string> Keys => _entries.Keys;

        /// <summary>True if <paramref name="key"/> is present.</summary>
        public bool Contains(string key) => _entries.ContainsKey(key);

        /// <summary>Stores a raw byte value under <paramref name="key"/>.</summary>
        public void SetBytes(string key, byte[] value) => _entries[key] = value ?? System.Array.Empty<byte>();

        /// <summary>Stores a UTF-8 string value.</summary>
        public void SetString(string key, string value) => _entries[key] = Encoding.UTF8.GetBytes(value ?? string.Empty);

        /// <summary>Stores an unsigned integer as unpadded lowercase hex (ZeroTier's number encoding).</summary>
        public void SetUInt64(string key, ulong value) => _entries[key] = Encoding.ASCII.GetBytes(value.ToString("x"));

        /// <summary>Gets the raw bytes for <paramref name="key"/>, or null when absent.</summary>
        public byte[]? GetBytes(string key) => _entries.TryGetValue(key, out byte[]? v) ? v : null;

        /// <summary>Gets the UTF-8 string for <paramref name="key"/>, or null when absent.</summary>
        public string? GetString(string key) => _entries.TryGetValue(key, out byte[]? v) ? Encoding.UTF8.GetString(v) : null;

        /// <summary>Parses a hex value (ZeroTier number encoding) for <paramref name="key"/>; returns false when absent or malformed.</summary>
        public bool TryGetUInt64(string key, out ulong value)
        {
            value = 0;
            string? s = GetString(key);
            if (string.IsNullOrEmpty(s)) return false;
            try { value = System.Convert.ToUInt64(s, 16); return true; }
            catch { return false; }
        }

        /// <summary>Serialises the dictionary to its on-wire byte form (entries sorted by key for determinism).</summary>
        public byte[] Serialize()
        {
            var sb = new List<byte>();
            var keys = new List<string>(_entries.Keys);
            keys.Sort(System.StringComparer.Ordinal);
            foreach (string key in keys)
            {
                foreach (char c in key) sb.Add((byte)c);   // keys are plain ASCII, unescaped
                sb.Add((byte)'=');
                AppendEscaped(sb, _entries[key]);
                sb.Add((byte)'\n');
            }
            return sb.ToArray();
        }

        /// <summary>Parses a serialised dictionary. Tolerant: stops at a NUL terminator and skips malformed lines.</summary>
        public static ZeroTierDictionary Deserialize(ReadOnlySpan<byte> data)
        {
            var dict = new ZeroTierDictionary();
            var key = new List<byte>();
            var value = new List<byte>();
            bool inValue = false;
            bool escaped = false;

            for (int i = 0; i < data.Length; i++)
            {
                byte c = data[i];
                // NUL is NOT a hard terminator: a ZeroTier controller (pre-1.6) emits binary values that contain raw NUL
                // bytes (e.g. the "v"/version field), so a value keeps NUL verbatim. A stray NUL outside any entry (before
                // a key has started) is just skipped. Entries are delimited only by '\n'; the buffer bounds the dict.
                if (c == 0 && !inValue && key.Count == 0) continue;

                if (escaped)
                {
                    escaped = false;
                    byte u = c switch
                    {
                        (byte)'e' => (byte)'=',
                        (byte)'0' => 0,
                        (byte)'r' => (byte)'\r',
                        (byte)'n' => (byte)'\n',
                        _ => c,                 // \\ and anything else: literal
                    };
                    (inValue ? value : key).Add(u);
                    continue;
                }

                if (c == (byte)'\\') { escaped = true; continue; }

                if (c == (byte)'\n')
                {
                    if (key.Count > 0)
                        dict._entries[Encoding.ASCII.GetString(key.ToArray())] = value.ToArray();
                    key.Clear(); value.Clear(); inValue = false;
                    continue;
                }

                if (!inValue && c == (byte)'=') { inValue = true; continue; }
                (inValue ? value : key).Add(c);
            }

            // A trailing entry without a closing newline is still accepted.
            if (key.Count > 0)
                dict._entries[Encoding.ASCII.GetString(key.ToArray())] = value.ToArray();
            return dict;
        }

        static void AppendEscaped(List<byte> sb, byte[] value)
        {
            foreach (byte b in value)
            {
                switch (b)
                {
                    case (byte)'=': sb.Add((byte)'\\'); sb.Add((byte)'e'); break;
                    case 0: sb.Add((byte)'\\'); sb.Add((byte)'0'); break;
                    case (byte)'\r': sb.Add((byte)'\\'); sb.Add((byte)'r'); break;
                    case (byte)'\n': sb.Add((byte)'\\'); sb.Add((byte)'n'); break;
                    case (byte)'\\': sb.Add((byte)'\\'); sb.Add((byte)'\\'); break;
                    default: sb.Add(b); break;
                }
            }
        }
    }
}
