using System.Globalization;
using System.Text;
using TqkLibrary.VpnClient.Vtun.Wire.Enums;

namespace TqkLibrary.VpnClient.Vtun.Wire
{
    /// <summary>
    /// Codec for the compact host-flags string vtun exchanges in <c>OK FLAGS: &lt;...&gt;</c> (vtun's <c>bf2cf</c> /
    /// <c>cf2bf</c>, <c>auth.c</c>). The string is wrapped in <c>&lt; &gt;</c> and built from single-character tokens:
    /// <c>T</c>/<c>U</c> = TCP/UDP, <c>t</c>/<c>p</c>/<c>e</c>/<c>u</c> = tty/pipe/ether/tun, <c>K</c> = keepalive,
    /// <c>C&lt;n&gt;</c>/<c>L&lt;n&gt;</c> = zlib/lzo at level n, <c>E[n]</c> = encryption (cipher id, bare <c>E</c> = legacy),
    /// <c>S&lt;n&gt;</c> = traffic shaping at speed n. Example: <c>&lt;TuE1&gt;</c> = TCP + tun + encrypt cipher 1.
    /// <para>The <b>server</b> dictates the flags; the client parses them with <see cref="TryParse"/>. <see cref="Encode"/>
    /// is the inverse (used by the in-process test responder).</para>
    /// </summary>
    public static class VtunHostFlagsCodec
    {
        /// <summary>
        /// Parses a vtun flags string (anything from the first <c>&lt;</c> to the closing <c>&gt;</c>) into its flag bits,
        /// the compression level, the encryption cipher id and the shaping speed. Returns <c>false</c> on a malformed
        /// string (no <c>&lt;</c>, an unknown token, or a non-numeric C/L/E/S argument). Mirrors vtun's <c>cf2bf</c>.
        /// </summary>
        public static bool TryParse(string text, out VtunHostFlags flags, out int compressionLevel, out int cipher, out int shapeSpeed)
        {
            flags = VtunHostFlags.None;
            compressionLevel = 0;
            cipher = 0;
            shapeSpeed = 0;
            if (text is null) return false;

            int start = text.IndexOf('<');
            if (start < 0) return false;

            int i = start + 1;
            while (i < text.Length)
            {
                char c = text[i++];
                switch (c)
                {
                    case 't': flags |= VtunHostFlags.Tty; break;
                    case 'p': flags |= VtunHostFlags.Pipe; break;
                    case 'e': flags |= VtunHostFlags.Ether; break;
                    case 'u': flags |= VtunHostFlags.Tun; break;
                    case 'U': flags = (flags & ~VtunHostFlags.ProtocolMask) | VtunHostFlags.Udp; break;
                    case 'T': flags = (flags & ~VtunHostFlags.ProtocolMask) | VtunHostFlags.Tcp; break;
                    case 'K': flags |= VtunHostFlags.KeepAlive; break;
                    case 'F': break;                  // reserved feature token — ignored, like vtun
                    case '>': return true;            // closing bracket — done
                    case 'C':
                        if (!ReadInt(text, ref i, out compressionLevel)) return false;
                        flags |= VtunHostFlags.Zlib;
                        break;
                    case 'L':
                        if (!ReadInt(text, ref i, out compressionLevel)) return false;
                        flags |= VtunHostFlags.Lzo;
                        break;
                    case 'E':
                        // New form is 'E<n>'; the legacy form is a bare 'E' (n absent → 0). vtun does not require a digit.
                        ReadIntOptional(text, ref i, out cipher);
                        flags |= VtunHostFlags.Encrypt;
                        break;
                    case 'S':
                        if (!ReadInt(text, ref i, out shapeSpeed)) return false;
                        if (shapeSpeed != 0) flags |= VtunHostFlags.Shape;
                        break;
                    default:
                        return false;                 // unknown token — malformed
                }
            }
            return false;                             // ran off the end without a closing '>'
        }

        /// <summary>
        /// Encodes a flag set back into the wire string <c>&lt;...&gt;</c> (the inverse of <see cref="TryParse"/>, vtun's
        /// <c>bf2cf</c>). Field order matches vtun: protocol, type, shape, compression, keepalive, encryption.
        /// </summary>
        public static string Encode(VtunHostFlags flags, int compressionLevel = 0, int cipher = 0, int shapeSpeed = 0)
        {
            var sb = new StringBuilder(20);
            sb.Append('<');

            switch (flags & VtunHostFlags.ProtocolMask)
            {
                case VtunHostFlags.Tcp: sb.Append('T'); break;
                case VtunHostFlags.Udp: sb.Append('U'); break;
            }
            switch (flags & VtunHostFlags.TypeMask)
            {
                case VtunHostFlags.Tty: sb.Append('t'); break;
                case VtunHostFlags.Pipe: sb.Append('p'); break;
                case VtunHostFlags.Ether: sb.Append('e'); break;
                case VtunHostFlags.Tun: sb.Append('u'); break;
            }
            if ((flags & VtunHostFlags.Shape) != 0) sb.Append('S').Append(shapeSpeed.ToString(CultureInfo.InvariantCulture));
            if ((flags & VtunHostFlags.Zlib) != 0) sb.Append('C').Append(compressionLevel.ToString(CultureInfo.InvariantCulture));
            if ((flags & VtunHostFlags.Lzo) != 0) sb.Append('L').Append(compressionLevel.ToString(CultureInfo.InvariantCulture));
            if ((flags & VtunHostFlags.KeepAlive) != 0) sb.Append('K');
            if ((flags & VtunHostFlags.Encrypt) != 0)
            {
                sb.Append('E');
                if (cipher != 0) sb.Append(cipher.ToString(CultureInfo.InvariantCulture));
            }

            sb.Append('>');
            return sb.ToString();
        }

        // Reads a required base-10 integer starting at index i, advancing i past the digits. Returns false if no digit.
        static bool ReadInt(string text, ref int i, out int value)
        {
            int begin = i;
            while (i < text.Length && (char.IsDigit(text[i]) || (i == begin && (text[i] == '-' || text[i] == '+')))) i++;
            return int.TryParse(text.Substring(begin, i - begin), NumberStyles.Integer, CultureInfo.InvariantCulture, out value);
        }

        // Reads an optional integer (for the legacy bare 'E'): no digits ⇒ value 0, no advance, still "ok".
        static void ReadIntOptional(string text, ref int i, out int value)
        {
            int begin = i;
            while (i < text.Length && char.IsDigit(text[i])) i++;
            if (i == begin) { value = 0; return; }
            int.TryParse(text.Substring(begin, i - begin), NumberStyles.Integer, CultureInfo.InvariantCulture, out value);
        }
    }
}
