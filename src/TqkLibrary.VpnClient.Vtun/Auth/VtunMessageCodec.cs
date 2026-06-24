using System.Text;
using TqkLibrary.VpnClient.Vtun.Wire;

namespace TqkLibrary.VpnClient.Vtun.Auth
{
    /// <summary>
    /// Codec for the fixed-size authentication message blocks vtun exchanges during the handshake (vtun's
    /// <c>print_p</c> / <c>readn_t</c>, <c>lib.c</c>). Every handshake line — <c>VTUN server ver ...</c>, <c>HOST: ...</c>,
    /// <c>OK CHAL: ...</c>, <c>CHAL: ...</c>, <c>OK FLAGS: ...</c>, <c>ERR</c> — is an ASCII string terminated by
    /// <c>\n</c> and then <b>zero-padded to exactly <see cref="VtunConstants.MessageSize"/> (50) bytes</b> on the wire.
    /// Getting the fixed-block framing wrong is a guaranteed interop failure (the daemon reads exactly 50 bytes per
    /// message), so this is its own codec.
    /// </summary>
    public static class VtunMessageCodec
    {
        /// <summary>
        /// Formats <paramref name="line"/> into a 50-byte message block: the ASCII bytes of the line, a trailing
        /// <c>\n</c> if absent, then NUL padding to <see cref="VtunConstants.MessageSize"/>. Throws if the line (with its
        /// newline) does not fit in 50 bytes.
        /// </summary>
        public static byte[] Encode(string line)
        {
            if (line is null) throw new ArgumentNullException(nameof(line));
            string withNewline = line.EndsWith("\n", StringComparison.Ordinal) ? line : line + "\n";
            byte[] body = Encoding.ASCII.GetBytes(withNewline);
            if (body.Length > VtunConstants.MessageSize)
                throw new ArgumentException($"vtun message exceeds {VtunConstants.MessageSize} bytes.", nameof(line));

            byte[] block = new byte[VtunConstants.MessageSize]; // zero-initialised ⇒ NUL padding
            Array.Copy(body, block, body.Length);
            return block;
        }

        /// <summary>
        /// Decodes a 50-byte message block back into its line: reads ASCII up to the first NUL, then trims the trailing
        /// <c>\r</c>/<c>\n</c>. <paramref name="block"/> must be exactly <see cref="VtunConstants.MessageSize"/> bytes.
        /// </summary>
        public static string Decode(ReadOnlySpan<byte> block)
        {
            if (block.Length != VtunConstants.MessageSize)
                throw new ArgumentException($"vtun message block must be {VtunConstants.MessageSize} bytes.", nameof(block));

            int end = block.IndexOf((byte)0);
            if (end < 0) end = block.Length;
            string line = Encoding.ASCII.GetString(block.Slice(0, end).ToArray());
            return line.TrimEnd('\r', '\n');
        }
    }
}
