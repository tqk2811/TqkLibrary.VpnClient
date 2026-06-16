namespace TqkLibrary.VpnClient.SoftEther
{
    /// <summary>
    /// Codec for the SoftEther <see cref="Enums.PackValueType.Str"/> ("ANSI") string form: a flat 8-bit byte stream
    /// where each character maps 1:1 to one byte (ISO-8859-1 / Latin-1). Implemented by hand so the behavior is
    /// identical on both target frameworks (<c>Encoding.Latin1</c> only exists from net5). Bytes &gt; 0x7F survive a
    /// round-trip unchanged, which is what protocol fields (usually ASCII hub/user names) require.
    /// </summary>
    internal static class SoftEtherAnsi
    {
        public static byte[] GetBytes(string value)
        {
            var bytes = new byte[value.Length];
            for (int i = 0; i < value.Length; i++)
                bytes[i] = (byte)value[i]; // low 8 bits; protocol fields are ASCII/Latin-1.
            return bytes;
        }

        public static string GetString(ReadOnlySpan<byte> bytes)
        {
            var chars = new char[bytes.Length];
            for (int i = 0; i < bytes.Length; i++)
                chars[i] = (char)bytes[i];
            return new string(chars);
        }
    }
}
