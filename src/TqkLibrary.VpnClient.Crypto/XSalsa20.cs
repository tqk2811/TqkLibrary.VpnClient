namespace TqkLibrary.VpnClient.Crypto
{
    /// <summary>
    /// XSalsa20 stream cipher (Bernstein, "Extending the Salsa20 nonce" §2) — Salsa20 with a 24-byte (192-bit) nonce.
    /// The extended nonce is split in two: <c>subkey = HSalsa20(key, nonce[0:16])</c> derives a fresh 32-byte key, then
    /// the standard 20-round <see cref="Salsa20"/> keystream is run under that subkey with the remaining 8-byte nonce
    /// <c>nonce[16:24]</c> (block counter starting at 0) and XORed into the data.
    /// <para>
    /// Stage 2 <b>reuses</b> the existing <see cref="Salsa20"/> (Salsa20/20, feed-forward included) — only the keyless
    /// <see cref="HSalsa20"/> core lives separately. This is the keystream underneath NaCl <c>crypto_secretbox</c>
    /// (see <see cref="Aead.XSalsa20Poly1305Cipher"/>) and the Quicktun/cjdns mesh transports. Encryption and decryption
    /// are the same XOR-with-keystream operation. Verified against the NaCl <c>crypto_stream_xsalsa20</c> vector.
    /// </para>
    /// </summary>
    public static class XSalsa20
    {
        /// <summary>XSalsa20 key length in bytes (256-bit).</summary>
        public const int KeyBytes = 32;

        /// <summary>XSalsa20 nonce length in bytes (192-bit / 24 bytes).</summary>
        public const int NonceBytes = 24;

        /// <summary>
        /// XORs <paramref name="input"/> with the XSalsa20 keystream (block counter 0) into <paramref name="output"/>
        /// (same length). Decryption is the identical call.
        /// </summary>
        public static void Transform(ReadOnlySpan<byte> key, ReadOnlySpan<byte> nonce, ReadOnlySpan<byte> input, Span<byte> output)
        {
            if (output.Length < input.Length) throw new ArgumentException("output too small", nameof(output));
            Span<byte> subKey = stackalloc byte[KeyBytes];
            DeriveSubKey(key, nonce, subKey);
            new Salsa20(20).Transform(subKey, nonce.Slice(16, 8), input, output);
        }

        /// <summary>Fills <paramref name="output"/> with raw XSalsa20 keystream bytes (equivalent to encrypting zeros).</summary>
        public static void GenerateKeystream(ReadOnlySpan<byte> key, ReadOnlySpan<byte> nonce, Span<byte> output)
        {
            Span<byte> subKey = stackalloc byte[KeyBytes];
            DeriveSubKey(key, nonce, subKey);
            new Salsa20(20).GenerateKeystream(subKey, nonce.Slice(16, 8), output);
        }

        // subkey = HSalsa20(key, nonce[0:16]); validates the 32-byte key and 24-byte nonce.
        static void DeriveSubKey(ReadOnlySpan<byte> key, ReadOnlySpan<byte> nonce, Span<byte> subKey)
        {
            if (key.Length != KeyBytes) throw new ArgumentException($"XSalsa20 key must be {KeyBytes} bytes.", nameof(key));
            if (nonce.Length != NonceBytes) throw new ArgumentException($"XSalsa20 nonce must be {NonceBytes} bytes.", nameof(nonce));
            HSalsa20.Hash(key, nonce.Slice(0, 16), subKey);
        }
    }
}
