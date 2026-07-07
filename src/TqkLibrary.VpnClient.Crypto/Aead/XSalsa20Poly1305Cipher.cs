// Alias the one BouncyCastle MAC + parameter type (not the whole namespace) — the same aliasing pattern the AEAD
// ciphers use, so BouncyCastle's Crypto namespace types do not clash with this project's interfaces. The BCL ships no
// raw one-time Poly1305 on either target framework, so BouncyCastle is used on net8.0 and netstandard2.0 alike.
using Poly1305Mac = Org.BouncyCastle.Crypto.Macs.Poly1305;
using KeyParameter = Org.BouncyCastle.Crypto.Parameters.KeyParameter;

namespace TqkLibrary.VpnClient.Crypto.Aead
{
    /// <summary>
    /// XSalsa20-Poly1305 authenticated encryption = NaCl <c>crypto_secretbox</c> (Bernstein). The keystream is
    /// <see cref="XSalsa20"/>(key, 24-byte nonce): its <b>first 32 bytes</b> become a one-time Poly1305 key, the message
    /// is XORed with the keystream <b>starting at byte 32</b>, and a 16-byte Poly1305 tag authenticates the ciphertext.
    /// There is <b>no</b> associated data and <b>no</b> length padding of the MAC input — this is the classic NaCl
    /// construction, not RFC 8439 AEAD, so it is a distinct type from <see cref="ChaCha20Poly1305Cipher"/> rather than an
    /// <c>IAeadCipher</c>.
    /// <para>
    /// The Poly1305 MAC reuses BouncyCastle's raw <c>Poly1305</c> (the same package the ChaCha20/AES AEAD ciphers use).
    /// BouncyCastle validates that the <c>r</c> half of the key is already clamped, so the first 16 bytes of the one-time
    /// key are clamped per RFC 8439 before <c>Init</c> (clamping is idempotent and matches NaCl's internal clamp).
    /// Tag verification is constant-time via <see cref="CryptoBytes.FixedTimeEquals"/>. Verified byte-exact against the
    /// NaCl <c>crypto_secretbox</c> test vector. Unlocks the NaCl mesh family (Quicktun <c>nacltai</c>, cjdns CryptoAuth).
    /// </para>
    /// </summary>
    public static class XSalsa20Poly1305Cipher
    {
        /// <summary>secretbox key length in bytes (256-bit).</summary>
        public const int KeyBytes = 32;

        /// <summary>secretbox nonce length in bytes (192-bit / 24 bytes).</summary>
        public const int NonceBytes = 24;

        /// <summary>secretbox authentication tag length in bytes.</summary>
        public const int TagBytes = 16;

        // XSalsa20 keystream bytes [0..32) form the one-time Poly1305 key; the message is XORed from byte 32 on.
        const int PolyKeyBytes = 32;

        /// <summary>
        /// Encrypts and authenticates <paramref name="plaintext"/> under <paramref name="key"/>/<paramref name="nonce"/>,
        /// returning <c>tag(16) ‖ ciphertext(plaintext.Length)</c> (the NaCl <c>crypto_secretbox</c> output layout).
        /// </summary>
        public static byte[] Seal(ReadOnlySpan<byte> key, ReadOnlySpan<byte> nonce, ReadOnlySpan<byte> plaintext)
        {
            byte[] output = new byte[TagBytes + plaintext.Length];
            Seal(key, nonce, plaintext, output.AsSpan(0, TagBytes), output.AsSpan(TagBytes));
            return output;
        }

        /// <summary>
        /// Encrypts <paramref name="plaintext"/> into <paramref name="ciphertext"/> (same length) and writes the 16-byte
        /// Poly1305 <paramref name="tag"/>.
        /// </summary>
        public static void Seal(ReadOnlySpan<byte> key, ReadOnlySpan<byte> nonce, ReadOnlySpan<byte> plaintext, Span<byte> tag, Span<byte> ciphertext)
        {
            if (tag.Length < TagBytes) throw new ArgumentException($"tag must be at least {TagBytes} bytes.", nameof(tag));
            if (ciphertext.Length < plaintext.Length) throw new ArgumentException("ciphertext too small", nameof(ciphertext));

            int mlen = plaintext.Length;
            byte[] keystream = new byte[PolyKeyBytes + mlen];
            XSalsa20.GenerateKeystream(key, nonce, keystream);   // validates key/nonce sizes

            for (int i = 0; i < mlen; i++)
                ciphertext[i] = (byte)(plaintext[i] ^ keystream[PolyKeyBytes + i]);

            byte[] oneTimeKey = ClampedOneTimeKey(keystream);
            ComputeTag(oneTimeKey, ciphertext.Slice(0, mlen), tag.Slice(0, TagBytes));
        }

        /// <summary>
        /// Verifies <paramref name="tag"/> over <paramref name="ciphertext"/> and, if valid, decrypts into
        /// <paramref name="plaintext"/>. Returns <see langword="false"/> (with <paramref name="plaintext"/> empty) on a
        /// bad tag; the tag is checked in constant time before any plaintext is produced.
        /// </summary>
        public static bool Open(ReadOnlySpan<byte> key, ReadOnlySpan<byte> nonce, ReadOnlySpan<byte> tag, ReadOnlySpan<byte> ciphertext, out byte[] plaintext)
        {
            plaintext = Array.Empty<byte>();
            if (tag.Length != TagBytes) return false;

            int clen = ciphertext.Length;
            byte[] keystream = new byte[PolyKeyBytes + clen];
            XSalsa20.GenerateKeystream(key, nonce, keystream);   // validates key/nonce sizes

            byte[] oneTimeKey = ClampedOneTimeKey(keystream);
            Span<byte> expected = stackalloc byte[TagBytes];
            ComputeTag(oneTimeKey, ciphertext, expected);
            if (!CryptoBytes.FixedTimeEquals(expected, tag)) return false;

            byte[] pt = new byte[clen];
            for (int i = 0; i < clen; i++)
                pt[i] = (byte)(ciphertext[i] ^ keystream[PolyKeyBytes + i]);
            plaintext = pt;
            return true;
        }

        // First 32 keystream bytes = one-time Poly1305 key; clamp the r-half (RFC 8439) so BouncyCastle accepts it.
        static byte[] ClampedOneTimeKey(byte[] keystream)
        {
            byte[] key = new byte[PolyKeyBytes];
            Array.Copy(keystream, 0, key, 0, PolyKeyBytes);
            key[3] &= 15; key[7] &= 15; key[11] &= 15; key[15] &= 15;
            key[4] &= 252; key[8] &= 252; key[12] &= 252;
            return key;
        }

        static void ComputeTag(byte[] oneTimeKey, ReadOnlySpan<byte> ciphertext, Span<byte> tag)
        {
            var poly = new Poly1305Mac();
            poly.Init(new KeyParameter(oneTimeKey));
            byte[] c = ciphertext.ToArray();
            poly.BlockUpdate(c, 0, c.Length);
            byte[] t = new byte[TagBytes];
            poly.DoFinal(t, 0);
            t.CopyTo(tag);
        }
    }
}
