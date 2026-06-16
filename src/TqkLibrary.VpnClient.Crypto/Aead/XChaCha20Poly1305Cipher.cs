using System.Buffers.Binary;
using TqkLibrary.VpnClient.Crypto.Abstractions.Interfaces;

namespace TqkLibrary.VpnClient.Crypto.Aead
{
    /// <summary>
    /// XChaCha20-Poly1305 AEAD (draft-irtf-cfrg-xchacha §2.3) — the extended-nonce variant WireGuard's cookie-reply
    /// uses. The 24-byte nonce is split: the first 16 bytes plus the key are run through <c>HChaCha20</c> to derive a
    /// 32-byte subkey, then RFC 8439 ChaCha20-Poly1305 is run with that subkey and a 12-byte nonce built as
    /// <c>0x00000000 || nonce[16:24]</c>. The inner AEAD reuses <see cref="ChaCha20Poly1305Cipher"/> (native on
    /// .NET 5+, BouncyCastle on netstandard2.0) so there is no second cipher implementation; only the keyless
    /// <c>HChaCha20</c> block function lives here.
    /// </summary>
    public sealed class XChaCha20Poly1305Cipher : IAeadCipher
    {
        const int KeyBytes = 32;
        const int NonceBytes = 24;
        const int TagBytes = 16;
        const int InnerNonceBytes = 12;

        readonly IAeadCipher _inner;

        /// <summary>Creates the cipher, optionally over a custom inner ChaCha20-Poly1305 (defaults to the F.4 one).</summary>
        public XChaCha20Poly1305Cipher(IAeadCipher? innerChaCha20Poly1305 = null)
        {
            _inner = innerChaCha20Poly1305 ?? new ChaCha20Poly1305Cipher();
            if (_inner.KeySizeInBytes != KeyBytes || _inner.NonceSizeInBytes != InnerNonceBytes || _inner.TagSizeInBytes != TagBytes)
                throw new ArgumentException("XChaCha20-Poly1305 requires an inner ChaCha20-Poly1305 (key 32, nonce 12, tag 16).", nameof(innerChaCha20Poly1305));
        }

        /// <inheritdoc/>
        public int KeySizeInBytes => KeyBytes;

        /// <inheritdoc/>
        public int NonceSizeInBytes => NonceBytes;

        /// <inheritdoc/>
        public int TagSizeInBytes => TagBytes;

        /// <inheritdoc/>
        public void Seal(
            ReadOnlySpan<byte> key,
            ReadOnlySpan<byte> nonce,
            ReadOnlySpan<byte> plaintext,
            ReadOnlySpan<byte> associatedData,
            Span<byte> ciphertext,
            Span<byte> tag)
        {
            Span<byte> subKey = stackalloc byte[KeyBytes];
            Span<byte> innerNonce = stackalloc byte[InnerNonceBytes];
            Derive(key, nonce, subKey, innerNonce);
            _inner.Seal(subKey, innerNonce, plaintext, associatedData, ciphertext, tag);
        }

        /// <inheritdoc/>
        public bool Open(
            ReadOnlySpan<byte> key,
            ReadOnlySpan<byte> nonce,
            ReadOnlySpan<byte> ciphertext,
            ReadOnlySpan<byte> tag,
            ReadOnlySpan<byte> associatedData,
            Span<byte> plaintext)
        {
            Span<byte> subKey = stackalloc byte[KeyBytes];
            Span<byte> innerNonce = stackalloc byte[InnerNonceBytes];
            Derive(key, nonce, subKey, innerNonce);
            return _inner.Open(subKey, innerNonce, ciphertext, tag, associatedData, plaintext);
        }

        // Split the 24-byte XNonce: subKey = HChaCha20(key, nonce[0:16]); innerNonce = 0^4 || nonce[16:24].
        static void Derive(ReadOnlySpan<byte> key, ReadOnlySpan<byte> nonce, Span<byte> subKey, Span<byte> innerNonce)
        {
            if (key.Length != KeyBytes) throw new ArgumentException("key must be 32 bytes", nameof(key));
            if (nonce.Length != NonceBytes) throw new ArgumentException("nonce must be 24 bytes", nameof(nonce));

            HChaCha20(key, nonce.Slice(0, 16), subKey);
            innerNonce.Slice(0, 4).Clear();
            nonce.Slice(16, 8).CopyTo(innerNonce.Slice(4));
        }

        // ---- HChaCha20 (draft-irtf-cfrg-xchacha §2.2): keyless 32-byte subkey derivation ----

        // ChaCha "expand 32-byte k" constants, little-endian words.
        const uint C0 = 0x61707865, C1 = 0x3320646e, C2 = 0x79622d32, C3 = 0x6b206574;

        /// <summary>
        /// Computes the 32-byte HChaCha20 subkey from a 32-byte <paramref name="key"/> and a 16-byte
        /// <paramref name="nonce16"/>. Runs the 20-round ChaCha20 core (no final word addition) and emits words 0–3
        /// and 12–15 of the result.
        /// </summary>
        public static void HChaCha20(ReadOnlySpan<byte> key, ReadOnlySpan<byte> nonce16, Span<byte> output32)
        {
            Span<uint> s = stackalloc uint[16];
            s[0] = C0; s[1] = C1; s[2] = C2; s[3] = C3;
            for (int i = 0; i < 8; i++) s[4 + i] = BinaryPrimitives.ReadUInt32LittleEndian(key.Slice(i * 4, 4));
            for (int i = 0; i < 4; i++) s[12 + i] = BinaryPrimitives.ReadUInt32LittleEndian(nonce16.Slice(i * 4, 4));

            for (int round = 0; round < 10; round++)
            {
                // Column rounds.
                QuarterRound(s, 0, 4, 8, 12);
                QuarterRound(s, 1, 5, 9, 13);
                QuarterRound(s, 2, 6, 10, 14);
                QuarterRound(s, 3, 7, 11, 15);
                // Diagonal rounds.
                QuarterRound(s, 0, 5, 10, 15);
                QuarterRound(s, 1, 6, 11, 12);
                QuarterRound(s, 2, 7, 8, 13);
                QuarterRound(s, 3, 4, 9, 14);
            }

            // HChaCha20 output = words 0..3 followed by words 12..15 (no addition of the initial state).
            for (int i = 0; i < 4; i++) BinaryPrimitives.WriteUInt32LittleEndian(output32.Slice(i * 4, 4), s[i]);
            for (int i = 0; i < 4; i++) BinaryPrimitives.WriteUInt32LittleEndian(output32.Slice(16 + i * 4, 4), s[12 + i]);
        }

        static void QuarterRound(Span<uint> s, int a, int b, int c, int d)
        {
            s[a] += s[b]; s[d] = RotateLeft(s[d] ^ s[a], 16);
            s[c] += s[d]; s[b] = RotateLeft(s[b] ^ s[c], 12);
            s[a] += s[b]; s[d] = RotateLeft(s[d] ^ s[a], 8);
            s[c] += s[d]; s[b] = RotateLeft(s[b] ^ s[c], 7);
        }

        static uint RotateLeft(uint value, int bits) => (value << bits) | (value >> (32 - bits));
    }
}
