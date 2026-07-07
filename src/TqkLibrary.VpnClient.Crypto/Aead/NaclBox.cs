using TqkLibrary.VpnClient.Crypto.Noise;

namespace TqkLibrary.VpnClient.Crypto.Aead
{
    /// <summary>
    /// NaCl <c>crypto_box</c> (Bernstein) — public-key authenticated encryption =
    /// <c>crypto_box_curve25519xsalsa20poly1305</c>. It layers the X25519 Diffie-Hellman
    /// (<see cref="Curve25519DhGroup"/>) over the symmetric NaCl <c>crypto_secretbox</c>
    /// (<see cref="XSalsa20Poly1305Cipher"/>): a sender who knows their own 32-byte secret key and the
    /// receiver's 32-byte public key derives a shared "beforenm" key, then seals the message under it.
    /// <para>
    /// The beforenm key is <c>HSalsa20(X25519(mySecret, theirPublic), 0^16)</c> — the 32-byte DH shared secret
    /// fed through the keyless <see cref="HSalsa20"/> core with a 16-byte all-zero input (NaCl
    /// <c>crypto_box_beforenm</c>). <see cref="Box"/> then equals <c>crypto_secretbox(message, nonce, beforenm)</c>,
    /// so the output layout is <c>tag(16) ‖ ciphertext</c> (libsodium <c>crypto_box_easy</c>); <see cref="Open"/> is the
    /// inverse with constant-time tag verification. Completes the NaCl family — unlocks Quicktun <c>nacltai</c> and
    /// cjdns CryptoAuth (both Curve25519 + XSalsa20-Poly1305). Verified byte-exact against the NaCl <c>tests/box.c</c>
    /// vector (see NaclBoxTests).
    /// </para>
    /// </summary>
    public static class NaclBox
    {
        /// <summary>crypto_box public-key length in bytes (Curve25519 point).</summary>
        public const int PublicKeyBytes = 32;

        /// <summary>crypto_box secret-key length in bytes (X25519 scalar).</summary>
        public const int SecretKeyBytes = 32;

        /// <summary>Shared "beforenm" key length in bytes (also the secretbox key length).</summary>
        public const int BeforeNmBytes = 32;

        /// <summary>crypto_box nonce length in bytes (192-bit / 24 bytes).</summary>
        public const int NonceBytes = XSalsa20Poly1305Cipher.NonceBytes;

        /// <summary>crypto_box authentication tag length in bytes.</summary>
        public const int TagBytes = XSalsa20Poly1305Cipher.TagBytes;

        // Reuse the existing X25519 DH implementation (BouncyCastle Rfc7748.X25519 under the hood) rather than
        // re-deriving scalar-mult here — same primitive the Noise/WireGuard stack already relies on.
        static readonly Curve25519DhGroup Dh = new Curve25519DhGroup();

        /// <summary>
        /// Computes the shared "beforenm" key <c>HSalsa20(X25519(<paramref name="mySecret"/>, <paramref name="theirPublic"/>), 0^16)</c>
        /// (NaCl <c>crypto_box_beforenm</c>) — precomputing this lets many messages to the same peer skip the DH.
        /// </summary>
        public static byte[] BeforeNm(ReadOnlySpan<byte> theirPublic, ReadOnlySpan<byte> mySecret)
        {
            if (theirPublic.Length != PublicKeyBytes) throw new ArgumentException($"crypto_box public key must be {PublicKeyBytes} bytes.", nameof(theirPublic));
            if (mySecret.Length != SecretKeyBytes) throw new ArgumentException($"crypto_box secret key must be {SecretKeyBytes} bytes.", nameof(mySecret));

            byte[] shared = Dh.DeriveSharedSecret(mySecret, theirPublic); // X25519 scalar-mult (RFC 7748)
            byte[] beforeNm = new byte[BeforeNmBytes];
            Span<byte> zero16 = stackalloc byte[HSalsa20.InputBytes]; // 16 zero bytes
            HSalsa20.Hash(shared, zero16, beforeNm);
            return beforeNm;
        }

        /// <summary>
        /// Seals <paramref name="plaintext"/> to the holder of <paramref name="theirPublic"/> using
        /// <paramref name="mySecret"/> and the 24-byte <paramref name="nonce"/>, returning
        /// <c>tag(16) ‖ ciphertext</c> (NaCl <c>crypto_box</c> / libsodium <c>crypto_box_easy</c>).
        /// </summary>
        public static byte[] Box(ReadOnlySpan<byte> plaintext, ReadOnlySpan<byte> nonce, ReadOnlySpan<byte> theirPublic, ReadOnlySpan<byte> mySecret)
            => BoxAfterNm(plaintext, nonce, BeforeNm(theirPublic, mySecret));

        /// <summary>
        /// Seals <paramref name="plaintext"/> under a precomputed <paramref name="beforeNm"/> shared key and the
        /// 24-byte <paramref name="nonce"/> (NaCl <c>crypto_box_afternm</c>) — identical to
        /// <c>crypto_secretbox(plaintext, nonce, beforeNm)</c>.
        /// </summary>
        public static byte[] BoxAfterNm(ReadOnlySpan<byte> plaintext, ReadOnlySpan<byte> nonce, ReadOnlySpan<byte> beforeNm)
            => XSalsa20Poly1305Cipher.Seal(beforeNm, nonce, plaintext);

        /// <summary>
        /// Opens a <c>tag(16) ‖ ciphertext</c> <paramref name="boxed"/> message from the holder of
        /// <paramref name="theirPublic"/> using <paramref name="mySecret"/> and the 24-byte <paramref name="nonce"/>.
        /// Returns <see langword="false"/> (with <paramref name="plaintext"/> empty) on a bad tag or short input.
        /// </summary>
        public static bool Open(ReadOnlySpan<byte> boxed, ReadOnlySpan<byte> nonce, ReadOnlySpan<byte> theirPublic, ReadOnlySpan<byte> mySecret, out byte[] plaintext)
            => OpenAfterNm(boxed, nonce, BeforeNm(theirPublic, mySecret), out plaintext);

        /// <summary>
        /// Opens a <c>tag(16) ‖ ciphertext</c> <paramref name="boxed"/> message under a precomputed
        /// <paramref name="beforeNm"/> shared key and the 24-byte <paramref name="nonce"/> (NaCl
        /// <c>crypto_box_open_afternm</c>). Returns <see langword="false"/> on a bad tag or short input.
        /// </summary>
        public static bool OpenAfterNm(ReadOnlySpan<byte> boxed, ReadOnlySpan<byte> nonce, ReadOnlySpan<byte> beforeNm, out byte[] plaintext)
        {
            plaintext = Array.Empty<byte>();
            if (boxed.Length < TagBytes) return false;
            return XSalsa20Poly1305Cipher.Open(beforeNm, nonce, boxed.Slice(0, TagBytes), boxed.Slice(TagBytes), out plaintext);
        }
    }
}
