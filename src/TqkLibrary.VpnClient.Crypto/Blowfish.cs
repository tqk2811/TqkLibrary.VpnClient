// Alias the one BouncyCastle engine rather than importing Org.BouncyCastle.* wholesale (its Crypto namespace defines
// types — IBlockCipher, etc. — that clash with this project's interfaces; see Salsa20 / Curve25519DhGroup for the same
// aliasing pattern). The BCL ships no Blowfish on either target framework, so BouncyCastle is used on net8.0 and
// netstandard2.0 alike (no #if split).
using BlowfishEngine = Org.BouncyCastle.Crypto.Engines.BlowfishEngine;
using KeyParameter = Org.BouncyCastle.Crypto.Parameters.KeyParameter;

namespace TqkLibrary.VpnClient.Crypto
{
    /// <summary>
    /// Blowfish block cipher (Schneier) in raw <b>ECB</b> mode — no chaining, no padding, processed one 8-byte block at a
    /// time. The variable-length key is fed verbatim to OpenSSL-compatible Blowfish key scheduling (BouncyCastle's
    /// <c>BlowfishEngine</c> matches OpenSSL's <c>BF_set_key</c>/<c>BF_ecb_encrypt</c> big-endian block I/O).
    /// <para>
    /// Used by the legacy <b>vtun</b> challenge-response authentication (V.11): the 16-byte challenge is encrypted with
    /// key = <c>MD5(password)</c> in two 8-byte ECB blocks. ⚠️ Blowfish-ECB is cryptographically weak (no chaining, no
    /// authentication); it exists here only to interoperate with the legacy vtund daemon, never as a recommended cipher.
    /// </para>
    /// </summary>
    public sealed class Blowfish
    {
        /// <summary>The Blowfish block size in bytes (8).</summary>
        public const int BlockSizeInBytes = 8;

        readonly KeyParameter _key;

        /// <summary>Creates a Blowfish instance keyed with <paramref name="key"/> (1..56 bytes; vtun uses a 16-byte MD5 digest).</summary>
        public Blowfish(ReadOnlySpan<byte> key)
        {
            if (key.Length == 0) throw new ArgumentException("Blowfish key must be at least 1 byte.", nameof(key));
            _key = new KeyParameter(key.ToArray());
        }

        /// <summary>Encrypts <paramref name="data"/> in place, ECB, block by block. Length must be a multiple of 8.</summary>
        public void EncryptEcb(Span<byte> data) => TransformEcb(data, encrypt: true);

        /// <summary>Decrypts <paramref name="data"/> in place, ECB, block by block. Length must be a multiple of 8.</summary>
        public void DecryptEcb(Span<byte> data) => TransformEcb(data, encrypt: false);

        void TransformEcb(Span<byte> data, bool encrypt)
        {
            if (data.Length % BlockSizeInBytes != 0)
                throw new ArgumentException($"Blowfish-ECB data must be a multiple of {BlockSizeInBytes} bytes.", nameof(data));

            var engine = new BlowfishEngine();
            engine.Init(encrypt, _key);

            // BouncyCastle's BlockCipher operates on byte[] with offsets; copy out, transform, copy back. The buffers are
            // tiny (the vtun challenge is 16 bytes), so the allocation is negligible.
            byte[] buffer = data.ToArray();
            for (int offset = 0; offset < buffer.Length; offset += BlockSizeInBytes)
                engine.ProcessBlock(buffer, offset, buffer, offset);
            buffer.CopyTo(data);
        }
    }
}
