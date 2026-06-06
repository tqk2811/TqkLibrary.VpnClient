using System.Security.Cryptography;
using TqkLibrary.Vpn.Crypto.Abstractions.Interfaces;

namespace TqkLibrary.Vpn.Crypto
{
    /// <summary>
    /// AES in cipher-block-chaining (CBC) mode with no padding (RFC 3602). The caller supplies plaintext that is
    /// already a multiple of the 16-byte block size — ESP/IKE do their own padding, so padding here is the caller's job.
    /// </summary>
    public sealed class AesCbcCipher : IBlockCipher
    {
        /// <inheritdoc/>
        public int BlockSizeInBytes => 16;

        /// <inheritdoc/>
        public int Encrypt(ReadOnlySpan<byte> key, ReadOnlySpan<byte> iv, ReadOnlySpan<byte> plaintext, Span<byte> ciphertext)
        {
            byte[] result = Transform(key, iv, plaintext.ToArray(), encrypt: true);
            result.CopyTo(ciphertext);
            return result.Length;
        }

        /// <inheritdoc/>
        public int Decrypt(ReadOnlySpan<byte> key, ReadOnlySpan<byte> iv, ReadOnlySpan<byte> ciphertext, Span<byte> plaintext)
        {
            byte[] result = Transform(key, iv, ciphertext.ToArray(), encrypt: false);
            result.CopyTo(plaintext);
            return result.Length;
        }

        static byte[] Transform(ReadOnlySpan<byte> key, ReadOnlySpan<byte> iv, byte[] data, bool encrypt)
        {
            if (iv.Length != 16) throw new ArgumentException("CBC IV must be 16 bytes.", nameof(iv));
            if (data.Length % 16 != 0) throw new ArgumentException("CBC data must be a multiple of 16 bytes.", nameof(data));

            using Aes aes = Aes.Create();
            aes.Mode = CipherMode.CBC;
            aes.Padding = PaddingMode.None;
            aes.Key = key.ToArray();
            aes.IV = iv.ToArray();
            using ICryptoTransform transform = encrypt ? aes.CreateEncryptor() : aes.CreateDecryptor();
            return transform.TransformFinalBlock(data, 0, data.Length);
        }
    }
}
