using TqkLibrary.Vpn.Crypto.Abstractions.Interfaces;
#if NET8_0_OR_GREATER
using System.Security.Cryptography;
#else
using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Crypto.Modes;
using Org.BouncyCastle.Crypto.Parameters;
#endif

namespace TqkLibrary.Vpn.Crypto.Aead
{
    /// <summary>
    /// AES-GCM AEAD. Uses the native <c>AesGcm</c> on net8.0 and a BouncyCastle fallback on netstandard2.0
    /// (where the BCL has no AES-GCM). 12-byte nonce, 16-byte tag.
    /// </summary>
    public sealed class AesGcmCipher : IAeadCipher
    {
        const int TagBytes = 16;
        const int NonceBytes = 12;

        /// <summary>Creates an AES-GCM cipher for the given key size (16/24/32 bytes; default 32 = AES-256).</summary>
        public AesGcmCipher(int keySizeInBytes = 32)
        {
            if (keySizeInBytes != 16 && keySizeInBytes != 24 && keySizeInBytes != 32)
                throw new ArgumentOutOfRangeException(nameof(keySizeInBytes));
            KeySizeInBytes = keySizeInBytes;
        }

        /// <inheritdoc/>
        public int KeySizeInBytes { get; }

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
#if NET8_0_OR_GREATER
            using var gcm = new AesGcm(key, TagBytes);
            gcm.Encrypt(nonce, plaintext, ciphertext.Slice(0, plaintext.Length), tag.Slice(0, TagBytes), associatedData);
#else
            var cipher = new GcmBlockCipher(new AesEngine());
            cipher.Init(true, new AeadParameters(new KeyParameter(key.ToArray()), TagBytes * 8, nonce.ToArray(), associatedData.ToArray()));
            byte[] input = plaintext.ToArray();
            byte[] output = new byte[cipher.GetOutputSize(input.Length)];
            int len = cipher.ProcessBytes(input, 0, input.Length, output, 0);
            cipher.DoFinal(output, len);
            // output = ciphertext || tag
            output.AsSpan(0, plaintext.Length).CopyTo(ciphertext);
            output.AsSpan(plaintext.Length, TagBytes).CopyTo(tag);
#endif
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
#if NET8_0_OR_GREATER
            try
            {
                using var gcm = new AesGcm(key, TagBytes);
                gcm.Decrypt(nonce, ciphertext, tag.Slice(0, TagBytes), plaintext.Slice(0, ciphertext.Length), associatedData);
                return true;
            }
            catch (AuthenticationTagMismatchException)
            {
                return false;
            }
#else
            var cipher = new GcmBlockCipher(new AesEngine());
            cipher.Init(false, new AeadParameters(new KeyParameter(key.ToArray()), TagBytes * 8, nonce.ToArray(), associatedData.ToArray()));
            byte[] input = new byte[ciphertext.Length + TagBytes];
            ciphertext.CopyTo(input);
            tag.Slice(0, TagBytes).CopyTo(input.AsSpan(ciphertext.Length));
            byte[] output = new byte[cipher.GetOutputSize(input.Length)];
            try
            {
                int len = cipher.ProcessBytes(input, 0, input.Length, output, 0);
                len += cipher.DoFinal(output, len);
                output.AsSpan(0, len).CopyTo(plaintext);
                return true;
            }
            catch (Org.BouncyCastle.Crypto.InvalidCipherTextException)
            {
                return false;
            }
#endif
        }
    }
}
