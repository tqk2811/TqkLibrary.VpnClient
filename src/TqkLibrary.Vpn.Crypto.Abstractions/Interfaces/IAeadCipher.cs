namespace TqkLibrary.Vpn.Crypto.Abstractions.Interfaces
{
    /// <summary>An AEAD cipher (AES-GCM, ChaCha20-Poly1305). Hides the netstandard2.0 vs net8.0 implementation split.</summary>
    public interface IAeadCipher
    {
        /// <summary>Key length in bytes.</summary>
        int KeySizeInBytes { get; }

        /// <summary>Nonce/IV length in bytes.</summary>
        int NonceSizeInBytes { get; }

        /// <summary>Authentication tag length in bytes.</summary>
        int TagSizeInBytes { get; }

        /// <summary>Encrypts + authenticates: writes ciphertext (same length as plaintext) and the tag.</summary>
        void Seal(
            ReadOnlySpan<byte> key,
            ReadOnlySpan<byte> nonce,
            ReadOnlySpan<byte> plaintext,
            ReadOnlySpan<byte> associatedData,
            Span<byte> ciphertext,
            Span<byte> tag);

        /// <summary>Verifies the tag and decrypts. Returns false (without writing plaintext) if authentication fails.</summary>
        bool Open(
            ReadOnlySpan<byte> key,
            ReadOnlySpan<byte> nonce,
            ReadOnlySpan<byte> ciphertext,
            ReadOnlySpan<byte> tag,
            ReadOnlySpan<byte> associatedData,
            Span<byte> plaintext);
    }
}
