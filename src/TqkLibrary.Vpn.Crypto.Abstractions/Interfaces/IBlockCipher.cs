namespace TqkLibrary.Vpn.Crypto.Abstractions.Interfaces
{
    /// <summary>A keyed symmetric cipher with an IV (AES-CBC/CTR, DES). Not authenticated — see <see cref="IAeadCipher"/>.</summary>
    public interface IBlockCipher
    {
        /// <summary>Cipher block size in bytes.</summary>
        int BlockSizeInBytes { get; }

        /// <summary>Encrypts <paramref name="plaintext"/> into <paramref name="ciphertext"/>; returns bytes written.</summary>
        int Encrypt(ReadOnlySpan<byte> key, ReadOnlySpan<byte> iv, ReadOnlySpan<byte> plaintext, Span<byte> ciphertext);

        /// <summary>Decrypts <paramref name="ciphertext"/> into <paramref name="plaintext"/>; returns bytes written.</summary>
        int Decrypt(ReadOnlySpan<byte> key, ReadOnlySpan<byte> iv, ReadOnlySpan<byte> ciphertext, Span<byte> plaintext);
    }
}
