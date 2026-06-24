using System.Security.Cryptography;
using TqkLibrary.VpnClient.Crypto.Abstractions.Interfaces;

namespace TqkLibrary.VpnClient.Crypto
{
    /// <summary>
    /// SHA-256 (FIPS 180-4) one-shot hash exposed as an <see cref="IHashAlgo"/> (32-byte digest). Backed by the BCL
    /// <see cref="SHA256"/> on both target frameworks. Used as the Noise transcript hash for the
    /// <c>Noise_IX_25519_AESGCM_SHA256</c> handshake (Nebula, V.7.1) — unlike WireGuard's BLAKE2s.
    /// </summary>
    public sealed class Sha256Hash : IHashAlgo
    {
        /// <inheritdoc/>
        public int HashSizeInBytes => 32;

        /// <inheritdoc/>
        public void ComputeHash(ReadOnlySpan<byte> input, Span<byte> destination)
        {
#if NET5_0_OR_GREATER
            SHA256.HashData(input, destination);
#else
            using var sha = SHA256.Create();
            byte[] digest = sha.ComputeHash(input.ToArray());
            digest.AsSpan(0, HashSizeInBytes).CopyTo(destination);
#endif
        }
    }
}
