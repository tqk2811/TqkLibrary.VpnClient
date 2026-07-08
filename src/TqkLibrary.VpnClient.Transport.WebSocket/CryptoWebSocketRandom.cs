using System.Security.Cryptography;

namespace TqkLibrary.VpnClient.Transport.WebSocket
{
    /// <summary>
    /// Default <see cref="IWebSocketRandom"/>: cryptographically-strong bytes from
    /// <see cref="RandomNumberGenerator"/> for the handshake key and per-frame masking keys.
    /// </summary>
    public sealed class CryptoWebSocketRandom : IWebSocketRandom
    {
        /// <summary>A shared, thread-safe instance (the underlying RNG is created per call).</summary>
        public static CryptoWebSocketRandom Default { get; } = new CryptoWebSocketRandom();

        /// <inheritdoc/>
        public byte[] NextBytes(int count)
        {
            byte[] buffer = new byte[count];
            if (count > 0)
            {
                using var rng = RandomNumberGenerator.Create();
                rng.GetBytes(buffer);
            }
            return buffer;
        }
    }
}
