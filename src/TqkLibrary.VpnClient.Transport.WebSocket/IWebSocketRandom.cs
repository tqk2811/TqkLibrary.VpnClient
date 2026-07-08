namespace TqkLibrary.VpnClient.Transport.WebSocket
{
    /// <summary>
    /// The source of randomness the WebSocket transport draws on for the handshake <c>Sec-WebSocket-Key</c> (16 bytes)
    /// and the per-frame 4-byte masking key (RFC 6455 §5.3). Injectable so a deterministic fake can pin exact bytes in
    /// tests; the default (<see cref="CryptoWebSocketRandom"/>) draws from
    /// <see cref="System.Security.Cryptography.RandomNumberGenerator"/> so real keys are unpredictable.
    /// </summary>
    public interface IWebSocketRandom
    {
        /// <summary>Returns <paramref name="count"/> fresh random bytes (a zero-length array when <paramref name="count"/> is 0).</summary>
        byte[] NextBytes(int count);
    }
}
