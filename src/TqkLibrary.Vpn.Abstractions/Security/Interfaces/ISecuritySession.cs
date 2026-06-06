namespace TqkLibrary.Vpn.Abstractions.Security.Interfaces
{
    /// <summary>
    /// The crypto layer of a driver: TLS, IPsec-ESP, Noise, MPPE, or null. Performs its handshake then
    /// protects/unprotects packets. Implementations own their own keying and rekey schedule.
    /// </summary>
    public interface ISecuritySession : IAsyncDisposable
    {
        /// <summary>Runs the security handshake (e.g. IKE, TLS, Noise) to derive keys.</summary>
        ValueTask PerformHandshakeAsync(CancellationToken cancellationToken = default);

        /// <summary>Encrypts/authenticates <paramref name="plaintext"/> into <paramref name="output"/>; returns bytes written.</summary>
        int Protect(ReadOnlySpan<byte> plaintext, Span<byte> output);

        /// <summary>Verifies/decrypts <paramref name="protectedData"/> into <paramref name="output"/>; returns bytes written, or -1 on auth failure.</summary>
        int Unprotect(ReadOnlySpan<byte> protectedData, Span<byte> output);
    }
}
