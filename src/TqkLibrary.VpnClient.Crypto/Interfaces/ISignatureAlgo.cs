namespace TqkLibrary.VpnClient.Crypto.Abstractions.Interfaces
{
    /// <summary>
    /// A public-key signature scheme (Ed25519, ECDSA-P256...) used to authenticate certificates and handshakes.
    /// Implementations are stateless; the key material is passed per call.
    /// </summary>
    public interface ISignatureAlgo
    {
        /// <summary>Size of a private (signing) key in bytes.</summary>
        int PrivateKeySizeInBytes { get; }

        /// <summary>Size of a public (verifying) key in bytes.</summary>
        int PublicKeySizeInBytes { get; }

        /// <summary>Size of a signature in bytes (fixed-length schemes only — e.g. Ed25519 = 64).</summary>
        int SignatureSizeInBytes { get; }

        /// <summary>Derives the public key from a private key.</summary>
        byte[] DerivePublicKey(ReadOnlySpan<byte> privateKey);

        /// <summary>Signs <paramref name="message"/> with <paramref name="privateKey"/>, returning the signature.</summary>
        byte[] Sign(ReadOnlySpan<byte> privateKey, ReadOnlySpan<byte> message);

        /// <summary>Verifies <paramref name="signature"/> over <paramref name="message"/> under <paramref name="publicKey"/>.</summary>
        bool Verify(ReadOnlySpan<byte> publicKey, ReadOnlySpan<byte> message, ReadOnlySpan<byte> signature);
    }
}
