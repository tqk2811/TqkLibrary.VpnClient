namespace TqkLibrary.Vpn.Crypto.Abstractions.Interfaces
{
    /// <summary>A Diffie-Hellman group (MODP group 2/14, or ECDH later) for IKE key agreement.</summary>
    public interface IDhGroup
    {
        /// <summary>IANA DH group number (2, 14, 19...).</summary>
        int GroupId { get; }

        /// <summary>Size of the wire-format public value in bytes.</summary>
        int PublicValueSizeInBytes { get; }

        /// <summary>Generates a fresh private key.</summary>
        byte[] GeneratePrivateKey();

        /// <summary>Derives the public value to send to the peer.</summary>
        byte[] DerivePublicValue(ReadOnlySpan<byte> privateKey);

        /// <summary>Computes the shared secret from our private key and the peer's public value.</summary>
        byte[] DeriveSharedSecret(ReadOnlySpan<byte> privateKey, ReadOnlySpan<byte> peerPublicValue);
    }
}
