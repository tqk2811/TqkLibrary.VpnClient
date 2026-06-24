using TqkLibrary.VpnClient.Crypto.Abstractions.Interfaces;
// Alias the one BouncyCastle type rather than importing Org.BouncyCastle.* wholesale (its Crypto namespace defines
// types that clash with this project's interfaces — see Curve25519DhGroup for the same pattern). Neither TFM's BCL
// ships Ed25519 in a span-friendly raw-key form, so BouncyCastle is used on net8.0 and netstandard2.0 alike.
using BcEd25519 = Org.BouncyCastle.Math.EC.Rfc8032.Ed25519;

namespace TqkLibrary.VpnClient.Crypto.Noise
{
    /// <summary>
    /// Ed25519 (PureEdDSA, RFC 8032) signatures exposed as an <see cref="ISignatureAlgo"/>: 32-byte private and public
    /// keys, 64-byte signatures, no pre-hash (the message is signed directly — matching Go's <c>crypto/ed25519</c>).
    /// Used to verify Nebula certificate signatures (V.7.1): the CA signs the marshaled certificate details with its
    /// Ed25519 key. Stateless; backed by BouncyCastle on both target frameworks.
    /// </summary>
    public sealed class Ed25519Signer : ISignatureAlgo
    {
        const int PrivateKeySize = 32; // RFC 8032 seed (BouncyCastle SecretKeySize)
        const int PublicKeySize = 32;  // BouncyCastle PublicKeySize
        const int SignatureSize = 64;  // BouncyCastle SignatureSize

        /// <inheritdoc/>
        public int PrivateKeySizeInBytes => PrivateKeySize;

        /// <inheritdoc/>
        public int PublicKeySizeInBytes => PublicKeySize;

        /// <inheritdoc/>
        public int SignatureSizeInBytes => SignatureSize;

        /// <inheritdoc/>
        public byte[] DerivePublicKey(ReadOnlySpan<byte> privateKey)
        {
            if (privateKey.Length != PrivateKeySize)
                throw new ArgumentException($"Ed25519 private key must be {PrivateKeySize} bytes.", nameof(privateKey));
            byte[] sk = privateKey.ToArray();
            byte[] pk = new byte[PublicKeySize];
            BcEd25519.GeneratePublicKey(sk, 0, pk, 0);
            return pk;
        }

        /// <inheritdoc/>
        public byte[] Sign(ReadOnlySpan<byte> privateKey, ReadOnlySpan<byte> message)
        {
            if (privateKey.Length != PrivateKeySize)
                throw new ArgumentException($"Ed25519 private key must be {PrivateKeySize} bytes.", nameof(privateKey));
            byte[] sk = privateKey.ToArray();
            byte[] msg = message.ToArray();
            byte[] sig = new byte[SignatureSize];
            BcEd25519.Sign(sk, 0, msg, 0, msg.Length, sig, 0);
            return sig;
        }

        /// <inheritdoc/>
        public bool Verify(ReadOnlySpan<byte> publicKey, ReadOnlySpan<byte> message, ReadOnlySpan<byte> signature)
        {
            if (publicKey.Length != PublicKeySize) return false;
            if (signature.Length != SignatureSize) return false;
            byte[] pk = publicKey.ToArray();
            byte[] msg = message.ToArray();
            byte[] sig = signature.ToArray();
            return BcEd25519.Verify(sig, 0, pk, 0, msg, 0, msg.Length);
        }
    }
}
