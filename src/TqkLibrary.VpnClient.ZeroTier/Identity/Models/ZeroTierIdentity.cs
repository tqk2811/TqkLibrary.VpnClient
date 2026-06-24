namespace TqkLibrary.VpnClient.ZeroTier.Identity.Models
{
    /// <summary>
    /// A ZeroTier V1 (x25519) identity: a 40-bit <see cref="Address"/> bound to a 64-byte combined public key
    /// (32-byte Curve25519 ECDH key || 32-byte Ed25519 signing key). The private key, when present, mirrors that
    /// layout (32-byte Curve25519 secret || 32-byte Ed25519 secret).
    /// <para>
    /// The address is not free: it is the output of a deliberately expensive memory-hard hash over the public key
    /// (see <c>ZeroTierAddressDerivation</c>), which binds key to address and makes address forgery costly.
    /// </para>
    /// </summary>
    public sealed class ZeroTierIdentity
    {
        /// <summary>Combined public-key length (32 C25519 + 32 Ed25519).</summary>
        public const int PublicKeySize = 64;

        /// <summary>Combined private-key length (32 C25519 + 32 Ed25519).</summary>
        public const int PrivateKeySize = 64;

        /// <summary>The 40-bit node address derived from <see cref="PublicKey"/>.</summary>
        public ZeroTierAddress Address { get; set; }

        /// <summary>The 64-byte combined public key (Curve25519 ECDH || Ed25519 signing).</summary>
        public byte[] PublicKey { get; set; } = Array.Empty<byte>();

        /// <summary>The 64-byte combined private key, or null for a public-only identity.</summary>
        public byte[]? PrivateKey { get; set; }

        /// <summary>True if this identity carries its secret key material.</summary>
        public bool HasPrivate => PrivateKey is { Length: PrivateKeySize };

        /// <summary>The 32-byte Curve25519 public key (first half of <see cref="PublicKey"/>).</summary>
        public ReadOnlySpan<byte> Curve25519Public =>
            PublicKey.Length == PublicKeySize ? PublicKey.AsSpan(0, 32) : throw new InvalidOperationException("public key not set");

        /// <summary>The 32-byte Ed25519 public key (second half of <see cref="PublicKey"/>).</summary>
        public ReadOnlySpan<byte> Ed25519Public =>
            PublicKey.Length == PublicKeySize ? PublicKey.AsSpan(32, 32) : throw new InvalidOperationException("public key not set");

        /// <summary>The 32-byte Curve25519 private key (first half of <see cref="PrivateKey"/>).</summary>
        public ReadOnlySpan<byte> Curve25519Private =>
            HasPrivate ? PrivateKey.AsSpan(0, 32) : throw new InvalidOperationException("private key not set");

        /// <summary>The 32-byte Ed25519 private key (second half of <see cref="PrivateKey"/>).</summary>
        public ReadOnlySpan<byte> Ed25519Private =>
            HasPrivate ? PrivateKey.AsSpan(32, 32) : throw new InvalidOperationException("private key not set");
    }
}
