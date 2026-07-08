using System;
using System.Security.Cryptography;
using TqkLibrary.VpnClient.Crypto.Abstractions.Interfaces;
// Import only targeted BouncyCastle types (via aliases) rather than the whole Org.BouncyCastle.Crypto
// namespace, whose IAeadCipher would clash with this project's interface (see Aead/*.cs). Neither TFM's BCL
// exposes raw P-256 scalar-mult / ECDH agreement, so BouncyCastle is used on net8.0 and netstandard2.0 alike
// (no #if split, same as Noise/Curve25519DhGroup.cs).
using BcBigInteger = Org.BouncyCastle.Math.BigInteger;
using BigIntegers = Org.BouncyCastle.Utilities.BigIntegers;
using CustomNamedCurves = Org.BouncyCastle.Crypto.EC.CustomNamedCurves;
using ECPoint = Org.BouncyCastle.Math.EC.ECPoint;
using X9ECParameters = Org.BouncyCastle.Asn1.X9.X9ECParameters;

namespace TqkLibrary.VpnClient.Crypto
{
    /// <summary>
    /// ECDH on the NIST P-256 curve (secp256r1 / prime256v1) exposed as an <see cref="IDhGroup"/> — IANA
    /// DH group 19, the "256-bit Random ECP Group" of RFC 5903. The wire public value is the raw affine point
    /// <c>x ‖ y</c> (each 32 bytes, 64 total, WITHOUT the 0x04 point-format prefix, per RFC 5903 §7), and the
    /// shared secret is the x-coordinate of the common point g^ir (32 bytes, RFC 5903 §9). Foundation for
    /// Nebula P-256 networks and FreeLAN FSCP ECDHE.
    /// </summary>
    public sealed class NistP256DhGroup : IDhGroup
    {
        const int ScalarSize = 32;      // private key scalar (matches curve order byte length)
        const int CoordinateSize = 32;  // one field element (x or y)
        const int PublicSize = 64;      // x ‖ y on the wire (no 0x04 prefix)

        // P-256 domain parameters. CustomNamedCurves uses the optimised field arithmetic; identical curve to
        // secp256r1. Loaded once — X9ECParameters is immutable and safe to share.
        static readonly X9ECParameters _curve = CustomNamedCurves.GetByName("P-256");
        static readonly BcBigInteger _n = _curve.N; // group order

        /// <inheritdoc/>
        public int GroupId => 19;

        /// <inheritdoc/>
        public int PublicValueSizeInBytes => PublicSize;

        /// <inheritdoc/>
        public byte[] GeneratePrivateKey()
        {
            // A uniformly random scalar in [1, n-1] (rejection sampling on the full 32-byte range).
            byte[] buf = new byte[ScalarSize];
            BcBigInteger d;
            using (var rng = RandomNumberGenerator.Create())
            {
                do
                {
                    rng.GetBytes(buf);
                    d = new BcBigInteger(1, buf); // positive, big-endian magnitude
                }
                while (d.SignValue == 0 || d.CompareTo(_n) >= 0);
            }
            return BigIntegers.AsUnsignedByteArray(ScalarSize, d);
        }

        /// <inheritdoc/>
        public byte[] DerivePublicValue(ReadOnlySpan<byte> privateKey)
        {
            BcBigInteger d = ParsePrivateScalar(privateKey);
            ECPoint q = _curve.G.Multiply(d).Normalize();
            // GetEncoded(false) = 0x04 ‖ x(32) ‖ y(32); RFC 5903 §7 puts only x‖y on the wire, so drop the prefix.
            byte[] encoded = q.GetEncoded(false);
            byte[] result = new byte[PublicSize];
            Array.Copy(encoded, 1, result, 0, PublicSize);
            return result;
        }

        /// <inheritdoc/>
        public byte[] DeriveSharedSecret(ReadOnlySpan<byte> privateKey, ReadOnlySpan<byte> peerPublicValue)
        {
            BcBigInteger d = ParsePrivateScalar(privateKey);
            if (peerPublicValue.Length != PublicSize)
                throw new ArgumentException($"P-256 public value must be {PublicSize} bytes (x‖y).", nameof(peerPublicValue));

            ECPoint peer = DecodePeerPoint(peerPublicValue);
            ECPoint shared = peer.Multiply(d).Normalize();
            if (shared.IsInfinity)
                throw new ArgumentException("P-256 ECDH produced the point at infinity.", nameof(peerPublicValue));
            // Shared secret = x-coordinate only (RFC 5903 §9); GetEncoded pads to the fixed 32-byte field width.
            return shared.AffineXCoord.GetEncoded();
        }

        static BcBigInteger ParsePrivateScalar(ReadOnlySpan<byte> privateKey)
        {
            if (privateKey.Length != ScalarSize)
                throw new ArgumentException($"P-256 private key must be {ScalarSize} bytes.", nameof(privateKey));
            BcBigInteger d = new BcBigInteger(1, privateKey.ToArray());
            if (d.SignValue == 0 || d.CompareTo(_n) >= 0)
                throw new ArgumentException("P-256 private key must be in [1, n-1].", nameof(privateKey));
            return d;
        }

        static ECPoint DecodePeerPoint(ReadOnlySpan<byte> peer64)
        {
            // Rebuild the 0x04-prefixed uncompressed encoding BouncyCastle expects, then decode.
            byte[] encoded = new byte[1 + PublicSize];
            encoded[0] = 0x04;
            peer64.CopyTo(encoded.AsSpan(1));

            ECPoint point;
            try
            {
                // DecodePoint validates that the coordinates lie on the curve (throws ArgumentException otherwise).
                point = _curve.Curve.DecodePoint(encoded);
            }
            catch (Exception ex) when (!(ex is ArgumentException))
            {
                throw new ArgumentException("Peer public value is not a valid P-256 point.", nameof(peer64), ex);
            }
            // Explicit on-curve / subgroup check (P-256 cofactor is 1, so any on-curve point is valid).
            if (!point.IsValid())
                throw new ArgumentException("Peer public value is not a valid P-256 point.", nameof(peer64));
            return point;
        }
    }
}
