// Alias the specific BouncyCastle digest (see Noise/Curve25519DhGroup for why we never import the namespace wholesale).
using Blake2bDigest = Org.BouncyCastle.Crypto.Digests.Blake2bDigest;

namespace TqkLibrary.VpnClient.Crypto
{
    /// <summary>
    /// Keyed BLAKE2b (RFC 7693 §2.9 / §4) with a caller-chosen output length — BLAKE2b's own MAC mode (key hashed as a
    /// padded first block), the 64-bit-word sibling of <see cref="Noise.Blake2sKeyedMac"/>. Stateless pure function:
    /// one call per MAC. Wraps BouncyCastle's <c>Blake2bDigest</c> keyed constructor; the key may be up to 64 bytes and
    /// the output 1..64 bytes. Used by BLAKE2b-based mesh crypto (e.g. Yggdrasil / libsodium <c>generichash</c> keyed).
    /// </summary>
    public static class Blake2bKeyedMac
    {
        /// <summary>Maximum BLAKE2b key length in bytes.</summary>
        public const int MaxKeyBytes = 64;

        /// <summary>Maximum BLAKE2b MAC output length in bytes.</summary>
        public const int MaxOutputBytes = 64;

        /// <summary>
        /// Computes keyed BLAKE2b of <paramref name="input"/> under <paramref name="key"/> (0..64 bytes) into
        /// <paramref name="output"/>; the digest length equals <paramref name="output"/>.Length (must be 1..64).
        /// </summary>
        public static void ComputeMac(ReadOnlySpan<byte> key, ReadOnlySpan<byte> input, Span<byte> output)
        {
            int outLen = output.Length;
            if (outLen < 1 || outLen > MaxOutputBytes) throw new ArgumentException($"BLAKE2b output length must be 1..{MaxOutputBytes} bytes.", nameof(output));
            if (key.Length > MaxKeyBytes) throw new ArgumentException($"BLAKE2b key must be at most {MaxKeyBytes} bytes.", nameof(key));
            // Note: this Blake2bDigest overload takes the digest size in BYTES (unlike Blake2bDigest(int) which is bits).
            var digest = new Blake2bDigest(key.ToArray(), outLen, null, null);
            byte[] data = input.ToArray();
            digest.BlockUpdate(data, 0, data.Length);
            byte[] result = new byte[digest.GetDigestSize()];
            digest.DoFinal(result, 0);
            result.AsSpan(0, outLen).CopyTo(output);
        }
    }
}
