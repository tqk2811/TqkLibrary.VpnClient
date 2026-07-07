// Alias the specific BouncyCastle digest (see Noise/Curve25519DhGroup for why we never import the namespace wholesale).
using Blake2bDigest = Org.BouncyCastle.Crypto.Digests.Blake2bDigest;

namespace TqkLibrary.VpnClient.Crypto
{
    /// <summary>
    /// BLAKE2b (RFC 7693) unkeyed hash with a caller-chosen output length (1..64 bytes, default 64) — a thin wrapper
    /// around BouncyCastle's <c>Blake2bDigest</c> (the compression function is BouncyCastle's, not re-implemented here),
    /// the same package the rest of the Crypto layer uses. This is the 64-bit-word sibling of
    /// <see cref="Noise.Blake2s"/> (32-bit) and fills the BLAKE2b gap for Yggdrasil (node-ID / tree hashing).
    /// Placed at the Crypto root rather than in <c>Noise/</c> because BLAKE2b is a general-purpose hash, not a
    /// Noise/WireGuard primitive. Verified byte-exact against the RFC 7693 Appendix A vector (see Blake2bTests).
    /// </summary>
    public static class Blake2b
    {
        /// <summary>Maximum BLAKE2b digest length in bytes (512-bit).</summary>
        public const int MaxOutputBytes = 64;

        /// <summary>Default BLAKE2b digest length in bytes (512-bit = BLAKE2b-512).</summary>
        public const int DefaultOutputBytes = 64;

        /// <summary>
        /// Hashes <paramref name="input"/> to a new <paramref name="outputBytes"/>-byte digest (default 64 / BLAKE2b-512).
        /// </summary>
        public static byte[] Hash(ReadOnlySpan<byte> input, int outputBytes = DefaultOutputBytes)
        {
            if (outputBytes < 1 || outputBytes > MaxOutputBytes) throw new ArgumentException($"BLAKE2b output length must be 1..{MaxOutputBytes} bytes.", nameof(outputBytes));
            byte[] output = new byte[outputBytes];
            Hash(input, output.AsSpan());
            return output;
        }

        /// <summary>
        /// Hashes <paramref name="input"/> into <paramref name="output"/>; the digest length equals
        /// <paramref name="output"/>.Length (must be 1..64).
        /// </summary>
        public static void Hash(ReadOnlySpan<byte> input, Span<byte> output)
        {
            int outLen = output.Length;
            if (outLen < 1 || outLen > MaxOutputBytes) throw new ArgumentException($"BLAKE2b output length must be 1..{MaxOutputBytes} bytes.", nameof(output));
            // Note: Blake2bDigest(int) takes the digest size in BITS (multiple of 8), unlike the keyed overload (bytes).
            var digest = new Blake2bDigest(outLen * 8);
            byte[] data = input.ToArray();
            digest.BlockUpdate(data, 0, data.Length);
            byte[] result = new byte[digest.GetDigestSize()];
            digest.DoFinal(result, 0);
            result.AsSpan(0, outLen).CopyTo(output);
        }
    }
}
