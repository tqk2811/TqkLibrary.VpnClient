using System.Security.Cryptography;
using TqkLibrary.VpnClient.Crypto;
using TqkLibrary.VpnClient.ZeroTier.Identity.Models;

namespace TqkLibrary.VpnClient.ZeroTier.Identity
{
    /// <summary>
    /// Computes a ZeroTier V1 node address from a 64-byte public key with the memory-hard "hashcash" hash, and checks
    /// the proof-of-work condition that gates a valid identity. The hash composes SHA-512 with Salsa20/20 over a 2 MB
    /// working buffer, which makes deriving — and therefore forging — an address deliberately slow.
    /// <para>
    /// Algorithm (clean-room from the public protocol description, not copied from ZeroTier source):
    /// </para>
    /// <list type="number">
    ///   <item><description><c>digest = SHA-512(publicKey)</c> (64 bytes).</description></item>
    ///   <item><description>Seed a Salsa20/20 stream with key = <c>digest[32..64]</c>, nonce = <c>digest[0..8]</c>.</description></item>
    ///   <item><description>Fill a 2 MB <c>genmem</c> buffer with the Salsa20 keystream (encrypting zeros).</description></item>
    ///   <item><description>Shuffle: 125000 rounds, each reading two little-endian uint64s from <c>genmem</c> and
    ///   swapping an 8-byte block of <c>digest</c> (index n1 % 8) with an 8-byte block of <c>genmem</c> (index n2 % 250000).</description></item>
    ///   <item><description>Re-encrypt <c>digest</c> with the same Salsa20 stream.</description></item>
    ///   <item><description>Proof-of-work: a valid identity requires <c>digest[0] &lt; 17</c>. The address is <c>digest[59..64]</c>.</description></item>
    /// </list>
    /// <para>
    /// <b>UNVERIFIED:</b> the byte-exact correctness of this derivation has not yet been cross-checked against a real
    /// <c>zerotier-idtool</c>-generated identity (no offline sample vector available, VM lab down). The Salsa20
    /// primitive underneath is KAT-verified; the surrounding buffer arithmetic / swap ordering is staged for live
    /// validation. See README / .docs/10.
    /// </para>
    /// </summary>
    public sealed class ZeroTierAddressDerivation
    {
        /// <summary>Size of the memory-hard working buffer in bytes (2 MB).</summary>
        public const int GenmemSize = 2 * 1024 * 1024;

        /// <summary>The hashcash threshold: a valid identity has <c>digest[0] &lt; 17</c>.</summary>
        public const int PowThreshold = 17;

        const int FillRounds = GenmemSize / 64;     // 31250 — one 64-byte digest block per fill step
        const int ShuffleRounds = GenmemSize / 16;  // 125000
        const int GenmemBlocks8 = GenmemSize / 8;   // 250000 eight-byte slots

        readonly Salsa20 _salsa = new Salsa20(20);

        /// <summary>
        /// Computes the 64-byte memory-hard digest for <paramref name="publicKey"/> (must be 64 bytes) and reports
        /// whether the proof-of-work passes. The address is the last 5 bytes of the digest.
        /// </summary>
        public bool TryComputeDigest(ReadOnlySpan<byte> publicKey, out byte[] digest, out ZeroTierAddress address)
        {
            if (publicKey.Length != ZeroTierIdentity.PublicKeySize)
                throw new ArgumentException($"public key must be {ZeroTierIdentity.PublicKeySize} bytes", nameof(publicKey));

            // 1) digest = SHA-512(publicKey)
            digest = Sha512(publicKey);

            // 2) Salsa20/20 stream: key = digest[32..64], nonce = digest[0..8].
            byte[] key = digest.AsSpan(32, 32).ToArray();
            byte[] nonce = digest.AsSpan(0, 8).ToArray();

            // 3) genmem = Salsa20 keystream over 2 MB (encrypting zeros).
            byte[] genmem = new byte[GenmemSize];
            _salsa.GenerateKeystream(key, nonce, genmem);

            // 4) Shuffle: swap 8-byte blocks between digest and genmem, indices read from genmem itself.
            for (int i = 0; i < ShuffleRounds; i++)
            {
                int baseOff = (i * 16) % GenmemSize;
                ulong n1 = ReadUInt64Le(genmem, baseOff);
                ulong n2 = ReadUInt64Le(genmem, baseOff + 8);

                int digestSlot = (int)(n1 % 8) * 8;          // one of 8 eight-byte slots in the 64-byte digest
                int genmemSlot = (int)(n2 % (ulong)GenmemBlocks8) * 8;

                SwapBlock8(digest, digestSlot, genmem, genmemSlot);
            }

            // 5) Re-encrypt the digest with the same stream (fresh Salsa20 at counter 0, matching the spec).
            byte[] finalDigest = new byte[64];
            _salsa.Transform(key, nonce, digest, finalDigest);
            digest = finalDigest;

            // 6) Proof-of-work + address.
            address = ZeroTierAddress.Read(digest.AsSpan(59, 5));
            return digest[0] < PowThreshold;
        }

        /// <summary>
        /// Computes the address for <paramref name="publicKey"/> assuming the identity is well-formed (does not enforce
        /// the proof-of-work). Use <see cref="TryComputeDigest"/> when the PoW result matters.
        /// </summary>
        public ZeroTierAddress ComputeAddress(ReadOnlySpan<byte> publicKey)
        {
            TryComputeDigest(publicKey, out _, out var address);
            return address;
        }

        static byte[] Sha512(ReadOnlySpan<byte> input)
        {
#if NET5_0_OR_GREATER
            byte[] digest = new byte[64];
            SHA512.HashData(input, digest);
            return digest;
#else
            using var sha = SHA512.Create();
            return sha.ComputeHash(input.ToArray());
#endif
        }

        static ulong ReadUInt64Le(byte[] buf, int offset)
        {
            return (ulong)buf[offset]
                | ((ulong)buf[offset + 1] << 8)
                | ((ulong)buf[offset + 2] << 16)
                | ((ulong)buf[offset + 3] << 24)
                | ((ulong)buf[offset + 4] << 32)
                | ((ulong)buf[offset + 5] << 40)
                | ((ulong)buf[offset + 6] << 48)
                | ((ulong)buf[offset + 7] << 56);
        }

        static void SwapBlock8(byte[] a, int aOff, byte[] b, int bOff)
        {
            for (int k = 0; k < 8; k++)
            {
                byte t = a[aOff + k];
                a[aOff + k] = b[bOff + k];
                b[bOff + k] = t;
            }
        }
    }
}
