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
    /// Algorithm (clean-room from the public protocol description / security analyses, not copied from ZeroTier source):
    /// </para>
    /// <list type="number">
    ///   <item><description><c>digest = SHA-512(publicKey)</c> (64 bytes).</description></item>
    ///   <item><description>Open one continuous Salsa20/20 stream with key = <c>digest[0..32]</c>, nonce = <c>digest[32..40]</c>.</description></item>
    ///   <item><description>Fill a 2 MB <c>genmem</c> buffer CBC-like: encrypt the first 64-byte block (zeros), then for
    ///   each later 64-byte block copy the previous block and re-encrypt it on the same (advancing) stream.</description></item>
    ///   <item><description>Shuffle: <c>2 MB / 8 = 262144</c> uint64 slots consumed pairwise (131072 rounds). Each round
    ///   reads two big-endian uint64s from <c>genmem</c>, swaps the 8-byte word <c>digest[idx1]</c>
    ///   (<c>idx1 = n1 % 8</c>) with <c>genmem[idx2]</c> (<c>idx2 = n2 % 262144</c>), then re-encrypts the digest on the
    ///   same stream.</description></item>
    ///   <item><description>Proof-of-work: a valid identity requires <c>digest[0] &lt; 17</c>. The address is the last 5
    ///   bytes <c>digest[59..64]</c>.</description></item>
    /// </list>
    /// <para>
    /// <b>VERIFIED:</b> KAT-checked byte-exact against real <c>zerotier-idtool generate</c> identities (V.7.3 live lab) —
    /// see <c>ZeroTierAddressKatTests</c>.
    /// </para>
    /// </summary>
    public sealed class ZeroTierAddressDerivation
    {
        /// <summary>Size of the memory-hard working buffer in bytes (2 MB).</summary>
        public const int GenmemSize = 2 * 1024 * 1024;

        /// <summary>The hashcash threshold: a valid identity has <c>digest[0] &lt; 17</c>.</summary>
        public const int PowThreshold = 17;

        const int GenmemSlots8 = GenmemSize / 8;   // 262144 eight-byte slots in genmem

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

            // 2) One continuous Salsa20/20 stream: key = digest[0..32], nonce = digest[32..40].
            //    Salsa20 s20(digest, digest + 32) — argument order is (key, iv).
            byte[] key = digest.AsSpan(0, 32).ToArray();
            byte[] nonce = digest.AsSpan(32, 8).ToArray();
            Salsa20.Stream s20 = _salsa.CreateStream(key, nonce);

            // 3) genmem = CBC-like fill on the SAME advancing stream.
            byte[] genmem = new byte[GenmemSize];
            s20.Process(genmem.AsSpan(0, 64));                          // block 0: encrypt zeros
            for (int i = 64; i < GenmemSize; i += 64)
            {
                Buffer.BlockCopy(genmem, i - 64, genmem, i, 64);       // copy previous block
                s20.Process(genmem.AsSpan(i, 64));                     // re-encrypt it (stream continues)
            }

            // 4) Shuffle: consume genmem pairwise as big-endian uint64s; swap 8-byte words between digest and genmem,
            //    re-encrypting the digest on the same stream after every swap.
            for (int i = 0; i < GenmemSlots8; )
            {
                ulong n1 = ReadUInt64Be(genmem, (i++) * 8);
                ulong n2 = ReadUInt64Be(genmem, (i++) * 8);

                int idx1 = (int)(n1 % 8) * 8;                          // 8-byte word inside the 64-byte digest
                int idx2 = (int)(n2 % (ulong)GenmemSlots8) * 8;        // 8-byte word inside genmem

                SwapBlock8(digest, idx1, genmem, idx2);
                s20.Process(digest.AsSpan(0, 64));
            }

            // 5) Proof-of-work + address (last 5 bytes).
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

        static ulong ReadUInt64Be(byte[] buf, int offset)
        {
            return ((ulong)buf[offset] << 56)
                | ((ulong)buf[offset + 1] << 48)
                | ((ulong)buf[offset + 2] << 40)
                | ((ulong)buf[offset + 3] << 32)
                | ((ulong)buf[offset + 4] << 24)
                | ((ulong)buf[offset + 5] << 16)
                | ((ulong)buf[offset + 6] << 8)
                | buf[offset + 7];
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
