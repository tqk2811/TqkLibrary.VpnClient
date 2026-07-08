using System.Buffers.Binary;
using System.Numerics;
using System.Security.Cryptography;

namespace TqkLibrary.VpnClient.Crypto
{
    /// <summary>
    /// UMAC message authentication code (RFC 4418) built on AES as the block cipher.
    /// <para>
    /// <c>UMAC(K, M, Nonce, taglen) = UHASH(K, M, taglen) xor PDF(K, Nonce, taglen)</c>. The universal hash
    /// <see cref="Uhash"/> runs <c>taglen/32</c> independent 4-byte streams, each a three-layer hash: NH (§5.2, message
    /// read as little-endian 32-bit words), the POLY polynomial hash mod <c>prime(64) = 2^64-59</c> (§5.3), and an
    /// inner-product mod <c>prime(36) = 2^36-5</c> (§5.4). Keys and the tag pad are derived from <c>K</c> with AES in
    /// counter mode (<see cref="Kdf"/> §3.2 / <see cref="Pdf"/> §3.3). The block cipher is AES-128 for a 16-byte key and
    /// AES-256 for a 32-byte key (BLOCKLEN = 16 in both cases).
    /// </para>
    /// <para>
    /// Stateless pure function — one call per tag. Verified byte-exact against every RFC 4418 §9 test vector
    /// (UMAC-32/64/96 over the published messages, including <c>'a'*2^25</c>).
    /// </para>
    /// <para>
    /// <b>L2 ramp note.</b> RFC 4418 §5.3 <i>describes</i> a two-step POLY that ramps to <c>prime(128)</c> once the
    /// L1-HASH output exceeds 2^17 bytes (messages &gt; 16&#160;MB). That description is inconsistent with the RFC's own
    /// §9 vectors: the <c>'a'*2^25</c> (32&#160;MB) tag is reproduced only by a single POLY mod <c>prime(64)</c> over the
    /// whole L1 output, never switching to <c>prime(128)</c>. The reference implementation confirms this — its
    /// <c>poly_hash</c> uses <c>poly64</c> throughout and explicitly documents that it "does not handle the ramp up to
    /// p128 modulus … limited to … 16MB". This implementation therefore follows the reference and the §9 vectors:
    /// single POLY mod <c>prime(64)</c>, no p128 ramp. For UMAC's practical uses (e.g. fastd, whose messages are single
    /// packets far below 16&#160;MB) the ramp is never reached.
    /// </para>
    /// </summary>
    public static class Umac
    {
        /// <summary>AES block length in bytes (also the maximum nonce length).</summary>
        public const int BlockLen = 16;

        // UMAC primes and POLY range bound (RFC 4418 §2.2 / §5.3). Only the 64-bit POLY is used (see the L2 ramp note).
        static readonly BigInteger P64 = (BigInteger.One << 64) - 59;                              // prime(64) = 2^64 - 59
        static readonly BigInteger MaxRange64 = (BigInteger.One << 64) - (BigInteger.One << 32);   // 2^64 - 2^32
        const ulong Prime36 = (1UL << 36) - 5;                                                     // prime(36) = 2^36 - 5

        /// <summary>
        /// Computes the UMAC tag of <paramref name="message"/> under <paramref name="key"/> (16 or 32 bytes) and
        /// <paramref name="nonce"/> (1..16 bytes). <paramref name="tagBits"/> is 32, 64, 96 or 128; the returned tag is
        /// <c>tagBits/8</c> bytes.
        /// </summary>
        public static byte[] ComputeTag(ReadOnlySpan<byte> key, ReadOnlySpan<byte> message, ReadOnlySpan<byte> nonce, int tagBits = 64)
        {
            if (key.Length != 16 && key.Length != 32)
                throw new ArgumentException("UMAC key must be 16 bytes (AES-128) or 32 bytes (AES-256).", nameof(key));
            if (tagBits != 32 && tagBits != 64 && tagBits != 96 && tagBits != 128)
                throw new ArgumentException("UMAC tag length must be 32, 64, 96 or 128 bits.", nameof(tagBits));
            if (nonce.Length < 1 || nonce.Length > BlockLen)
                throw new ArgumentException($"UMAC nonce must be 1..{BlockLen} bytes.", nameof(nonce));

            int taglen = tagBits / 8;

            using Aes aes = Aes.Create();
            aes.Mode = CipherMode.ECB;
            aes.Padding = PaddingMode.None;
            aes.Key = key.ToArray();
            using ICryptoTransform enc = aes.CreateEncryptor();

            byte[] hashed = Uhash(enc, message, taglen);
            byte[] pad = Pdf(enc, key, nonce, taglen);

            byte[] tag = new byte[taglen];
            for (int i = 0; i < taglen; i++)
                tag[i] = (byte)(hashed[i] ^ pad[i]);
            return tag;
        }

        // ----- §3.2 KDF: AES in counter mode -----------------------------------------------------------------

        /// <summary>KDF(K, index, numbytes) — <paramref name="enc"/> is AES-ECB under K. Counter block = index(8B BE) || i(8B BE).</summary>
        static byte[] Kdf(ICryptoTransform enc, long index, int numbytes)
        {
            int n = (numbytes + BlockLen - 1) / BlockLen; // ceil(numbytes / BLOCKLEN)
            byte[] buffer = new byte[n * BlockLen];
            byte[] block = new byte[BlockLen];
            BinaryPrimitives.WriteUInt64BigEndian(block.AsSpan(0, 8), (ulong)index);
            for (int i = 1; i <= n; i++)
            {
                BinaryPrimitives.WriteUInt64BigEndian(block.AsSpan(8, 8), (ulong)i);
                enc.TransformBlock(block, 0, BlockLen, buffer, (i - 1) * BlockLen);
            }
            if (buffer.Length == numbytes) return buffer;
            byte[] result = new byte[numbytes];
            Array.Copy(buffer, result, numbytes);
            return result;
        }

        // ----- §3.3 PDF: pad derivation ---------------------------------------------------------------------

        static byte[] Pdf(ICryptoTransform encMain, ReadOnlySpan<byte> key, ReadOnlySpan<byte> nonce, int taglen)
        {
            byte[] subKey = Kdf(encMain, 0, key.Length);       // K' = KDF(K, 0, KEYLEN)
            byte[] nonceBuf = nonce.ToArray();

            int index = 0;
            if (taglen == 4 || taglen == 8)
            {
                int mod = BlockLen / taglen;                    // 4 for taglen 4, 2 for taglen 8
                int last = nonceBuf.Length - 1;
                index = nonceBuf[last] % mod;                   // str2uint(Nonce) mod (BLOCKLEN/taglen)
                nonceBuf[last] = (byte)(nonceBuf[last] & ~(mod - 1)); // zero the low bit(s)
            }

            byte[] block = new byte[BlockLen];                  // nonce padded to BLOCKLEN with zeroes
            Array.Copy(nonceBuf, block, nonceBuf.Length);

            using Aes aes = Aes.Create();
            aes.Mode = CipherMode.ECB;
            aes.Padding = PaddingMode.None;
            aes.Key = subKey;
            using ICryptoTransform enc = aes.CreateEncryptor();
            byte[] t = new byte[BlockLen];
            enc.TransformBlock(block, 0, BlockLen, t, 0);

            byte[] pad = new byte[taglen];
            int start = (taglen == 4 || taglen == 8) ? index * taglen : 0;
            Array.Copy(t, start, pad, 0, taglen);
            return pad;
        }

        // ----- §5.1 UHASH ------------------------------------------------------------------------------------

        static byte[] Uhash(ICryptoTransform enc, ReadOnlySpan<byte> message, int taglen)
        {
            int iters = taglen / 4;
            byte[] l1Key = Kdf(enc, 1, 1024 + (iters - 1) * 16);
            byte[] l2Key = Kdf(enc, 2, iters * 24);
            byte[] l3Key1 = Kdf(enc, 3, iters * 64);
            byte[] l3Key2 = Kdf(enc, 4, iters * 4);

            byte[] y = new byte[taglen];
            for (int i = 0; i < iters; i++)
            {
                ReadOnlySpan<byte> l1 = l1Key.AsSpan(i * 16, 1024);
                ReadOnlySpan<byte> l2 = l2Key.AsSpan(i * 24, 24);
                ReadOnlySpan<byte> k1 = l3Key1.AsSpan(i * 64, 64);
                ReadOnlySpan<byte> k2 = l3Key2.AsSpan(i * 4, 4);

                byte[] a = L1Hash(l1, message);
                byte[] b;
                if ((long)message.Length <= 1024) // bitlength(M) <= bitlength(L1Key_i) == 8192
                {
                    b = new byte[16];
                    Array.Copy(a, 0, b, 8, 8); // zeroes(8) || A
                }
                else
                {
                    b = L2Hash(l2, a);
                }
                byte[] c = L3Hash(k1, k2, b);
                Array.Copy(c, 0, y, i * 4, 4);
            }
            return y;
        }

        // ----- §5.2 L1-HASH / NH -----------------------------------------------------------------------------

        static byte[] L1Hash(ReadOnlySpan<byte> key, ReadOnlySpan<byte> message)
        {
            int msgLen = message.Length;
            int t = Math.Max((msgLen + 1023) / 1024, 1); // number of 1024-byte chunks
            byte[] y = new byte[t * 8];

            byte[]? padBuf = null;
            for (int chunk = 0; chunk < t; chunk++)
            {
                int start = chunk * 1024;
                int len = Math.Min(1024, msgLen - start);
                bool last = chunk == t - 1;

                ulong nh;
                ulong lenBits;
                if (!last)
                {
                    nh = Nh(key, message.Slice(start, 1024));
                    lenBits = 1024UL * 8;
                }
                else
                {
                    // Pad last chunk up to a positive multiple of 32 bytes (zeropad), then NH.
                    int padded = ((len + 31) / 32) * 32;
                    if (padded == 0) padded = 32;
                    if (padBuf == null || padBuf.Length != padded) padBuf = new byte[padded];
                    else Array.Clear(padBuf, 0, padBuf.Length);
                    message.Slice(start, len).CopyTo(padBuf);
                    nh = Nh(key, padBuf.AsSpan(0, padded));
                    lenBits = (ulong)((long)len * 8);
                }

                ulong val = unchecked(nh + lenBits); // NH(K, M_i) +_64 Len
                BinaryPrimitives.WriteUInt64BigEndian(y.AsSpan(chunk * 8, 8), val);
            }
            return y;
        }

        /// <summary>NH (§5.2.2). Message words are read little-endian (equivalent to ENDIAN-SWAP then str2uint); key words big-endian.</summary>
        static ulong Nh(ReadOnlySpan<byte> key, ReadOnlySpan<byte> m)
        {
            int t = m.Length / 4; // number of 32-bit words
            ulong y = 0;
            int i = 0;
            while (i < t)
            {
                for (int j = 0; j < 4; j++)
                {
                    int wm = (i + j) * 4;
                    int wm4 = (i + j + 4) * 4;
                    uint m0 = BinaryPrimitives.ReadUInt32LittleEndian(m.Slice(wm, 4));
                    uint k0 = BinaryPrimitives.ReadUInt32BigEndian(key.Slice(wm, 4));
                    uint m4 = BinaryPrimitives.ReadUInt32LittleEndian(m.Slice(wm4, 4));
                    uint k4 = BinaryPrimitives.ReadUInt32BigEndian(key.Slice(wm4, 4));
                    ulong a = unchecked(m0 + k0); // +_32
                    ulong b = unchecked(m4 + k4);
                    y = unchecked(y + a * b);     // *_64 then +_64
                }
                i += 8;
            }
            return y;
        }

        // ----- §5.3 L2-HASH / POLY ---------------------------------------------------------------------------

        // Hashes the 8-byte-word L1 output with a single POLY mod prime(64). See the L2 ramp note on the class:
        // the RFC's p128 ramp is a spec/vector inconsistency, so only the 64-bit POLY is used (matching the reference).
        static byte[] L2Hash(ReadOnlySpan<byte> key, ReadOnlySpan<byte> m)
        {
            // k64 = str2uint(K[1..8] and 0x01ffffff01ffffff)
            BigInteger k64 = BinaryPrimitives.ReadUInt64BigEndian(key.Slice(0, 8)) & 0x01ffffff01ffffffUL;
            BigInteger y = Poly64(k64, m);

            byte[] outBytes = new byte[16]; // uint2str(y, 16); y < prime(64) so the high 8 bytes are zero
            BigToBe(y, outBytes);
            return outBytes;
        }

        // POLY (§5.3.2) with wordbits = 64, maxwordrange = 2^64 - 2^32. M is read as 8-byte big-endian words.
        static BigInteger Poly64(BigInteger k, ReadOnlySpan<byte> m)
        {
            BigInteger offset = 59;      // 2^64 - prime(64)
            BigInteger marker = P64 - 1;
            int n = m.Length / 8;

            BigInteger y = 1;
            for (int i = 0; i < n; i++)
            {
                BigInteger word = BinaryPrimitives.ReadUInt64BigEndian(m.Slice(i * 8, 8));
                if (word >= MaxRange64)
                {
                    y = (k * y + marker) % P64;
                    y = (k * y + (word - offset)) % P64;
                }
                else
                {
                    y = (k * y + word) % P64;
                }
            }
            return y;
        }

        // ----- §5.4 L3-HASH ----------------------------------------------------------------------------------

        static byte[] L3Hash(ReadOnlySpan<byte> k1, ReadOnlySpan<byte> k2, ReadOnlySpan<byte> m)
        {
            ulong y = 0; // sum fits: 8 * (2^16-1) * (2^36-6) < 2^60
            for (int i = 0; i < 8; i++)
            {
                uint mi = BinaryPrimitives.ReadUInt16BigEndian(m.Slice(i * 2, 2));
                ulong ki = BinaryPrimitives.ReadUInt64BigEndian(k1.Slice(i * 8, 8)) % Prime36;
                y += mi * ki;
            }
            y %= Prime36;
            uint low = (uint)(y % (1UL << 32));

            byte[] outBytes = new byte[4];
            BinaryPrimitives.WriteUInt32BigEndian(outBytes, low);
            for (int i = 0; i < 4; i++) outBytes[i] ^= k2[i];
            return outBytes;
        }

        // ----- BigInteger -> big-endian helper (portable to netstandard2.0) ----------------------------------

        static void BigToBe(BigInteger value, Span<byte> dst)
        {
            for (int i = dst.Length - 1; i >= 0; i--)
            {
                dst[i] = (byte)(value & 0xFF);
                value >>= 8;
            }
        }
    }
}
