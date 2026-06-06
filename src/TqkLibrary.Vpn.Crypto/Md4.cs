using TqkLibrary.Vpn.Crypto.Abstractions.Interfaces;

namespace TqkLibrary.Vpn.Crypto
{
    /// <summary>
    /// MD4 message digest (RFC 1320). Not part of the modern BCL; needed for the MS-CHAPv2 NT hash.
    /// Cryptographically broken — used only because the protocol mandates it.
    /// </summary>
    public sealed class Md4 : IHashAlgo
    {
        /// <inheritdoc/>
        public int HashSizeInBytes => 16;

        /// <inheritdoc/>
        public void ComputeHash(ReadOnlySpan<byte> input, Span<byte> destination)
        {
            if (destination.Length < 16) throw new ArgumentException("destination must be >= 16 bytes", nameof(destination));

            uint a = 0x67452301, b = 0xefcdab89, c = 0x98badcfe, d = 0x10325476;

            // Process full 64-byte blocks, then a padded tail.
            int fullBlocks = input.Length / 64;
            for (int i = 0; i < fullBlocks; i++)
                ProcessBlock(input.Slice(i * 64, 64), ref a, ref b, ref c, ref d);

            ReadOnlySpan<byte> tail = input.Slice(fullBlocks * 64);
            Span<byte> buffer = stackalloc byte[128];
            tail.CopyTo(buffer);
            buffer[tail.Length] = 0x80;
            // Determine padded length: pad so that the final block ends with an 8-byte length.
            int padded = (tail.Length < 56) ? 64 : 128;
            ulong bitLength = (ulong)input.Length * 8;
            BinaryWriteUInt64LittleEndian(buffer.Slice(padded - 8), bitLength);

            ProcessBlock(buffer.Slice(0, 64), ref a, ref b, ref c, ref d);
            if (padded == 128)
                ProcessBlock(buffer.Slice(64, 64), ref a, ref b, ref c, ref d);

            WriteUInt32LittleEndian(destination, a);
            WriteUInt32LittleEndian(destination.Slice(4), b);
            WriteUInt32LittleEndian(destination.Slice(8), c);
            WriteUInt32LittleEndian(destination.Slice(12), d);
        }

        /// <summary>Convenience one-shot that allocates a 16-byte result.</summary>
        public static byte[] Hash(ReadOnlySpan<byte> input)
        {
            var result = new byte[16];
            new Md4().ComputeHash(input, result);
            return result;
        }

        static void ProcessBlock(ReadOnlySpan<byte> block, ref uint a, ref uint b, ref uint c, ref uint d)
        {
            Span<uint> x = stackalloc uint[16];
            for (int i = 0; i < 16; i++)
                x[i] = (uint)(block[i * 4] | (block[i * 4 + 1] << 8) | (block[i * 4 + 2] << 16) | (block[i * 4 + 3] << 24));

            uint aa = a, bb = b, cc = c, dd = d;

            // Round 1
            for (int i = 0; i < 16; i += 4)
            {
                aa = Rotl(aa + F(bb, cc, dd) + x[i], 3);
                dd = Rotl(dd + F(aa, bb, cc) + x[i + 1], 7);
                cc = Rotl(cc + F(dd, aa, bb) + x[i + 2], 11);
                bb = Rotl(bb + F(cc, dd, aa) + x[i + 3], 19);
            }

            // Round 2
            for (int i = 0; i < 4; i++)
            {
                aa = Rotl(aa + G(bb, cc, dd) + x[i] + 0x5a827999u, 3);
                dd = Rotl(dd + G(aa, bb, cc) + x[i + 4] + 0x5a827999u, 5);
                cc = Rotl(cc + G(dd, aa, bb) + x[i + 8] + 0x5a827999u, 9);
                bb = Rotl(bb + G(cc, dd, aa) + x[i + 12] + 0x5a827999u, 13);
            }

            // Round 3
            ReadOnlySpan<int> order = stackalloc int[] { 0, 8, 4, 12, 2, 10, 6, 14, 1, 9, 5, 13, 3, 11, 7, 15 };
            for (int i = 0; i < 16; i += 4)
            {
                aa = Rotl(aa + H(bb, cc, dd) + x[order[i]] + 0x6ed9eba1u, 3);
                dd = Rotl(dd + H(aa, bb, cc) + x[order[i + 1]] + 0x6ed9eba1u, 9);
                cc = Rotl(cc + H(dd, aa, bb) + x[order[i + 2]] + 0x6ed9eba1u, 11);
                bb = Rotl(bb + H(cc, dd, aa) + x[order[i + 3]] + 0x6ed9eba1u, 15);
            }

            a += aa; b += bb; c += cc; d += dd;
        }

        static uint F(uint x, uint y, uint z) => (x & y) | (~x & z);
        static uint G(uint x, uint y, uint z) => (x & y) | (x & z) | (y & z);
        static uint H(uint x, uint y, uint z) => x ^ y ^ z;
        static uint Rotl(uint v, int s) => (v << s) | (v >> (32 - s));

        static void WriteUInt32LittleEndian(Span<byte> dst, uint v)
        {
            dst[0] = (byte)v;
            dst[1] = (byte)(v >> 8);
            dst[2] = (byte)(v >> 16);
            dst[3] = (byte)(v >> 24);
        }

        static void BinaryWriteUInt64LittleEndian(Span<byte> dst, ulong v)
        {
            for (int i = 0; i < 8; i++) dst[i] = (byte)(v >> (8 * i));
        }
    }
}
