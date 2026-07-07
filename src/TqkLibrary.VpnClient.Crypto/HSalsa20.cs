using System.Buffers.Binary;

namespace TqkLibrary.VpnClient.Crypto
{
    /// <summary>
    /// HSalsa20 core function (Bernstein, "Extending the Salsa20 nonce" §2) — the keyless (but keyed by the 256-bit
    /// key) hash that turns a 32-byte key plus a 16-byte input into a 32-byte output. It is the first stage of
    /// <see cref="XSalsa20"/>: <c>subkey = HSalsa20(key, nonce[0:16])</c>. Unlike the full Salsa20 keystream generator,
    /// HSalsa20 runs the 20-round core <b>without the final feed-forward</b> (the initial state is <b>not</b> added back)
    /// and emits eight specific words of the mixed state.
    /// <para>
    /// This mirrors <c>XChaCha20Poly1305Cipher.HChaCha20</c> (the ChaCha analogue), but Salsa20 has a different state
    /// layout and a different quarter-round, so the core is implemented here rather than reusing BouncyCastle's
    /// <c>Salsa20Engine</c> (which does not expose the raw, feed-forward-free core). Verified byte-exact against the
    /// DJB / libsodium <c>crypto_core_hsalsa20</c> test vector (see HSalsa20Tests / XSalsa20Poly1305Tests).
    /// </para>
    /// </summary>
    public static class HSalsa20
    {
        /// <summary>HSalsa20 key length in bytes (256-bit).</summary>
        public const int KeyBytes = 32;

        /// <summary>HSalsa20 input length in bytes.</summary>
        public const int InputBytes = 16;

        /// <summary>HSalsa20 output length in bytes.</summary>
        public const int OutputBytes = 32;

        // "expand 32-byte k" constant words, little-endian (same sigma constants as Salsa20/ChaCha20).
        const uint C0 = 0x61707865, C1 = 0x3320646e, C2 = 0x79622d32, C3 = 0x6b206574;

        /// <summary>
        /// Computes the 32-byte HSalsa20 output from a 32-byte <paramref name="key"/> and a 16-byte
        /// <paramref name="input"/>. Runs the 20-round Salsa20 core (10 double-rounds) with no feed-forward and emits
        /// words (x0, x5, x10, x15, x6, x7, x8, x9) little-endian.
        /// </summary>
        public static void Hash(ReadOnlySpan<byte> key, ReadOnlySpan<byte> input, Span<byte> output)
        {
            if (key.Length != KeyBytes) throw new ArgumentException($"HSalsa20 key must be {KeyBytes} bytes.", nameof(key));
            if (input.Length != InputBytes) throw new ArgumentException($"HSalsa20 input must be {InputBytes} bytes.", nameof(input));
            if (output.Length < OutputBytes) throw new ArgumentException($"HSalsa20 output must be at least {OutputBytes} bytes.", nameof(output));

            Span<uint> x = stackalloc uint[16];
            // Diagonal: constant words at x0/x5/x10/x15.
            x[0] = C0; x[5] = C1; x[10] = C2; x[15] = C3;
            // key[0:16] -> x1..x4.
            x[1] = BinaryPrimitives.ReadUInt32LittleEndian(key.Slice(0, 4));
            x[2] = BinaryPrimitives.ReadUInt32LittleEndian(key.Slice(4, 4));
            x[3] = BinaryPrimitives.ReadUInt32LittleEndian(key.Slice(8, 4));
            x[4] = BinaryPrimitives.ReadUInt32LittleEndian(key.Slice(12, 4));
            // key[16:32] -> x11..x14.
            x[11] = BinaryPrimitives.ReadUInt32LittleEndian(key.Slice(16, 4));
            x[12] = BinaryPrimitives.ReadUInt32LittleEndian(key.Slice(20, 4));
            x[13] = BinaryPrimitives.ReadUInt32LittleEndian(key.Slice(24, 4));
            x[14] = BinaryPrimitives.ReadUInt32LittleEndian(key.Slice(28, 4));
            // in[0:16] -> x6..x9.
            x[6] = BinaryPrimitives.ReadUInt32LittleEndian(input.Slice(0, 4));
            x[7] = BinaryPrimitives.ReadUInt32LittleEndian(input.Slice(4, 4));
            x[8] = BinaryPrimitives.ReadUInt32LittleEndian(input.Slice(8, 4));
            x[9] = BinaryPrimitives.ReadUInt32LittleEndian(input.Slice(12, 4));

            for (int i = 0; i < 10; i++)
            {
                // Column rounds.
                QuarterRound(x, 0, 4, 8, 12);
                QuarterRound(x, 5, 9, 13, 1);
                QuarterRound(x, 10, 14, 2, 6);
                QuarterRound(x, 15, 3, 7, 11);
                // Row rounds.
                QuarterRound(x, 0, 1, 2, 3);
                QuarterRound(x, 5, 6, 7, 4);
                QuarterRound(x, 10, 11, 8, 9);
                QuarterRound(x, 15, 12, 13, 14);
            }

            // Output = x0, x5, x10, x15, x6, x7, x8, x9 (no addition of the initial state).
            BinaryPrimitives.WriteUInt32LittleEndian(output.Slice(0, 4), x[0]);
            BinaryPrimitives.WriteUInt32LittleEndian(output.Slice(4, 4), x[5]);
            BinaryPrimitives.WriteUInt32LittleEndian(output.Slice(8, 4), x[10]);
            BinaryPrimitives.WriteUInt32LittleEndian(output.Slice(12, 4), x[15]);
            BinaryPrimitives.WriteUInt32LittleEndian(output.Slice(16, 4), x[6]);
            BinaryPrimitives.WriteUInt32LittleEndian(output.Slice(20, 4), x[7]);
            BinaryPrimitives.WriteUInt32LittleEndian(output.Slice(24, 4), x[8]);
            BinaryPrimitives.WriteUInt32LittleEndian(output.Slice(28, 4), x[9]);
        }

        // Salsa20 quarter-round on (y0,y1,y2,y3): y1^=R(y0+y3,7); y2^=R(y1+y0,9); y3^=R(y2+y1,13); y0^=R(y3+y2,18).
        static void QuarterRound(Span<uint> x, int a, int b, int c, int d)
        {
            x[b] ^= RotateLeft(x[a] + x[d], 7);
            x[c] ^= RotateLeft(x[b] + x[a], 9);
            x[d] ^= RotateLeft(x[c] + x[b], 13);
            x[a] ^= RotateLeft(x[d] + x[c], 18);
        }

        static uint RotateLeft(uint value, int bits) => (value << bits) | (value >> (32 - bits));
    }
}
