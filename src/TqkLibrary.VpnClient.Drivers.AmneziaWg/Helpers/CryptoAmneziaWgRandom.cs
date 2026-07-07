using System;
using System.Security.Cryptography;
using TqkLibrary.VpnClient.Drivers.AmneziaWg.Interfaces;

namespace TqkLibrary.VpnClient.Drivers.AmneziaWg.Helpers
{
    /// <summary>
    /// The production <see cref="IAmneziaWgRandom"/>: draws bytes and range integers from the BCL cryptographic RNG
    /// (<see cref="RandomNumberGenerator"/>, available on both <c>netstandard2.0</c> and <c>net8.0</c>) so obfuscation
    /// junk is unpredictable. Range integers use rejection sampling over a 32-bit draw to stay uniform (no modulo bias),
    /// implemented locally rather than via <c>RandomNumberGenerator.GetInt32</c> (which is not on <c>netstandard2.0</c>).
    /// </summary>
    public sealed class CryptoAmneziaWgRandom : IAmneziaWgRandom
    {
        /// <summary>A shared, thread-safe instance backed by the process cryptographic RNG.</summary>
        public static readonly CryptoAmneziaWgRandom Shared = new CryptoAmneziaWgRandom();

        readonly RandomNumberGenerator _rng = RandomNumberGenerator.Create();

        /// <inheritdoc/>
        public byte[] NextBytes(int count)
        {
            if (count < 0) throw new ArgumentOutOfRangeException(nameof(count));
            if (count == 0) return Array.Empty<byte>();
            byte[] buffer = new byte[count];
            _rng.GetBytes(buffer);
            return buffer;
        }

        /// <inheritdoc/>
        public int NextInt(int minInclusive, int maxInclusive)
        {
            if (minInclusive > maxInclusive) throw new ArgumentOutOfRangeException(nameof(minInclusive));
            if (minInclusive == maxInclusive) return minInclusive;

            // Uniform value in [0, range) via rejection sampling on a 32-bit unsigned draw (avoids modulo bias).
            uint range = (uint)(maxInclusive - minInclusive) + 1u;
            uint limit = range == 0 ? 0u : uint.MaxValue - (uint.MaxValue % range); // range==0 ⇒ full u32 span (handled below)
            byte[] four = new byte[4];
            while (true)
            {
                _rng.GetBytes(four);
                uint sample = (uint)(four[0] | (four[1] << 8) | (four[2] << 16) | (four[3] << 24));
                if (range == 0) return (int)(minInclusive + sample); // whole uint span requested
                if (sample < limit) return (int)(minInclusive + (sample % range));
            }
        }
    }
}
