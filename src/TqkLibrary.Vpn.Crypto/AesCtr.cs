using System.Security.Cryptography;

namespace TqkLibrary.Vpn.Crypto
{
    /// <summary>
    /// AES in counter (CTR) mode, built from AES-ECB. The 128-bit counter block is incremented big-endian
    /// across the whole block (NIST SP 800-38A). ESP-specific counter framing (RFC 3686) is layered on top.
    /// </summary>
    public static class AesCtr
    {
        /// <summary>XORs <paramref name="input"/> with the AES-CTR keystream into <paramref name="output"/> (same length).</summary>
        public static void Transform(ReadOnlySpan<byte> key, ReadOnlySpan<byte> initialCounter, ReadOnlySpan<byte> input, Span<byte> output)
        {
            if (initialCounter.Length != 16) throw new ArgumentException("counter must be 16 bytes", nameof(initialCounter));
            if (output.Length < input.Length) throw new ArgumentException("output too small", nameof(output));

            using Aes aes = Aes.Create();
            aes.Mode = CipherMode.ECB;
            aes.Padding = PaddingMode.None;
            aes.Key = key.ToArray();
            using ICryptoTransform enc = aes.CreateEncryptor();

            byte[] counter = initialCounter.ToArray();
            byte[] keystream = new byte[16];

            for (int offset = 0; offset < input.Length; offset += 16)
            {
                enc.TransformBlock(counter, 0, 16, keystream, 0);
                int n = Math.Min(16, input.Length - offset);
                for (int i = 0; i < n; i++)
                    output[offset + i] = (byte)(input[offset + i] ^ keystream[i]);
                IncrementBigEndian(counter);
            }
        }

        static void IncrementBigEndian(byte[] counter)
        {
            for (int i = 15; i >= 0; i--)
            {
                if (++counter[i] != 0) break;
            }
        }
    }
}
