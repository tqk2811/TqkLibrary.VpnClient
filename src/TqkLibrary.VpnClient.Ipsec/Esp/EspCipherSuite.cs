using System.Security.Cryptography;
using TqkLibrary.VpnClient.Crypto;

namespace TqkLibrary.VpnClient.Ipsec.Esp
{
    /// <summary>
    /// An ESP transform: turns an inner payload into a complete ESP packet (SPI + Seq + encrypted body + ICV) and back.
    /// Stateless with respect to sequencing and replay — those live in <see cref="EspSession"/>.
    /// </summary>
    public abstract class EspCipherSuite
    {
        /// <summary>Builds a full ESP packet for the given SPI/sequence carrying <paramref name="payload"/>.</summary>
        public abstract byte[] Protect(uint spi, uint sequence, ReadOnlySpan<byte> payload, byte nextHeader);

        /// <summary>
        /// Validates and decrypts an ESP packet. Returns false (writing nothing) if it is malformed or fails integrity.
        /// </summary>
        public abstract bool TryUnprotect(ReadOnlySpan<byte> packet, out byte[] payload, out byte nextHeader);

        /// <summary>AES-CBC-256 encryption with HMAC-SHA-256-128 integrity (RFC 3602 + RFC 4868).</summary>
        public static EspCipherSuite AesCbcHmacSha256(byte[] encryptionKey, byte[] integrityKey)
            => new EspCbcHmacSuite(encryptionKey, integrityKey);

        /// <summary>AES-CBC encryption with HMAC-SHA-1-96 integrity (RFC 3602 + RFC 2404) — the common IKEv1 ESP SA.</summary>
        public static EspCipherSuite AesCbcHmacSha1(byte[] encryptionKey, byte[] integrityKey)
            => new EspCbcHmacSuite(encryptionKey, integrityKey, HmacIntegrity.HmacSha1_96());

        /// <summary>AES-GCM-128 AEAD with a 4-byte salt and 8-byte explicit IV (RFC 4106).</summary>
        public static EspCipherSuite AesGcm(byte[] key, byte[] salt)
            => new EspGcmSuite(key, salt);

        /// <summary>Fills <paramref name="buffer"/> with cryptographically strong random bytes (TFM-agnostic).</summary>
        private protected static void FillRandom(byte[] buffer)
        {
            using var rng = RandomNumberGenerator.Create();
            rng.GetBytes(buffer);
        }

        /// <summary>
        /// Strips ESP trailer padding from decrypted plaintext (… Pad | PadLength | NextHeader) per RFC 4303 §2.4,
        /// validating the monotonic 1..PadLength pattern. Returns false on malformed padding.
        /// </summary>
        private protected static bool TryStripTrailer(ReadOnlySpan<byte> plain, out byte[] payload, out byte nextHeader)
        {
            payload = System.Array.Empty<byte>();
            nextHeader = 0;
            if (plain.Length < 2) return false;

            nextHeader = plain[plain.Length - 1];
            int padLength = plain[plain.Length - 2];
            int payloadLength = plain.Length - 2 - padLength;
            if (payloadLength < 0) return false;

            for (int i = 0; i < padLength; i++)
            {
                if (plain[payloadLength + i] != (byte)(i + 1)) return false;
            }

            payload = plain.Slice(0, payloadLength).ToArray();
            return true;
        }
    }
}
