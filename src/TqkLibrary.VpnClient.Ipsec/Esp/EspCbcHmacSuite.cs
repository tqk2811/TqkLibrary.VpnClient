using TqkLibrary.VpnClient.Crypto;
using TqkLibrary.VpnClient.Crypto.Abstractions.Interfaces;

namespace TqkLibrary.VpnClient.Ipsec.Esp
{
    /// <summary>
    /// ESP transform with a separate cipher and MAC: AES-CBC-256 for confidentiality (RFC 3602) and
    /// HMAC-SHA-256-128 for integrity (RFC 4868), in the encrypt-then-MAC layout ESP mandates.
    /// Wire layout: SPI(4) | Seq(4) | IV(16) | ciphertext | ICV(16).
    /// </summary>
    public sealed class EspCbcHmacSuite : EspCipherSuite
    {
        const int BlockSize = 16;
        const int IvSize = 16;

        readonly byte[] _encryptionKey;
        readonly byte[] _integrityKey;
        readonly IBlockCipher _cipher = new AesCbcCipher();
        readonly IIntegrityAlgo _integrity;

        /// <summary>
        /// Creates the suite with an AES key (16/24/32 bytes) and an integrity algorithm + key.
        /// Defaults to HMAC-SHA-256-128 (IKEv2); pass <see cref="HmacIntegrity.HmacSha1_96"/> for IKEv1 ESP SAs.
        /// </summary>
        public EspCbcHmacSuite(byte[] encryptionKey, byte[] integrityKey, IIntegrityAlgo? integrity = null)
        {
            _integrity = integrity ?? HmacIntegrity.HmacSha256_128();
            if (encryptionKey.Length != 16 && encryptionKey.Length != 24 && encryptionKey.Length != 32)
                throw new ArgumentException("AES key must be 16, 24 or 32 bytes.", nameof(encryptionKey));
            if (integrityKey.Length != _integrity.KeySizeInBytes)
                throw new ArgumentException($"Integrity key must be {_integrity.KeySizeInBytes} bytes.", nameof(integrityKey));
            _encryptionKey = encryptionKey;
            _integrityKey = integrityKey;
        }

        /// <inheritdoc/>
        public override byte[] Protect(uint spi, uint sequence, ReadOnlySpan<byte> payload, byte nextHeader)
        {
            // Plaintext = payload | padding(1..n) | PadLength | NextHeader, padded to a 16-byte boundary.
            int unpadded = payload.Length + 2;
            int padLength = (BlockSize - (unpadded % BlockSize)) % BlockSize;
            int plainLength = unpadded + padLength;

            byte[] plain = new byte[plainLength];
            payload.CopyTo(plain);
            for (int i = 0; i < padLength; i++)
                plain[payload.Length + i] = (byte)(i + 1);
            plain[plainLength - 2] = (byte)padLength;
            plain[plainLength - 1] = nextHeader;

            byte[] iv = new byte[IvSize];
            FillRandom(iv);

            byte[] cipherText = new byte[plainLength];
            _cipher.Encrypt(_encryptionKey, iv, plain, cipherText);

            int icvSize = _integrity.IcvSizeInBytes;
            byte[] packet = new byte[EspConstants.HeaderSize + IvSize + plainLength + icvSize];
            EspConstants.WriteHeader(packet, spi, sequence);
            iv.CopyTo(packet.AsSpan(EspConstants.HeaderSize));
            cipherText.CopyTo(packet.AsSpan(EspConstants.HeaderSize + IvSize));

            int macLength = packet.Length - icvSize;
            _integrity.ComputeIcv(_integrityKey, packet.AsSpan(0, macLength), packet.AsSpan(macLength, icvSize));
            return packet;
        }

        /// <inheritdoc/>
        public override bool TryUnprotect(ReadOnlySpan<byte> packet, out byte[] payload, out byte nextHeader)
        {
            payload = Array.Empty<byte>();
            nextHeader = 0;

            int icvSize = _integrity.IcvSizeInBytes;
            int minLength = EspConstants.HeaderSize + IvSize + BlockSize + icvSize;
            if (packet.Length < minLength) return false;

            int macLength = packet.Length - icvSize;
            Span<byte> expected = stackalloc byte[icvSize];
            _integrity.ComputeIcv(_integrityKey, packet.Slice(0, macLength), expected);
            if (!CryptoBytes.FixedTimeEquals(expected, packet.Slice(macLength, icvSize))) return false;

            int cipherLength = macLength - EspConstants.HeaderSize - IvSize;
            if (cipherLength <= 0 || cipherLength % BlockSize != 0) return false;

            ReadOnlySpan<byte> iv = packet.Slice(EspConstants.HeaderSize, IvSize);
            ReadOnlySpan<byte> cipherText = packet.Slice(EspConstants.HeaderSize + IvSize, cipherLength);

            byte[] plain = new byte[cipherLength];
            _cipher.Decrypt(_encryptionKey, iv, cipherText, plain);
            return TryStripTrailer(plain, out payload, out nextHeader);
        }
    }
}
