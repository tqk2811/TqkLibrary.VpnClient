using TqkLibrary.VpnClient.Crypto;
using Poly1305 = Org.BouncyCastle.Crypto.Macs.Poly1305;
using KeyParameter = Org.BouncyCastle.Crypto.Parameters.KeyParameter;

namespace TqkLibrary.VpnClient.Ssh.Cipher
{
    /// <summary>
    /// The <c>chacha20-poly1305@openssh.com</c> AEAD packet cipher (OpenSSH PROTOCOL.chacha20poly1305). It consumes 64
    /// bytes of key material from the SSH KDF, split into two 32-byte ChaCha20 keys:
    /// <list type="bullet">
    /// <item><b>K_2</b> = the <b>first</b> 32 bytes — encrypts the packet payload and derives the per-packet Poly1305 key.</item>
    /// <item><b>K_1</b> = the <b>second</b> 32 bytes — a separate stream cipher that encrypts only the 4-byte packet length,
    /// so an attacker cannot use the length as a decryption oracle for the payload.</item>
    /// </list>
    /// For each packet the ChaCha20 nonce/IV is the packet sequence number as a uint64 in SSH wire (big-endian) order.
    /// The Poly1305 key is the first 32 bytes of the K_2 keystream at block counter 0; the payload is then encrypted with
    /// K_2 from block counter 1. The MAC is Poly1305 over the encrypted-length bytes concatenated with the encrypted
    /// payload, and is checked in constant time before the payload is decrypted. This cipher carries its own MAC, so no
    /// separate MAC algorithm is negotiated. (ChaCha20 here is the original djb 8-byte-nonce/8-byte-counter cipher —
    /// see <see cref="ChaCha20"/>.)
    /// </summary>
    public sealed class ChaCha20Poly1305OpenSshCipher : ISshPacketCipher
    {
        const int KeyBytes = 32;
        const int PolyKeyBytes = 32;
        const int TagBytes = 16;

        readonly ChaCha20 _chacha = new();
        readonly byte[] _payloadKey;  // K_2
        readonly byte[] _lengthKey;   // K_1

        /// <summary>The total key material this cipher consumes from the KDF (64 bytes = K_2 || K_1).</summary>
        public const int KeyMaterialBytes = 64;

        /// <summary>
        /// Builds the cipher from the 64-byte KDF output for one direction. <paramref name="keyMaterial"/> is
        /// <c>K_2 (32) || K_1 (32)</c> exactly as the SSH key derivation produces it (the encryption-key derivation for
        /// this direction, truncated to 64 bytes).
        /// </summary>
        public ChaCha20Poly1305OpenSshCipher(ReadOnlySpan<byte> keyMaterial)
        {
            if (keyMaterial.Length < KeyMaterialBytes)
                throw new ArgumentException($"chacha20-poly1305@openssh.com needs {KeyMaterialBytes} bytes of key material.", nameof(keyMaterial));
            _payloadKey = keyMaterial.Slice(0, KeyBytes).ToArray();      // first 256 bits = K_2
            _lengthKey = keyMaterial.Slice(KeyBytes, KeyBytes).ToArray(); // second 256 bits = K_1
        }

        /// <inheritdoc/>
        public int BlockSize => 8; // chacha20-poly1305@openssh.com pads to an 8-byte boundary

        /// <inheritdoc/>
        public int TagLength => TagBytes;

        /// <inheritdoc/>
        public bool LengthIsEncrypted => true;

        static byte[] SeqNonce(uint sequenceNumber)
        {
            // The IV is the sequence number as a uint64 in SSH wire (big-endian) order — 8 bytes for the djb nonce.
            byte[] nonce = new byte[8];
            nonce[4] = (byte)(sequenceNumber >> 24);
            nonce[5] = (byte)(sequenceNumber >> 16);
            nonce[6] = (byte)(sequenceNumber >> 8);
            nonce[7] = (byte)sequenceNumber;
            return nonce;
        }

        byte[] DerivePolyKey(byte[] nonce)
        {
            // First 32 bytes of K_2 keystream at counter 0 = the one-time Poly1305 key.
            var stream = _chacha.CreateStream(_payloadKey, nonce);
            byte[] polyKey = new byte[PolyKeyBytes];
            stream.NextKeystream(polyKey);
            return polyKey;
        }

        static byte[] ComputeTag(byte[] polyKey, ReadOnlySpan<byte> macData)
        {
            var poly = new Poly1305();
            poly.Init(new KeyParameter(polyKey));
            byte[] data = macData.ToArray();
            poly.BlockUpdate(data, 0, data.Length);
            byte[] tag = new byte[TagBytes];
            poly.DoFinal(tag, 0);
            return tag;
        }

        /// <inheritdoc/>
        public byte[] Seal(ReadOnlySpan<byte> packet, uint sequenceNumber)
        {
            // packet = uint32 packet_length || (padding_length || payload || padding). Encrypt the 4 length bytes with
            // K_1 (counter 0), the rest with K_2 (counter 1), then MAC over the two ciphertexts.
            byte[] nonce = SeqNonce(sequenceNumber);

            byte[] encLength = packet.Slice(0, 4).ToArray();
            _chacha.Transform(_lengthKey, nonce, packet.Slice(0, 4), encLength);

            int bodyLen = packet.Length - 4;
            byte[] encBody = new byte[bodyLen];
            var payloadStream = _chacha.CreateStream(_payloadKey, nonce);
            byte[] polyKey = new byte[PolyKeyBytes];
            payloadStream.NextKeystream(polyKey);     // counter 0, bytes 0..31 → Poly1305 key
            payloadStream.Skip(64 - PolyKeyBytes);    // discard bytes 32..63 → advance to counter 1
            packet.Slice(4).CopyTo(encBody);
            payloadStream.Process(encBody);           // counter 1+ → encrypt body

            byte[] result = new byte[4 + bodyLen + TagBytes];
            Buffer.BlockCopy(encLength, 0, result, 0, 4);
            Buffer.BlockCopy(encBody, 0, result, 4, bodyLen);

            byte[] tag = ComputeTag(polyKey, result.AsSpan(0, 4 + bodyLen));
            Buffer.BlockCopy(tag, 0, result, 4 + bodyLen, TagBytes);
            return result;
        }

        /// <inheritdoc/>
        public uint ReadLength(ReadOnlySpan<byte> firstFourBytes, uint sequenceNumber)
        {
            byte[] nonce = SeqNonce(sequenceNumber);
            byte[] plainLen = new byte[4];
            _chacha.Transform(_lengthKey, nonce, firstFourBytes.Slice(0, 4), plainLen);
            return (uint)((plainLen[0] << 24) | (plainLen[1] << 16) | (plainLen[2] << 8) | plainLen[3]);
        }

        /// <inheritdoc/>
        public bool Open(ReadOnlySpan<byte> wirePacket, uint packetLength, uint sequenceNumber, Span<byte> plaintext)
        {
            // wirePacket = encrypted-length(4) || encrypted-body(packetLength) || tag(16).
            int bodyLen = (int)packetLength;
            int total = 4 + bodyLen;
            if (wirePacket.Length < total + TagBytes) return false;

            byte[] nonce = SeqNonce(sequenceNumber);
            byte[] polyKey = DerivePolyKey(nonce);

            byte[] expectedTag = ComputeTag(polyKey, wirePacket.Slice(0, total));
            ReadOnlySpan<byte> actualTag = wirePacket.Slice(total, TagBytes);
            if (!CryptoBytes.FixedTimeEquals(expectedTag, actualTag)) return false;

            // Decrypt the length (K_1) and the body (K_2 from counter 1) into the plaintext binary packet.
            byte[] plainLen = new byte[4];
            _chacha.Transform(_lengthKey, nonce, wirePacket.Slice(0, 4), plainLen);
            plainLen.CopyTo(plaintext);

            byte[] body = wirePacket.Slice(4, bodyLen).ToArray();
            var payloadStream = _chacha.CreateStream(_payloadKey, nonce);
            payloadStream.Skip(64);                   // skip the counter-0 block (the Poly1305 key)
            payloadStream.Process(body);              // counter 1+ → decrypt body
            body.CopyTo(plaintext.Slice(4));
            return true;
        }
    }
}
