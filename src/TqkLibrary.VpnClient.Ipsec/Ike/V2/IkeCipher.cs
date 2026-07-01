using TqkLibrary.VpnClient.Crypto;
using TqkLibrary.VpnClient.Crypto.Abstractions.Interfaces;
using TqkLibrary.VpnClient.Ipsec.Ike.V2.Enums;

namespace TqkLibrary.VpnClient.Ipsec.Ike.V2
{
    /// <summary>
    /// Encrypts/decrypts IKEv2 messages whose payloads ride inside an Encrypted (SK) payload (RFC 7296 §3.14):
    /// AES-CBC-256 over the inner payload chain, HMAC-SHA-256-128 over the whole message up to the ICV.
    /// Holds both directions' keys — the initiator sends with SK_e/a_i and receives with SK_e/a_r.
    /// </summary>
    public sealed class IkeCipher
    {
        const int IvSize = 16;
        const int BlockSize = 16;

        readonly byte[] _sendEncryptionKey;
        readonly byte[] _sendIntegrityKey;
        readonly byte[] _receiveEncryptionKey;
        readonly byte[] _receiveIntegrityKey;
        readonly IBlockCipher _cipher = new AesCbcCipher();
        readonly IIntegrityAlgo _integrity = HmacIntegrity.HmacSha256_128();

        /// <summary>Creates a cipher with this endpoint's send keys and the peer's keys (used to verify/decrypt).</summary>
        public IkeCipher(byte[] sendEncryptionKey, byte[] sendIntegrityKey, byte[] receiveEncryptionKey, byte[] receiveIntegrityKey)
        {
            _sendEncryptionKey = sendEncryptionKey;
            _sendIntegrityKey = sendIntegrityKey;
            _receiveEncryptionKey = receiveEncryptionKey;
            _receiveIntegrityKey = receiveIntegrityKey;
        }

        /// <summary>Builds an initiator-side cipher from the IKE_SA_INIT key material.</summary>
        public static IkeCipher ForInitiator(IkeKeyMaterial keys)
            => new(keys.SkEi, keys.SkAi, keys.SkEr, keys.SkAr);

        /// <summary>Builds a responder-side cipher (used by the in-process test responder).</summary>
        public static IkeCipher ForResponder(IkeKeyMaterial keys)
            => new(keys.SkEr, keys.SkAr, keys.SkEi, keys.SkAi);

        /// <summary>Encrypts <paramref name="message"/>'s payloads into a single SK payload and returns the full wire bytes.</summary>
        public byte[] EncryptMessage(IkeMessage message)
        {
            var inner = new List<byte>();
            IkeMessage.EncodePayloadChain(inner, message.Payloads);
            IkePayloadType firstInner = message.Payloads.Count > 0 ? message.Payloads[0].Type : IkePayloadType.None;

            int padLength = (BlockSize - ((inner.Count + 1) % BlockSize)) % BlockSize;
            byte[] plaintext = new byte[inner.Count + padLength + 1];
            inner.CopyTo(plaintext);
            for (int i = 0; i < padLength; i++) plaintext[inner.Count + i] = (byte)(i + 1);
            plaintext[plaintext.Length - 1] = (byte)padLength;

            byte[] iv = new byte[IvSize];
            using (var rng = System.Security.Cryptography.RandomNumberGenerator.Create()) rng.GetBytes(iv);
            byte[] ciphertext = new byte[plaintext.Length];
            _cipher.Encrypt(_sendEncryptionKey, iv, plaintext, ciphertext);

            int icvSize = _integrity.IcvSizeInBytes;
            int skBodyLength = IvSize + ciphertext.Length + icvSize;
            int skPayloadLength = 4 + skBodyLength;
            int total = IkeMessage.HeaderSize + skPayloadLength;

            byte[] buffer = new byte[total];
            WriteHeader(buffer, message, IkePayloadType.Encrypted, total);
            int o = IkeMessage.HeaderSize;
            buffer[o] = (byte)firstInner;                 // SK generic header: Next Payload = first inner type
            buffer[o + 1] = 0;                            // critical + reserved
            buffer[o + 2] = (byte)(skPayloadLength >> 8);
            buffer[o + 3] = (byte)skPayloadLength;
            Buffer.BlockCopy(iv, 0, buffer, o + 4, IvSize);
            Buffer.BlockCopy(ciphertext, 0, buffer, o + 4 + IvSize, ciphertext.Length);

            int macLength = total - icvSize;
            _integrity.ComputeIcv(_sendIntegrityKey, buffer.AsSpan(0, macLength), buffer.AsSpan(macLength, icvSize));
            return buffer;
        }

        /// <summary>
        /// Verifies and decrypts an SK-wrapped message. Returns null if integrity fails or the framing is malformed.
        /// </summary>
        public IkeMessage? DecryptMessage(byte[] data)
        {
            int icvSize = _integrity.IcvSizeInBytes;
            if (data.Length < IkeMessage.HeaderSize + 4 + IvSize + BlockSize + icvSize) return null;

            int macLength = data.Length - icvSize;
            Span<byte> expected = stackalloc byte[icvSize];
            _integrity.ComputeIcv(_receiveIntegrityKey, data.AsSpan(0, macLength), expected);
            if (!CryptoBytes.FixedTimeEquals(expected, data.AsSpan(macLength, icvSize))) return null;

            var firstInner = (IkePayloadType)data[IkeMessage.HeaderSize];
            int o = IkeMessage.HeaderSize + 4;
            int cipherLength = macLength - o - IvSize;
            if (cipherLength <= 0 || cipherLength % BlockSize != 0) return null;

            ReadOnlySpan<byte> iv = data.AsSpan(o, IvSize);
            ReadOnlySpan<byte> ciphertext = data.AsSpan(o + IvSize, cipherLength);
            byte[] plaintext = new byte[cipherLength];
            _cipher.Decrypt(_receiveEncryptionKey, iv, ciphertext, plaintext);

            int padLength = plaintext[plaintext.Length - 1];
            int innerLength = plaintext.Length - 1 - padLength;
            if (innerLength < 0) return null;

            var message = new IkeMessage
            {
                InitiatorSpi = data.AsSpan(0, 8).ToArray(),
                ResponderSpi = data.AsSpan(8, 8).ToArray(),
                ExchangeType = (IkeExchangeType)data[18],
                Flags = (IkeHeaderFlags)data[19],
                MessageId = IkeBuffer.ReadUInt32(data, 20),
            };
            IkeMessage.ParsePayloadChain(plaintext.AsSpan(0, innerLength), firstInner, message.Payloads);
            return message;
        }

        static void WriteHeader(byte[] buffer, IkeMessage message, IkePayloadType firstPayload, int totalLength)
        {
            Buffer.BlockCopy(message.InitiatorSpi, 0, buffer, 0, 8);
            Buffer.BlockCopy(message.ResponderSpi, 0, buffer, 8, 8);
            buffer[16] = (byte)firstPayload;
            buffer[17] = IkeMessage.Version2;
            buffer[18] = (byte)message.ExchangeType;
            buffer[19] = (byte)message.Flags;
            buffer[20] = (byte)(message.MessageId >> 24);
            buffer[21] = (byte)(message.MessageId >> 16);
            buffer[22] = (byte)(message.MessageId >> 8);
            buffer[23] = (byte)message.MessageId;
            buffer[24] = (byte)(totalLength >> 24);
            buffer[25] = (byte)(totalLength >> 16);
            buffer[26] = (byte)(totalLength >> 8);
            buffer[27] = (byte)totalLength;
        }
    }
}
