using System.Security.Cryptography;
using TqkLibrary.Vpn.Crypto;
using TqkLibrary.Vpn.Crypto.Abstractions.Interfaces;

namespace TqkLibrary.Vpn.Ipsec.Ike.V1
{
    /// <summary>
    /// The IKEv1 CBC encryption state for a phase (RFC 2409 §5.5). It chains the IV: each message is encrypted
    /// with the previous message's last cipher block, so encrypt/decrypt must be driven in protocol order.
    /// ISAKMP pads to the block size and relies on payload lengths to find the real end, so the pad is zeros.
    /// </summary>
    public sealed class IkeV1Cipher
    {
        readonly byte[] _key;
        readonly int _blockSize;
        readonly IBlockCipher _cbc = new AesCbcCipher();
        byte[] _iv;

        /// <summary>Creates the cipher with the negotiated key and the phase's initial IV.</summary>
        public IkeV1Cipher(byte[] key, byte[] initialIv, int blockSize = 16)
        {
            _key = key;
            _blockSize = blockSize;
            _iv = new byte[blockSize];
            Buffer.BlockCopy(initialIv, 0, _iv, 0, Math.Min(blockSize, initialIv.Length));
        }

        /// <summary>The current IV (the last cipher block); used to seed the Quick Mode IV.</summary>
        public byte[] CurrentIv => (byte[])_iv.Clone();

        /// <summary>Encrypts a payload chain (zero-padded to the block size) and advances the IV.</summary>
        public byte[] Encrypt(byte[] plaintext)
        {
            int padded = Math.Max(_blockSize, ((plaintext.Length + _blockSize - 1) / _blockSize) * _blockSize);
            byte[] input = new byte[padded];
            Buffer.BlockCopy(plaintext, 0, input, 0, plaintext.Length);
            byte[] cipher = new byte[padded];
            _cbc.Encrypt(_key, _iv, input, cipher);
            _iv = Tail(cipher);
            return cipher;
        }

        /// <summary>Decrypts a ciphertext blob and advances the IV.</summary>
        public byte[] Decrypt(byte[] ciphertext)
        {
            byte[] plain = new byte[ciphertext.Length];
            _cbc.Decrypt(_key, _iv, ciphertext, plain);
            _iv = Tail(ciphertext);
            return plain;
        }

        /// <summary>Derives the Quick Mode IV for a message id: <c>hash(lastPhase1Iv | M-ID)</c> truncated to the block.</summary>
        public static byte[] QuickModeIv(HashAlgorithmName hash, byte[] lastPhase1Iv, uint messageId, int blockSize = 16)
        {
            byte[] data = new byte[lastPhase1Iv.Length + 4];
            Buffer.BlockCopy(lastPhase1Iv, 0, data, 0, lastPhase1Iv.Length);
            data[lastPhase1Iv.Length] = (byte)(messageId >> 24);
            data[lastPhase1Iv.Length + 1] = (byte)(messageId >> 16);
            data[lastPhase1Iv.Length + 2] = (byte)(messageId >> 8);
            data[lastPhase1Iv.Length + 3] = (byte)messageId;

            byte[] full = IkeV1KeyMaterial.HashBytes(hash, data);
            byte[] iv = new byte[blockSize];
            Buffer.BlockCopy(full, 0, iv, 0, Math.Min(blockSize, full.Length));
            return iv;
        }

        byte[] Tail(byte[] data)
        {
            byte[] tail = new byte[_blockSize];
            Buffer.BlockCopy(data, data.Length - _blockSize, tail, 0, _blockSize);
            return tail;
        }
    }
}
