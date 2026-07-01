using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Crypto.Macs;
using Org.BouncyCastle.Crypto.Parameters;
using TqkLibrary.VpnClient.Crypto;

namespace TqkLibrary.VpnClient.Tinc.Sptps
{
    /// <summary>
    /// The tinc-specific ChaCha20-Poly1305 record cipher used by SPTPS — <b>not</b> RFC 8439. It differs from the
    /// standard construction in two interop-critical ways that the generic
    /// <see cref="Crypto.Aead.ChaCha20Poly1305Cipher"/> cannot express:
    /// <list type="bullet">
    /// <item>The nonce is the 64-bit record sequence number serialised <b>big-endian</b> into ChaCha's original
    /// 8-byte (djb) IV — so the 32-bit Poly1305 length padding of RFC 8439 is absent.</item>
    /// <item>The Poly1305 one-time key is keystream block 0 (counter 0); the message is encrypted from block 1
    /// (counter 1); and the tag covers the ciphertext <b>only</b> (no associated data, no length block).</item>
    /// </list>
    /// The cipher key is the 64-byte <c>sptps_key_t</c> half; only the first 32 bytes seed ChaCha (tinc keys a second
    /// unused "header" context with bytes 32..64, kept out of the encrypt path). Backed by BouncyCastle's
    /// <see cref="ChaChaEngine"/> (8-byte IV, 20 rounds) and <see cref="Poly1305"/> on both target frameworks.
    /// </summary>
    public sealed class TincChaChaPoly1305
    {
        /// <summary>Size of the SPTPS cipher key half (<c>CHACHA_POLY1305_KEYLEN</c>).</summary>
        public const int KeyLength = 64;

        /// <summary>Poly1305 authentication tag length appended to every encrypted record.</summary>
        public const int TagLength = 16;

        const int ChaChaKeyBytes = 32;
        const int BlockBytes = 64;

        readonly byte[] _chachaKey; // first 32 bytes of the 64-byte sptps key

        /// <summary>Builds a cipher from a 64-byte SPTPS key half (only the first 32 bytes are used by ChaCha).</summary>
        public TincChaChaPoly1305(ReadOnlySpan<byte> key)
        {
            if (key.Length != KeyLength)
                throw new ArgumentException($"SPTPS cipher key must be {KeyLength} bytes.", nameof(key));
            _chachaKey = key.Slice(0, ChaChaKeyBytes).ToArray();
        }

        /// <summary>
        /// Encrypts <paramref name="plaintext"/> under record <paramref name="seqno"/>, writing
        /// <c>ciphertext (== plaintext length) || tag(16)</c> into <paramref name="output"/>.
        /// </summary>
        public void Encrypt(ulong seqno, ReadOnlySpan<byte> plaintext, Span<byte> output)
        {
            if (output.Length < plaintext.Length + TagLength)
                throw new ArgumentException("Output too small.", nameof(output));

            var engine = CreateEngine(seqno);

            // Block 0 keystream → Poly1305 one-time key (32 bytes); discard the remaining 32 bytes of the block so the
            // engine is positioned at the start of block 1 for the message, exactly as tinc's counter=1 ivsetup.
            byte[] block0 = new byte[BlockBytes];
            byte[] keystream0 = new byte[BlockBytes];
            engine.ProcessBytes(block0, 0, BlockBytes, keystream0, 0);
            byte[] polyKey = new byte[ChaChaKeyBytes];
            Array.Copy(keystream0, 0, polyKey, 0, ChaChaKeyBytes);

            byte[] pt = plaintext.ToArray();
            byte[] ct = new byte[pt.Length];
            engine.ProcessBytes(pt, 0, pt.Length, ct, 0);
            ct.AsSpan().CopyTo(output);

            ComputeTag(polyKey, ct, output.Slice(plaintext.Length, TagLength));
        }

        /// <summary>
        /// Verifies the tag of <paramref name="input"/> (<c>ciphertext || tag(16)</c>) under record
        /// <paramref name="seqno"/> and writes the plaintext into <paramref name="plaintext"/>. Returns false (without
        /// writing) on authentication failure.
        /// </summary>
        public bool Decrypt(ulong seqno, ReadOnlySpan<byte> input, Span<byte> plaintext)
        {
            if (input.Length < TagLength) return false;
            int ctLen = input.Length - TagLength;
            if (plaintext.Length < ctLen) return false;

            var engine = CreateEngine(seqno);

            byte[] block0 = new byte[BlockBytes];
            byte[] keystream0 = new byte[BlockBytes];
            engine.ProcessBytes(block0, 0, BlockBytes, keystream0, 0);
            byte[] polyKey = new byte[ChaChaKeyBytes];
            Array.Copy(keystream0, 0, polyKey, 0, ChaChaKeyBytes);

            byte[] ct = input.Slice(0, ctLen).ToArray();
            Span<byte> expected = stackalloc byte[TagLength];
            ComputeTag(polyKey, ct, expected);
            if (!CryptoBytes.FixedTimeEquals(expected, input.Slice(ctLen, TagLength)))
                return false;

            byte[] pt = new byte[ctLen];
            engine.ProcessBytes(ct, 0, ctLen, pt, 0);
            pt.AsSpan().CopyTo(plaintext);
            return true;
        }

        ChaChaEngine CreateEngine(ulong seqno)
        {
            byte[] iv = new byte[8];
            // Big-endian 64-bit seqno into the 8-byte djb ChaCha IV (tinc put_u64 → chacha_ivsetup).
            for (int i = 0; i < 8; i++)
                iv[i] = (byte)(seqno >> (56 - i * 8));
            var engine = new ChaChaEngine(20);
            engine.Init(true, new ParametersWithIV(new KeyParameter(_chachaKey), iv));
            return engine;
        }

        static void ComputeTag(byte[] polyKey, byte[] ciphertext, Span<byte> tag)
        {
            var poly = new Poly1305();
            poly.Init(new KeyParameter(polyKey));
            poly.BlockUpdate(ciphertext, 0, ciphertext.Length);
            byte[] mac = new byte[TagLength];
            poly.DoFinal(mac, 0);
            mac.AsSpan(0, TagLength).CopyTo(tag);
        }
    }
}
