using TqkLibrary.VpnClient.Crypto.Abstractions.Interfaces;
using TqkLibrary.VpnClient.Crypto.Aead;

namespace TqkLibrary.VpnClient.Tailscale.Control.Noise
{
    /// <summary>
    /// The post-handshake ts2021 transport record cipher (control/controlbase <c>conn.go</c>): one direction's
    /// ChaCha20-Poly1305 key with its own monotonic 64-bit nonce counter. Each record frame seals/opens one plaintext
    /// chunk (≤ <see cref="MaxPlaintextSize"/> bytes) with <b>empty</b> associated data and a 12-byte nonce
    /// <c>0x00000000 || counter(big-endian)</c> that starts at 0 and increments once per record. The framing header
    /// (<c>[type][len]</c>) is added by <see cref="Ts2021FrameCodec"/> and is <b>not</b> part of the AEAD AAD.
    /// <para>
    /// The client uses two of these: the send cipher keyed with the first <see cref="Ts2021NoiseHandshake.Split"/>
    /// output and the receive cipher with the second (standard Noise initiator orientation).
    /// </para>
    /// </summary>
    public sealed class Ts2021Transport
    {
        /// <summary>The maximum ChaCha20-Poly1305 message size (controlbase <c>maxMessageSize</c>).</summary>
        public const int MaxMessageSize = 4096;

        /// <summary>The maximum ciphertext+tag per record (<c>maxMessageSize - 3</c> header).</summary>
        public const int MaxCiphertextSize = MaxMessageSize - Ts2021FrameCodec.HeaderLength;

        /// <summary>The maximum plaintext per record (<c>maxCiphertextSize - 16</c> tag) = 4077 bytes.</summary>
        public const int MaxPlaintextSize = MaxCiphertextSize - TagSize;

        const int NonceSize = 12;
        const int TagSize = 16;

        readonly IAeadCipher _cipher;
        readonly byte[] _key;
        ulong _counter;

        /// <summary>Creates the cipher from a 32-byte transport key (a <see cref="Ts2021NoiseHandshake.Split"/> output).</summary>
        public Ts2021Transport(byte[] key, IAeadCipher? cipher = null)
        {
            if (key is null || key.Length != 32) throw new ArgumentException("Transport key must be 32 bytes.", nameof(key));
            _key = (byte[])key.Clone();
            _cipher = cipher ?? new ChaCha20Poly1305Cipher();
        }

        /// <summary>
        /// Seals one plaintext chunk into <c>ciphertext || tag</c> with the current nonce, then advances the counter.
        /// <paramref name="plaintext"/> must be ≤ <see cref="MaxPlaintextSize"/> bytes. Returns a fresh buffer of length
        /// <c>plaintext.Length + 16</c>.
        /// </summary>
        public byte[] Seal(ReadOnlySpan<byte> plaintext)
        {
            if (plaintext.Length > MaxPlaintextSize)
                throw new ArgumentOutOfRangeException(nameof(plaintext), "Record plaintext exceeds the maximum size.");
            byte[] output = new byte[plaintext.Length + TagSize];
            Span<byte> nonce = stackalloc byte[NonceSize];
            WriteNonce(nonce);
            _cipher.Seal(_key, nonce, plaintext, ReadOnlySpan<byte>.Empty,
                output.AsSpan(0, plaintext.Length), output.AsSpan(plaintext.Length));
            _counter++;
            return output;
        }

        /// <summary>
        /// Opens one record's <c>ciphertext || tag</c> with the current nonce. On success writes the plaintext to a
        /// fresh buffer, advances the counter and returns it; on authentication failure returns <c>null</c> and leaves
        /// the counter unchanged.
        /// </summary>
        public byte[]? Open(ReadOnlySpan<byte> ciphertextAndTag)
        {
            if (ciphertextAndTag.Length < TagSize) return null;
            int plainLen = ciphertextAndTag.Length - TagSize;
            byte[] plaintext = new byte[plainLen];
            Span<byte> nonce = stackalloc byte[NonceSize];
            WriteNonce(nonce);
            bool ok = _cipher.Open(_key, nonce,
                ciphertextAndTag.Slice(0, plainLen), ciphertextAndTag.Slice(plainLen, TagSize),
                ReadOnlySpan<byte>.Empty, plaintext);
            if (!ok) return null;
            _counter++;
            return plaintext;
        }

        // 12-byte nonce: 4 zero bytes then the 64-bit counter big-endian (controlbase nonce.Increment).
        void WriteNonce(Span<byte> nonce)
        {
            nonce.Clear();
            ulong c = _counter;
            for (int i = 0; i < 8; i++)
                nonce[4 + i] = (byte)(c >> (56 - i * 8));
        }
    }
}
