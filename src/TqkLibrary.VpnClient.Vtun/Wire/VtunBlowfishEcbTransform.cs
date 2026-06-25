using TqkLibrary.VpnClient.Crypto;
using TqkLibrary.VpnClient.Vtun.Wire.Interfaces;

namespace TqkLibrary.VpnClient.Vtun.Wire
{
    /// <summary>
    /// The vtun data-plane transform for the default cipher, <b>Blowfish-128-ECB</b> (vtund's <c>VTUN_ENC_BF128ECB</c> —
    /// the <c>encrypt yes</c> / legacy bare-<c>E</c> mode). One frame payload is encrypted independently with
    /// <see cref="Blowfish"/> (ECB, key = <c>MD5(password)</c>, 16 bytes), after vtun's block padding. There is no IV, no
    /// sequence number and no sideband init handshake for the ECB modes (vtund's <c>cipher_enc_state</c> starts at
    /// <c>CIPHER_CODE</c>, so <c>send_msg</c>/<c>send_ib_mesg</c> prepend nothing), so the wire is simply:
    /// <code>frame = BF-ECB( MD5(password), pad(payload) )</code>
    /// <para><b>Padding</b> (vtund's <c>encrypt_buf</c>): <c>pad = blocksize − (len mod blocksize)</c>, always 1..8; the
    /// pad bytes are set to the value <c>pad</c> (PKCS#7). vtund randomizes the first <c>blocksize−1</c> pad bytes only
    /// when the input is already block-aligned (the trailing byte stays <c>= blocksize</c>); that randomization is
    /// irrelevant to the peer, which reads only the last byte as the pad length, so this transform writes deterministic
    /// PKCS#7 padding and decrypts byte-for-byte the same.</para>
    /// ⚠️ ECB has no chaining, no IV and no authentication — it leaks plaintext structure and is malleable. Present only to
    /// interoperate with vtund's default <c>encrypt</c> setting, never as a recommended cipher.
    /// </summary>
    public sealed class VtunBlowfishEcbTransform : IVtunFrameTransform
    {
        const int BlockSize = Blowfish.BlockSizeInBytes; // 8

        readonly Blowfish _blowfish;

        /// <summary>Creates the transform from a vtun password (the key is <c>MD5(password)</c>, 16 bytes).</summary>
        public VtunBlowfishEcbTransform(string password)
            : this(Auth.VtunKeyDerivation.DeriveKey16(password)) { }

        /// <summary>Creates the transform from a raw 16-byte Blowfish-128 key (vtun derives it as <c>MD5(password)</c>).</summary>
        public VtunBlowfishEcbTransform(ReadOnlySpan<byte> key)
        {
            _blowfish = new Blowfish(key);
        }

        /// <inheritdoc/>
        public byte[] Encrypt(ReadOnlySpan<byte> payload)
        {
            // pad = blocksize - (len mod blocksize), always 1..blocksize; pad bytes = pad (PKCS#7).
            int pad = BlockSize - (payload.Length & (BlockSize - 1));
            byte[] buffer = new byte[payload.Length + pad];
            payload.CopyTo(buffer);
            for (int i = payload.Length; i < buffer.Length; i++) buffer[i] = (byte)pad;
            _blowfish.EncryptEcb(buffer);
            return buffer;
        }

        /// <inheritdoc/>
        public byte[] Decrypt(ReadOnlySpan<byte> frame)
        {
            // A valid ECB frame is a non-empty multiple of the block size.
            if (frame.Length == 0 || (frame.Length & (BlockSize - 1)) != 0) return Array.Empty<byte>();

            byte[] buffer = frame.ToArray();
            _blowfish.DecryptEcb(buffer);

            int pad = buffer[buffer.Length - 1];
            if (pad < 1 || pad > BlockSize || pad > buffer.Length) return Array.Empty<byte>(); // bad pad — drop the frame

            int plainLength = buffer.Length - pad;
            byte[] result = new byte[plainLength];
            Array.Copy(buffer, result, plainLength);
            return result;
        }
    }
}
