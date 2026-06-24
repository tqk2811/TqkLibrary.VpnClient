using TqkLibrary.VpnClient.Crypto;
using Xunit;

namespace TqkLibrary.VpnClient.Crypto.Tests
{
    /// <summary>
    /// Known-answer tests for the original (djb) ChaCha20 stream cipher — 256-bit key, 8-byte nonce, 64-bit counter,
    /// 20 rounds. The TC1 keystream (all-zero key + nonce) is the canonical vector from
    /// draft-strombergson-chacha-test-vectors. This pins the engine byte-exact (it is the primitive the
    /// chacha20-poly1305@openssh.com AEAD is built on, so any keystream drift would break OpenSSH interop). The stateful
    /// stream also continues past the first 64-byte block (counter 1+), which is exactly how the OpenSSH AEAD reads the
    /// counter-0 block for the Poly1305 key and then encrypts the payload from counter 1.
    /// </summary>
    public class ChaCha20Tests
    {
        // TC1: all-zero 256-bit key, all-zero 8-byte nonce, 20 rounds — first 128 bytes of keystream (blocks 0 and 1).
        const string Tc1Block0 = "76b8e0ada0f13d90405d6ae55386bd28bdd219b8a08ded1aa836efcc8b770dc7da41597c5157488d7724e03fb8d84a376a43b8f41518a11cc387b669b2ee6586";
        const string Tc1Block1 = "9f07e7be5551387a98ba977c732d080dcb0f29a048e3656912c6533e32ee7aed29b721769ce64e43d57133b074d839d531ed1f28510afb45ace10a1f4b794d6f";

        [Fact]
        public void Keystream_MatchesTc1Vector_Block0()
        {
            byte[] key = new byte[32];
            byte[] nonce = new byte[8];
            byte[] keystream = new byte[64];
            new ChaCha20().CreateStream(key, nonce).NextKeystream(keystream);
            Assert.Equal(Tc1Block0, Convert.ToHexString(keystream).ToLowerInvariant());
        }

        [Fact]
        public void Stream_ContinuesAcrossBlocks_MatchesTc1Block1()
        {
            byte[] key = new byte[32];
            byte[] nonce = new byte[8];
            var stream = new ChaCha20().CreateStream(key, nonce);

            byte[] block0 = new byte[64];
            stream.NextKeystream(block0);
            Assert.Equal(Tc1Block0, Convert.ToHexString(block0).ToLowerInvariant());

            // The same stream continues into block 1 (counter 1) — the AEAD relies on this.
            byte[] block1 = new byte[64];
            stream.NextKeystream(block1);
            Assert.Equal(Tc1Block1, Convert.ToHexString(block1).ToLowerInvariant());
        }

        [Fact]
        public void Skip_AdvancesCounterLikeNextKeystream()
        {
            byte[] key = new byte[32];
            byte[] nonce = new byte[8];

            var a = new ChaCha20().CreateStream(key, nonce);
            a.Skip(64);
            byte[] afterSkip = new byte[64];
            a.NextKeystream(afterSkip);
            Assert.Equal(Tc1Block1, Convert.ToHexString(afterSkip).ToLowerInvariant());
        }

        [Fact]
        public void Transform_IsItsOwnInverse()
        {
            byte[] key = new byte[32]; for (int i = 0; i < 32; i++) key[i] = (byte)(i + 1);
            byte[] nonce = { 1, 2, 3, 4, 5, 6, 7, 8 };
            byte[] plaintext = System.Text.Encoding.ASCII.GetBytes("the quick brown fox jumps over the lazy dog");

            byte[] ciphertext = new byte[plaintext.Length];
            new ChaCha20().Transform(key, nonce, plaintext, ciphertext);
            Assert.NotEqual(plaintext, ciphertext);

            byte[] decrypted = new byte[plaintext.Length];
            new ChaCha20().Transform(key, nonce, ciphertext, decrypted);
            Assert.Equal(plaintext, decrypted);
        }
    }
}
