using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Crypto.Parameters;
using Xunit;

namespace TqkLibrary.VpnClient.Tinc.Tests
{
    /// <summary>
    /// Known-answer test pinning the ChaCha20 keystream that <see cref="Sptps.TincChaChaPoly1305"/> relies on. tinc's
    /// record cipher uses the original djb ChaCha20 (8-byte nonce + 64-bit counter), which BouncyCastle's
    /// <see cref="ChaChaEngine"/> implements. The all-zero key / all-zero nonce / counter-0 first keystream block is a
    /// well-known vector (draft-nir-cfrg-chacha20-poly1305 Test Vector #1), so this verifies our cipher foundation
    /// matches the variant tincd uses byte-for-byte, independent of the live lab.
    /// </summary>
    public class ChaChaEngineKatTests
    {
        [Fact]
        public void ChaChaEngine_ZeroKeyZeroNonce_FirstBlock_MatchesDjbVector()
        {
            byte[] key = new byte[32];
            byte[] iv = new byte[8];
            var engine = new ChaChaEngine(20);
            engine.Init(true, new ParametersWithIV(new KeyParameter(key), iv));

            byte[] keystream = new byte[64];
            engine.ProcessBytes(new byte[64], 0, 64, keystream, 0);

            byte[] expected = HexToBytes(
                "76b8e0ada0f13d90405d6ae55386bd28bdd219b8a08ded1aa836efcc8b770dc7" +
                "da41597c5157488d7724e03fb8d84a376a43b8f41518a11cc387b669b2ee6586");
            Assert.Equal(expected, keystream);
        }

        [Fact]
        public void ChaChaEngine_CounterAdvancesPerBlock()
        {
            // Second 64-byte block (counter 1) for the zero vector — confirms our "skip block 0 → message at counter 1"
            // assumption in TincChaChaPoly1305 lines up with the engine's natural counter progression.
            byte[] key = new byte[32];
            byte[] iv = new byte[8];
            var engine = new ChaChaEngine(20);
            engine.Init(true, new ParametersWithIV(new KeyParameter(key), iv));
            byte[] twoBlocks = new byte[128];
            engine.ProcessBytes(new byte[128], 0, 128, twoBlocks, 0);

            byte[] block1 = new byte[64];
            System.Array.Copy(twoBlocks, 64, block1, 0, 64);
            byte[] expectedBlock1 = HexToBytes(
                "9f07e7be5551387a98ba977c732d080dcb0f29a048e3656912c6533e32ee7aed" +
                "29b721769ce64e43d57133b074d839d531ed1f28510afb45ace10a1f4b794d6f");
            Assert.Equal(expectedBlock1, block1);
        }

        [Fact]
        public void Poly1305_RfcVector_MatchesTag()
        {
            // RFC 8439 §2.5.2: a fixed one-time key + message → known 16-byte tag. Confirms BouncyCastle's Poly1305
            // (used by TincChaChaPoly1305 to authenticate the ciphertext) is the standard algorithm.
            byte[] key = HexToBytes(
                "85d6be7857556d337f4452fe42d506a80103808afb0db2fd4abff6af4149f51b");
            byte[] msg = System.Text.Encoding.ASCII.GetBytes("Cryptographic Forum Research Group");
            var poly = new Org.BouncyCastle.Crypto.Macs.Poly1305();
            poly.Init(new KeyParameter(key));
            poly.BlockUpdate(msg, 0, msg.Length);
            byte[] tag = new byte[16];
            poly.DoFinal(tag, 0);
            Assert.Equal(HexToBytes("a8061dc1305136c6c22b8baf0c0127a9"), tag);
        }

        static byte[] HexToBytes(string hex)
        {
            byte[] result = new byte[hex.Length / 2];
            for (int i = 0; i < result.Length; i++)
                result[i] = System.Convert.ToByte(hex.Substring(i * 2, 2), 16);
            return result;
        }
    }
}
