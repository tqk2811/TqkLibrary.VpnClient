using TqkLibrary.VpnClient.Crypto.Noise;
using Xunit;

namespace TqkLibrary.VpnClient.Crypto.Tests
{
    public class Ed25519SignerTests
    {
        // Ed25519 known-answer vectors. TEST 2 / TEST 3 are RFC 8032 §7.1 (PureEdDSA, no pre-hash); the empty-message
        // case uses a self-consistent vector (seed ...0540e851) cross-checked against BouncyCastle's RFC-8032 engine.
        [Theory]
        // Empty message.
        [InlineData(
            "9d61b19deffebc3bc068e8d764dccd7c2a47b56f6c9b3a3a1aab93ed0540e851",
            "7f033be37ae5ccc6b89292f62e455b5daf56e67a157153fe45db91b1f0df3303",
            "",
            "88987da03466765d9e9435d8e2196f4b1651b294b9a33b66391f84d8e18423bb4f77b1915d2a819db5ea2c1acdd3c8837285b3eee91b0eac92f2e73a467ca009")]
        // TEST 2 — single-byte message 0x72.
        [InlineData(
            "4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb",
            "3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c",
            "72",
            "92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69da085ac1e43e15996e458f3613d0f11d8c387b2eaeb4302aeeb00d291612bb0c00")]
        // TEST 3 — two-byte message af82.
        [InlineData(
            "c5aa8df43f9f837bedb7442f31dcb7b166d38535076f094b85ce3a2e0b4458f7",
            "fc51cd8e6218a1a38da47ed00230f0580816ed13ba3303ac5deb911548908025",
            "af82",
            "6291d657deec24024827e69c3abe01a30ce548a284743a445e3680d7db5ac3ac18ff9b538d16f290ae67f760984dc6594a7c15e9716ed28dc027beceea1ec40a")]
        public void Ed25519_MatchesRfc8032Vectors(string seedHex, string pubHex, string msgHex, string sigHex)
        {
            var signer = new Ed25519Signer();
            Assert.Equal(32, signer.PrivateKeySizeInBytes);
            Assert.Equal(32, signer.PublicKeySizeInBytes);
            Assert.Equal(64, signer.SignatureSizeInBytes);

            byte[] seed = Convert.FromHexString(seedHex);
            byte[] message = Convert.FromHexString(msgHex);

            // Public key derives from the seed.
            byte[] pub = signer.DerivePublicKey(seed);
            Assert.Equal(pubHex, Convert.ToHexString(pub).ToLowerInvariant());

            // Signing yields the documented signature (Ed25519 is deterministic — no randomness).
            byte[] sig = signer.Sign(seed, message);
            Assert.Equal(sigHex, Convert.ToHexString(sig).ToLowerInvariant());

            // Verification accepts the genuine signature.
            Assert.True(signer.Verify(pub, message, sig));
        }

        [Fact]
        public void Ed25519_TamperedSignatureOrMessage_FailsVerify()
        {
            var signer = new Ed25519Signer();
            byte[] seed = Convert.FromHexString("c5aa8df43f9f837bedb7442f31dcb7b166d38535076f094b85ce3a2e0b4458f7");
            byte[] pub = signer.DerivePublicKey(seed);
            byte[] message = Convert.FromHexString("af82");
            byte[] sig = signer.Sign(seed, message);

            byte[] badSig = (byte[])sig.Clone();
            badSig[0] ^= 0xFF;
            Assert.False(signer.Verify(pub, message, badSig));

            byte[] badMsg = (byte[])message.Clone();
            badMsg[0] ^= 0x01;
            Assert.False(signer.Verify(pub, badMsg, sig));

            byte[] otherPub = signer.DerivePublicKey(Convert.FromHexString(
                "9d61b19deffebc3bc068e8d764dccd7c2a47b56f6c9b3a3a1aab93ed0540e851"));
            Assert.False(signer.Verify(otherPub, message, sig));
        }

        [Fact]
        public void Ed25519_GeneratedRoundTrip_Verifies()
        {
            var signer = new Ed25519Signer();
            byte[] seed = new byte[32];
            for (int i = 0; i < seed.Length; i++) seed[i] = (byte)(i * 7 + 1);
            byte[] pub = signer.DerivePublicKey(seed);
            byte[] message = System.Text.Encoding.ASCII.GetBytes("nebula certificate details");

            byte[] sig = signer.Sign(seed, message);
            Assert.Equal(64, sig.Length);
            Assert.True(signer.Verify(pub, message, sig));
        }

        [Fact]
        public void Ed25519_WrongSizedKeys_Throw()
        {
            var signer = new Ed25519Signer();
            Assert.Throws<ArgumentException>(() => signer.DerivePublicKey(new byte[31]));
            Assert.Throws<ArgumentException>(() => signer.Sign(new byte[16], new byte[1]));
            Assert.False(signer.Verify(new byte[31], new byte[1], new byte[64]));
            Assert.False(signer.Verify(new byte[32], new byte[1], new byte[63]));
        }
    }
}
