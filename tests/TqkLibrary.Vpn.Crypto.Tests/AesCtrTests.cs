using TqkLibrary.Vpn.Crypto;
using Xunit;

namespace TqkLibrary.Vpn.Crypto.Tests
{
    public class AesCtrTests
    {
        // NIST SP 800-38A, F.5.1 CTR-AES128.Encrypt.
        [Fact]
        public void AesCtr_MatchesNistSp80038A_Aes128()
        {
            byte[] key = Convert.FromHexString("2b7e151628aed2a6abf7158809cf4f3c");
            byte[] counter = Convert.FromHexString("f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff");
            byte[] plaintext = Convert.FromHexString(
                "6bc1bee22e409f96e93d7e117393172a" +
                "ae2d8a571e03ac9c9eb76fac45af8e51" +
                "30c81c46a35ce411e5fbc1191a0a52ef" +
                "f69f2445df4f9b17ad2b417be66c3710");
            byte[] expected = Convert.FromHexString(
                "874d6191b620e3261bef6864990db6ce" +
                "9806f66b7970fdff8617187bb9fffdff" +
                "5ae4df3edbd5d35e5b4f09020db03eab" +
                "1e031dda2fbe03d1792170a0f3009cee");

            byte[] output = new byte[plaintext.Length];
            AesCtr.Transform(key, counter, plaintext, output);
            Assert.Equal(expected, output);

            // CTR is symmetric: re-running on the ciphertext recovers the plaintext.
            byte[] roundtrip = new byte[output.Length];
            AesCtr.Transform(key, counter, output, roundtrip);
            Assert.Equal(plaintext, roundtrip);
        }
    }
}
