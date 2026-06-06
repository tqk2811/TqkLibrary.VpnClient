using TqkLibrary.Vpn.Crypto.Aead;
using Xunit;

namespace TqkLibrary.Vpn.Crypto.Tests
{
    public class AesGcmCipherTests
    {
        // NIST GCM test vector (McGrew/Viega Test Case 4, AES-128).
        [Fact]
        public void AesGcm_SealMatchesNistTestCase4()
        {
            byte[] key = Convert.FromHexString("feffe9928665731c6d6a8f9467308308");
            byte[] nonce = Convert.FromHexString("cafebabefacedbaddecaf888");
            byte[] plaintext = Convert.FromHexString(
                "d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a72" +
                "1c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b39");
            byte[] aad = Convert.FromHexString("feedfacedeadbeeffeedfacedeadbeefabaddad2");
            byte[] expectedCt = Convert.FromHexString(
                "42831ec2217774244b7221b784d0d49ce3aa212f2c02a4e035c17e2329aca12e" +
                "21d514b25466931c7d8f6a5aac84aa051ba30b396a0aac973d58e091");
            byte[] expectedTag = Convert.FromHexString("5bc94fbc3221a5db94fae95ae7121a47");

            var cipher = new AesGcmCipher(keySizeInBytes: 16);
            byte[] ct = new byte[plaintext.Length];
            byte[] tag = new byte[cipher.TagSizeInBytes];
            cipher.Seal(key, nonce, plaintext, aad, ct, tag);

            Assert.Equal(expectedCt, ct);
            Assert.Equal(expectedTag, tag);
        }

        [Fact]
        public void AesGcm_OpenRoundtripsAndDetectsTamper()
        {
            byte[] key = Convert.FromHexString("feffe9928665731c6d6a8f9467308308");
            byte[] nonce = Convert.FromHexString("cafebabefacedbaddecaf888");
            byte[] plaintext = Convert.FromHexString("d9313225f88406e5a55909c5aff5269a");
            byte[] aad = Convert.FromHexString("feedfacedeadbeef");

            var cipher = new AesGcmCipher(keySizeInBytes: 16);
            byte[] ct = new byte[plaintext.Length];
            byte[] tag = new byte[cipher.TagSizeInBytes];
            cipher.Seal(key, nonce, plaintext, aad, ct, tag);

            byte[] recovered = new byte[plaintext.Length];
            Assert.True(cipher.Open(key, nonce, ct, tag, aad, recovered));
            Assert.Equal(plaintext, recovered);

            // Flip a tag bit -> authentication must fail.
            tag[0] ^= 0x01;
            Assert.False(cipher.Open(key, nonce, ct, tag, aad, recovered));
        }
    }
}
