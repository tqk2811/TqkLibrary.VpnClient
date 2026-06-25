using TqkLibrary.VpnClient.Vtun.Wire;
using TqkLibrary.VpnClient.Vtun.Wire.Enums;
using TqkLibrary.VpnClient.Vtun.Wire.Interfaces;
using Xunit;

namespace TqkLibrary.VpnClient.Vtun.Tests
{
    /// <summary>
    /// Unit tests for the vtun data-plane encryptor (<c>lfd_encrypt.c</c>'s default Blowfish-128-ECB mode). Golden
    /// ciphertexts are produced by OpenSSL — the exact primitive vtund layers over — so a frame this transform emits is
    /// byte-for-byte what a real vtund decrypts (and vice versa). The reference command for each vector is:
    /// <code>printf &lt;padded payload&gt; | openssl enc -bf-ecb -nopad -K MD5(password) -provider legacy</code>
    /// where the padding is vtun's PKCS#7-style scheme: <c>pad = 8 − (len mod 8)</c>, all pad bytes set to the value
    /// <c>pad</c> (1..8).
    /// </summary>
    public class VtunEncryptorTests
    {
        static byte[] Hex(string hex)
        {
            byte[] b = new byte[hex.Length / 2];
            for (int i = 0; i < b.Length; i++) b[i] = Convert.ToByte(hex.Substring(i * 2, 2), 16);
            return b;
        }

        [Fact]
        public void Bf128Ecb_MatchesOpenSslGoldenVector_5BytePayload()
        {
            // key  = MD5("pass") = 1a1dc91c907325c69271ddf0c944bc72
            // in   = 01 02 03 04 05         (5 bytes; pad = 8-5 = 3 → 01 02 03 04 05 03 03 03)
            // out  = BF-ECB(key, padded)    = 771cf8354baedcbf  (OpenSSL, legacy provider)
            var transform = new VtunBlowfishEcbTransform("pass");
            byte[] frame = transform.Encrypt(Hex("0102030405"));
            Assert.Equal(Hex("771cf8354baedcbf"), frame);
            Assert.Equal(Hex("0102030405"), transform.Decrypt(frame)); // inverse recovers the plaintext
        }

        [Fact]
        public void Bf128Ecb_MatchesOpenSslGoldenVector_3BytePayload()
        {
            // key = MD5("pass"); in = de ad be (pad = 5 → de ad be 05 05 05 05 05); out = 93f42f60588e4ffa
            var transform = new VtunBlowfishEcbTransform("pass");
            byte[] frame = transform.Encrypt(Hex("deadbe"));
            Assert.Equal(Hex("93f42f60588e4ffa"), frame);
            Assert.Equal(Hex("deadbe"), transform.Decrypt(frame));
        }

        [Fact]
        public void Bf128Ecb_MatchesOpenSslGoldenVector_OtherPassword()
        {
            // key = MD5("secret123") = 5d7845ac6ee7cfffafc5fe5f35cf666d
            // in  = 48 69 ("Hi")  (pad = 6 → 48 69 06 06 06 06 06 06); out = 871286fb039e78f3
            var transform = new VtunBlowfishEcbTransform("secret123");
            byte[] frame = transform.Encrypt(Hex("4869"));
            Assert.Equal(Hex("871286fb039e78f3"), frame);
            Assert.Equal(Hex("4869"), transform.Decrypt(frame));
        }

        [Fact]
        public void Bf128Ecb_BlockAlignedPayload_PadsAFullBlock()
        {
            // An 8-byte (block-aligned) payload pads a full extra block (pad = 8); the frame is 2 blocks = 16 bytes,
            // and the inverse still recovers the original 8 bytes (vtund reads only the trailing pad-length byte).
            var transform = new VtunBlowfishEcbTransform("pass");
            byte[] payload = Hex("1122334455667788");
            byte[] frame = transform.Encrypt(payload);
            Assert.Equal(16, frame.Length);
            Assert.Equal(payload, transform.Decrypt(frame));
        }

        [Fact]
        public void Bf128Ecb_RoundTrips_AcrossLengths()
        {
            var transform = new VtunBlowfishEcbTransform("hunter2");
            for (int len = 1; len <= 64; len++)
            {
                byte[] payload = new byte[len];
                for (int i = 0; i < len; i++) payload[i] = (byte)(i * 7 + 1);
                byte[] frame = transform.Encrypt(payload);
                Assert.Equal(0, frame.Length % 8);          // always a whole number of blocks
                Assert.Equal(payload, transform.Decrypt(frame));
            }
        }

        [Fact]
        public void Decrypt_RejectsMalformedFrames()
        {
            var transform = new VtunBlowfishEcbTransform("pass");
            Assert.Empty(transform.Decrypt(Array.Empty<byte>()));   // empty
            Assert.Empty(transform.Decrypt(new byte[5]));           // not a block multiple
        }

        [Fact]
        public void Factory_ResolvesDefaultAndLegacyCiphersToBlowfishEcb()
        {
            IVtunFrameTransform? bf1 = VtunFrameTransformFactory.TryCreate(VtunCipher.Blowfish128Ecb, "pass");
            IVtunFrameTransform? legacy = VtunFrameTransformFactory.TryCreate(VtunCipher.Legacy, "pass");
            Assert.IsType<VtunBlowfishEcbTransform>(bf1);
            Assert.IsType<VtunBlowfishEcbTransform>(legacy);

            // A bare 'E' token parses to cipher id 0 → legacy → Blowfish-128-ECB.
            Assert.Equal(VtunCipher.Legacy, VtunFrameTransformFactory.FromCipherId(0));
            Assert.Equal(VtunCipher.Blowfish128Ecb, VtunFrameTransformFactory.FromCipherId(1));

            // An id this driver does not yet implement returns null (the caller turns it into a precise error).
            Assert.Null(VtunFrameTransformFactory.TryCreate(VtunCipher.Aes256Ofb, "pass"));
        }

        [Fact]
        public void KeyDerivation_32Byte_IsTwoMd5Halves()
        {
            // vtund prep_key(size=32): MD5(pw[0..len/2]) ‖ MD5(pw[len/2..]). For "abcd": MD5("ab") ‖ MD5("cd").
            byte[] key32 = Auth.VtunKeyDerivation.DeriveKey32("abcd");
            Assert.Equal(32, key32.Length);
            using var md5 = System.Security.Cryptography.MD5.Create();
            byte[] firstHalf = md5.ComputeHash(System.Text.Encoding.ASCII.GetBytes("ab"));
            byte[] secondHalf = md5.ComputeHash(System.Text.Encoding.ASCII.GetBytes("cd"));
            Assert.Equal(firstHalf, key32[..16]);
            Assert.Equal(secondHalf, key32[16..]);
        }
    }
}
