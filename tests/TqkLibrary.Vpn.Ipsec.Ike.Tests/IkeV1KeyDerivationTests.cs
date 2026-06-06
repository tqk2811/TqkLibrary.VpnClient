using System.Security.Cryptography;
using TqkLibrary.Vpn.Crypto;
using TqkLibrary.Vpn.Ipsec.Ike.V1;
using Xunit;

namespace TqkLibrary.Vpn.Ipsec.Ike.Tests
{
    public class IkeV1KeyDerivationTests
    {
        static readonly byte[] Psk = System.Text.Encoding.ASCII.GetBytes("vpn");

        [Fact]
        public void MainMode_TwoParties_DeriveIdenticalKeysAndHashes()
        {
            var dh = ModpDhGroup.Group2();
            byte[] privI = dh.GeneratePrivateKey(), keI = dh.DerivePublicValue(privI);
            byte[] privR = dh.GeneratePrivateKey(), keR = dh.DerivePublicValue(privR);
            byte[] sharedI = dh.DeriveSharedSecret(privI, keR);
            byte[] sharedR = dh.DeriveSharedSecret(privR, keI);
            Assert.Equal(sharedI, sharedR);

            byte[] ni = Bytes(0x11, 16), nr = Bytes(0x22, 16);
            byte[] cookieI = Bytes(0xA0, 8), cookieR = Bytes(0xB0, 8);

            IkeV1KeyMaterial keysI = IkeV1KeyMaterial.DeriveMainMode(
                HashAlgorithmName.SHA1, Psk, ni, nr, sharedI, cookieI, cookieR, keI, keR, cipherKeyLength: 32, blockSize: 16);
            IkeV1KeyMaterial keysR = IkeV1KeyMaterial.DeriveMainMode(
                HashAlgorithmName.SHA1, Psk, ni, nr, sharedR, cookieI, cookieR, keI, keR, cipherKeyLength: 32, blockSize: 16);

            Assert.Equal(keysI.Skeyid, keysR.Skeyid);
            Assert.Equal(keysI.SkeyidE, keysR.SkeyidE);
            Assert.Equal(keysI.CipherKey, keysR.CipherKey);
            Assert.Equal(32, keysI.CipherKey.Length); // AES-256 expanded from 20-byte SHA1 SKEYID_e
            Assert.Equal(16, keysI.InitialIv.Length);
            Assert.Equal(keysI.InitialIv, keysR.InitialIv);

            var prf = new HmacPrf(HashAlgorithmName.SHA1);
            byte[] saiBody = { 1, 2, 3, 4 };
            byte[] idiBody = { 0x01, 0x11, 0x00, 0x00, 10, 0, 0, 1 };
            byte[] hashIByInitiator = IkeV1Auth.ComputeHashI(prf, keysI.Skeyid, keI, keR, cookieI, cookieR, saiBody, idiBody);
            byte[] hashIByResponder = IkeV1Auth.ComputeHashI(prf, keysR.Skeyid, keI, keR, cookieI, cookieR, saiBody, idiBody);
            Assert.Equal(hashIByInitiator, hashIByResponder);
        }

        [Fact]
        public void Cipher_IvChain_RoundTripsBothDirections()
        {
            byte[] key = Bytes(0x01, 32);
            byte[] iv0 = Bytes(0x80, 16);
            var initiator = new IkeV1Cipher(key, iv0);
            var responder = new IkeV1Cipher(key, iv0);

            byte[] m1 = Bytes(0x40, 30); // not a block multiple → exercises padding
            byte[] c1 = initiator.Encrypt(m1);
            byte[] p1 = responder.Decrypt(c1);
            Assert.Equal(m1, p1[..m1.Length]);

            // Responder replies; its IV is now the last block of c1, matching the initiator's decrypt IV.
            byte[] m2 = Bytes(0x50, 16);
            byte[] c2 = responder.Encrypt(m2);
            byte[] p2 = initiator.Decrypt(c2);
            Assert.Equal(m2, p2[..m2.Length]);
        }

        [Fact]
        public void QuickModeIv_IsDeterministic()
        {
            byte[] last = Bytes(0x33, 16);
            byte[] a = IkeV1Cipher.QuickModeIv(HashAlgorithmName.SHA1, last, 0xDEADBEEF);
            byte[] b = IkeV1Cipher.QuickModeIv(HashAlgorithmName.SHA1, last, 0xDEADBEEF);
            byte[] c = IkeV1Cipher.QuickModeIv(HashAlgorithmName.SHA1, last, 0x00000001);
            Assert.Equal(a, b);
            Assert.NotEqual(a, c);
            Assert.Equal(16, a.Length);
        }

        static byte[] Bytes(byte seed, int length)
        {
            byte[] b = new byte[length];
            for (int i = 0; i < length; i++) b[i] = (byte)(seed + i);
            return b;
        }
    }
}
