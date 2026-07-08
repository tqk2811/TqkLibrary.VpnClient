using System.Text;
using TqkLibrary.VpnClient.Crypto;
using Xunit;

namespace TqkLibrary.VpnClient.Crypto.Tests
{
    public class UmacTests
    {
        // RFC 4418 §9 test vectors. Key = "abcdefghijklmnop" (16 bytes), Nonce = "bcdefghi" (8 bytes).
        // Messages are repeated-ASCII patterns; the RFC lists 32-, 64- and 96-bit tags (no 128-bit column).
        static readonly byte[] Key = Encoding.ASCII.GetBytes("abcdefghijklmnop");
        static readonly byte[] Nonce = Encoding.ASCII.GetBytes("bcdefghi");

        static byte[] BuildMessage(string pattern, int totalLen)
        {
            byte[] pat = Encoding.ASCII.GetBytes(pattern);
            byte[] msg = new byte[totalLen];
            for (int i = 0; i < totalLen; i++) msg[i] = pat[i % pat.Length];
            return msg;
        }

        [Theory]
        // pattern, totalBytes,  UMAC-32,   UMAC-64,            UMAC-96
        [InlineData("a", 0, "113145FB", "6E155FAD26900BE1", "32FEDB100C79AD58F07FF764")]           // <empty>
        [InlineData("a", 3, "3B91D102", "44B5CB542F220104", "185E4FE905CBA7BD85E4C2DC")]           // 'a' * 3
        [InlineData("a", 1024, "599B350B", "26BF2F5D60118BD9", "7A54ABE04AF82D60FB298C3C")]        // 'a' * 2^10
        [InlineData("a", 32768, "58DCF532", "27F8EF643B0D118D", "7B136BD911E4B734286EF2BE")]       // 'a' * 2^15
        [InlineData("a", 1048576, "DB6364D1", "A4477E87E9F55853", "F8ACFA3AC31CFEEA047F7B11")]     // 'a' * 2^20
        [InlineData("a", 33554432, "5109A660", "2E2DBC36860A0A5F", "72C6388BACE3ACE6FBF062D9")]    // 'a' * 2^25
        [InlineData("abc", 3, "ABF3A3A0", "D4D7B9F6BD4FBFCF", "883C3D4B97A61976FFCF2323")]         // 'abc' * 1
        [InlineData("abc", 1500, "ABEB3C8B", "D4CF26DDEFD5C01A", "8824A260C53C66A36C9260A6")]      // 'abc' * 500
        public void Umac_MatchesRfc4418Section9Vectors(string pattern, int totalLen, string tag32, string tag64, string tag96)
        {
            byte[] msg = BuildMessage(pattern, totalLen);

            Assert.Equal(tag32, Convert.ToHexString(Umac.ComputeTag(Key, msg, Nonce, 32)));
            Assert.Equal(tag64, Convert.ToHexString(Umac.ComputeTag(Key, msg, Nonce, 64)));
            Assert.Equal(tag96, Convert.ToHexString(Umac.ComputeTag(Key, msg, Nonce, 96)));

            // The RFC has no 128-bit column, but UMAC-128's first 12 bytes are provably identical to UMAC-96
            // (iterations 1..3 of UHASH and the first 12 pad bytes coincide). Check that for the smaller inputs.
            if (totalLen <= 32768)
            {
                byte[] tag128 = Umac.ComputeTag(Key, msg, Nonce, 128);
                Assert.Equal(16, tag128.Length);
                Assert.Equal(tag96, Convert.ToHexString(tag128).Substring(0, 24));
            }
        }

        [Theory]
        [InlineData(32, 4)]
        [InlineData(64, 8)]
        [InlineData(96, 12)]
        [InlineData(128, 16)]
        public void Umac_TagHasRequestedLength(int tagBits, int expectedBytes)
        {
            byte[] tag = Umac.ComputeTag(Key, Encoding.ASCII.GetBytes("hello world"), Nonce, tagBits);
            Assert.Equal(expectedBytes, tag.Length);
        }

        [Fact]
        public void Umac_AcceptsAes256Key()
        {
            byte[] key32 = Encoding.ASCII.GetBytes("abcdefghijklmnopqrstuvwxyz012345"); // 32 bytes
            byte[] tag = Umac.ComputeTag(key32, Encoding.ASCII.GetBytes("payload"), Nonce, 64);
            Assert.Equal(8, tag.Length);
            // Deterministic: same inputs -> same tag.
            byte[] tag2 = Umac.ComputeTag(key32, Encoding.ASCII.GetBytes("payload"), Nonce, 64);
            Assert.Equal(tag, tag2);
        }

        [Fact]
        public void Umac_DifferentNonceProducesDifferentTag()
        {
            byte[] msg = Encoding.ASCII.GetBytes("same message");
            byte[] a = Umac.ComputeTag(Key, msg, Encoding.ASCII.GetBytes("nonce001"), 64);
            byte[] b = Umac.ComputeTag(Key, msg, Encoding.ASCII.GetBytes("nonce002"), 64);
            Assert.NotEqual(a, b);
        }

        [Fact]
        public void Umac_RejectsBadParameters()
        {
            byte[] msg = Encoding.ASCII.GetBytes("m");
            Assert.Throws<ArgumentException>(() => Umac.ComputeTag(new byte[15], msg, Nonce, 64)); // key not 16/32
            Assert.Throws<ArgumentException>(() => Umac.ComputeTag(new byte[0], msg, Nonce, 64));  // empty key
            Assert.Throws<ArgumentException>(() => Umac.ComputeTag(Key, msg, Nonce, 16));          // bad tagBits
            Assert.Throws<ArgumentException>(() => Umac.ComputeTag(Key, msg, Nonce, 0));           // bad tagBits
            Assert.Throws<ArgumentException>(() => Umac.ComputeTag(Key, msg, new byte[0], 64));    // empty nonce
            Assert.Throws<ArgumentException>(() => Umac.ComputeTag(Key, msg, new byte[17], 64));   // nonce > BLOCKLEN
        }
    }
}
