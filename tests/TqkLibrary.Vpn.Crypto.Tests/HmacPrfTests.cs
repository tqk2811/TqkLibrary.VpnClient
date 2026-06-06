using System.Text;
using TqkLibrary.Vpn.Crypto;
using Xunit;

namespace TqkLibrary.Vpn.Crypto.Tests
{
    public class HmacPrfTests
    {
        // RFC 4231, Test Case 1 — HMAC-SHA-256.
        [Fact]
        public void HmacSha256_MatchesRfc4231_Case1()
        {
            byte[] key = Enumerable.Repeat((byte)0x0b, 20).ToArray();
            byte[] data = Encoding.ASCII.GetBytes("Hi There");

            var prf = HmacPrf.Sha256();
            byte[] output = new byte[prf.OutputSizeInBytes];
            prf.Compute(key, data, output);

            Assert.Equal(
                "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7",
                Convert.ToHexString(output).ToLowerInvariant());
        }

        // RFC 4231, Test Case 2 — HMAC-SHA-256 with short key.
        [Fact]
        public void HmacSha256_MatchesRfc4231_Case2()
        {
            byte[] key = Encoding.ASCII.GetBytes("Jefe");
            byte[] data = Encoding.ASCII.GetBytes("what do ya want for nothing?");

            var prf = HmacPrf.Sha256();
            byte[] output = new byte[prf.OutputSizeInBytes];
            prf.Compute(key, data, output);

            Assert.Equal(
                "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843",
                Convert.ToHexString(output).ToLowerInvariant());
        }
    }
}
