using TqkLibrary.VpnClient.Crypto;
using Xunit;

namespace TqkLibrary.VpnClient.Crypto.Tests
{
    public class Sha256HashTests
    {
        // FIPS 180-4 / NIST reference SHA-256 digests.
        [Theory]
        [InlineData("", "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855")]
        [InlineData("abc", "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad")]
        [InlineData("abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq",
            "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1")]
        public void Sha256_MatchesReferenceVectors(string asciiInput, string expectedHex)
        {
            var hash = new Sha256Hash();
            Assert.Equal(32, hash.HashSizeInBytes);
            byte[] digest = new byte[hash.HashSizeInBytes];
            hash.ComputeHash(System.Text.Encoding.ASCII.GetBytes(asciiInput), digest);
            Assert.Equal(expectedHex, Convert.ToHexString(digest).ToLowerInvariant());
        }
    }
}
