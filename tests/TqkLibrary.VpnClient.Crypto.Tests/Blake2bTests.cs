using TqkLibrary.VpnClient.Crypto;
using Xunit;

namespace TqkLibrary.VpnClient.Crypto.Tests
{
    /// <summary>
    /// BLAKE2b (RFC 7693) pinned byte-exact against the canonical published vectors: the RFC 7693 Appendix A example
    /// (<c>BLAKE2b-512("abc")</c>) for the unkeyed hash and the official BLAKE2 <c>blake2b-kat.txt</c> keyed KAT
    /// (64-byte sequential key 00..3f) for the MAC. Independent of any lab.
    /// </summary>
    public class Blake2bTests
    {
        // RFC 7693 Appendix A — BLAKE2b-512("abc").
        [Fact]
        public void Blake2b512_Abc_MatchesRfc7693AppendixA()
        {
            byte[] digest = Blake2b.Hash(System.Text.Encoding.ASCII.GetBytes("abc"));
            Assert.Equal(64, digest.Length);
            Assert.Equal(
                "ba80a53f981c4d0d6a2797b69f12f6e94c212f14685ac4b74b12bb6fdbffa2d1" +
                "7d87c5392aab792dc252d5de4533cc9518d38aa8dbf1925ab92386edd4009923",
                Convert.ToHexString(digest).ToLowerInvariant());
        }

        // Well-known reference digests for the empty input at two output lengths (libsodium/BLAKE2 references).
        [Theory]
        [InlineData(64, "786a02f742015903c6c6fd852552d272912f4740e15847618a86e217f71f5419d25e1031afee585313896444934eb04b903a685b1448b755d56f701afe9be2ce")]
        [InlineData(32, "0e5751c026e543b2e8ab2eb06099daa1d1e5df47778f7787faab45cdf12fe3a8")]
        public void Blake2b_EmptyInput_MatchesReferenceVectors(int outputBytes, string expectedHex)
        {
            byte[] digest = Blake2b.Hash(ReadOnlySpan<byte>.Empty, outputBytes);
            Assert.Equal(outputBytes, digest.Length);
            Assert.Equal(expectedHex, Convert.ToHexString(digest).ToLowerInvariant());
        }

        [Fact]
        public void Blake2b_SpanOverload_MatchesByteArrayOverload()
        {
            byte[] input = System.Text.Encoding.ASCII.GetBytes("blake2b span overload");
            byte[] viaArray = Blake2b.Hash(input, 48);
            byte[] viaSpan = new byte[48];
            Blake2b.Hash(input, viaSpan);
            Assert.Equal(viaArray, viaSpan);
        }

        [Fact]
        public void Blake2b_BadOutputLength_Throws()
        {
            Assert.Throws<ArgumentException>(() => Blake2b.Hash(ReadOnlySpan<byte>.Empty, 0));
            Assert.Throws<ArgumentException>(() => Blake2b.Hash(ReadOnlySpan<byte>.Empty, 65));
            Assert.Throws<ArgumentException>(() => Blake2b.Hash(ReadOnlySpan<byte>.Empty, new byte[0]));
            Assert.Throws<ArgumentException>(() => Blake2b.Hash(ReadOnlySpan<byte>.Empty, new byte[65]));
        }

        // Official keyed-BLAKE2b KAT (blake2b-kat.txt): 64-byte sequential key 00..3f.
        [Theory]
        // Entry 1: in = empty.
        [InlineData("", "10ebb67700b1868efb4417987acf4690ae9d972fb7a590c2f02871799aaa4786b5e996e8f0f4eb981fc214b005f42d2ff4233499391653df7aefcbc13fc51568")]
        // Entry 2: in = "00".
        [InlineData("00", "961f6dd1e4dd30f63901690c512e78e4b45e4742ed197c3c5e45c549fd25f2e4187b0bc9fe30492b16b0d0bc4ef9b0f34c7003fac09a5ef1532e69430234cebd")]
        public void Blake2bKeyedMac_MatchesOfficialKat(string inputHex, string expectedHex)
        {
            byte[] key = new byte[64];
            for (int i = 0; i < key.Length; i++) key[i] = (byte)i;
            byte[] input = inputHex.Length == 0 ? Array.Empty<byte>() : Convert.FromHexString(inputHex);

            byte[] mac = new byte[64];
            Blake2bKeyedMac.ComputeMac(key, input, mac);
            Assert.Equal(expectedHex, Convert.ToHexString(mac).ToLowerInvariant());
        }

        [Fact]
        public void Blake2bKeyedMac_ShortOutput_IsDeterministicAndKeySensitive()
        {
            byte[] keyA = new byte[32];
            byte[] keyB = new byte[32];
            keyB[0] = 0x01;
            byte[] input = System.Text.Encoding.ASCII.GetBytes("yggdrasil node id");

            byte[] a1 = new byte[16], a2 = new byte[16], b = new byte[16];
            Blake2bKeyedMac.ComputeMac(keyA, input, a1);
            Blake2bKeyedMac.ComputeMac(keyA, input, a2);
            Blake2bKeyedMac.ComputeMac(keyB, input, b);

            Assert.Equal(a1, a2);   // deterministic
            Assert.NotEqual(a1, b); // sensitive to the key
        }

        [Fact]
        public void Blake2bKeyedMac_BadSizes_Throw()
        {
            byte[] key = new byte[32];
            Assert.Throws<ArgumentException>(() => Blake2bKeyedMac.ComputeMac(key, ReadOnlySpan<byte>.Empty, new byte[0]));
            Assert.Throws<ArgumentException>(() => Blake2bKeyedMac.ComputeMac(key, ReadOnlySpan<byte>.Empty, new byte[65]));
            Assert.Throws<ArgumentException>(() => Blake2bKeyedMac.ComputeMac(new byte[65], ReadOnlySpan<byte>.Empty, new byte[32]));
        }
    }
}
