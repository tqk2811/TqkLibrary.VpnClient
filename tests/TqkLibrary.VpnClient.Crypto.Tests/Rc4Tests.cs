using System.Text;
using TqkLibrary.VpnClient.Crypto;
using Xunit;

namespace TqkLibrary.VpnClient.Crypto.Tests
{
    /// <summary>
    /// Known-answer tests for the RC4 stream cipher: the classic Rivest test vectors plus the
    /// RFC 6229 keystream vectors. RC4 is broken (RFC 7465) — exercised here only for the legacy
    /// MPPE/PPTP and SoftEther <c>use_encrypt</c> code paths.
    /// </summary>
    public class Rc4Tests
    {
        static byte[] Hex(string hex) => Convert.FromHexString(hex.Replace(" ", ""));

        // Classic ASCII RC4 test vectors (widely published — e.g. Wikipedia "RC4").
        [Theory]
        [InlineData("Key", "Plaintext", "BBF316E8D940AF0AD3")]
        [InlineData("Wiki", "pedia", "1021BF0420")]
        [InlineData("Secret", "Attack at dawn", "45A01F645FC35B383552544B9BF5")]
        public void Rc4_MatchesClassicVectors(string key, string plaintext, string expectedCipherHex)
        {
            byte[] cipher = Rc4.Apply(Encoding.ASCII.GetBytes(key), Encoding.ASCII.GetBytes(plaintext));
            Assert.Equal(expectedCipherHex, Convert.ToHexString(cipher));
        }

        [Theory]
        [InlineData("Key", "Plaintext", "BBF316E8D940AF0AD3")]
        public void Rc4_Decrypt_RoundTrips(string key, string plaintext, string cipherHex)
        {
            byte[] decrypted = Rc4.Apply(Encoding.ASCII.GetBytes(key), Hex(cipherHex));
            Assert.Equal(plaintext, Encoding.ASCII.GetString(decrypted));
        }

        // RFC 6229 keystream vectors: 40-bit key 0x0102030405.
        [Fact]
        public void Rc4_Rfc6229_40BitKey_Keystream()
        {
            var rc4 = new Rc4(Hex("0102030405"));
            byte[] ks = new byte[32];
            rc4.GenerateKeystream(ks);

            Assert.Equal("B2396305F03DC027CCC3524A0A1118A8", Convert.ToHexString(ks.AsSpan(0, 16).ToArray()));
            Assert.Equal("6982944F18FC82D589C403A47A0D0919", Convert.ToHexString(ks.AsSpan(16, 16).ToArray()));
        }

        // RFC 6229 keystream vectors: 128-bit key 0x0102030405060708090a0b0c0d0e0f10.
        [Fact]
        public void Rc4_Rfc6229_128BitKey_Keystream()
        {
            var rc4 = new Rc4(Hex("0102030405060708090a0b0c0d0e0f10"));
            byte[] ks = new byte[32];
            rc4.GenerateKeystream(ks);

            Assert.Equal("9AC7CC9A609D1EF7B2932899CDE41B97", Convert.ToHexString(ks.AsSpan(0, 16).ToArray()));
            Assert.Equal("5248C4959014126A6E8A84F11D1A9E1C", Convert.ToHexString(ks.AsSpan(16, 16).ToArray()));
        }

        [Fact]
        public void Rc4_GenerateKeystream_EqualsEncryptingZeros()
        {
            byte[] key = Hex("0102030405");
            byte[] zeros = new byte[24];
            byte[] cipher = Rc4.Apply(key, zeros);

            byte[] ks = new byte[24];
            new Rc4(key).GenerateKeystream(ks);
            Assert.Equal(cipher, ks);
        }

        [Fact]
        public void Rc4_Rejects_EmptyKey()
        {
            Assert.Throws<ArgumentException>(() => new Rc4(Array.Empty<byte>()));
        }
    }
}
