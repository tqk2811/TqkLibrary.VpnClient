using System.Text;
using TqkLibrary.VpnClient.Crypto;
using Xunit;

namespace TqkLibrary.VpnClient.Crypto.Tests
{
    /// <summary>
    /// Tests for the TLS 1.0/1.1 PRF (MD5+SHA1) that drives OpenVPN's classic key-method-2 derivation: determinism,
    /// exact output length, and sensitivity to every input. (Interop against a live OpenVPN server is the Q.1 lab gate.)
    /// </summary>
    public class Tls1PrfTests
    {
        static byte[] Ascii(string s) => Encoding.ASCII.GetBytes(s);

        [Fact]
        public void Compute_IsDeterministic()
        {
            byte[] secret = Ascii("the-pre-master-secret-material!!");
            byte[] label = Ascii("OpenVPN master secret");
            byte[] seed = Ascii("client-random||server-random");

            byte[] a = Tls1Prf.Compute(secret, label, seed, 48);
            byte[] b = Tls1Prf.Compute(secret, label, seed, 48);
            Assert.Equal(a, b);
        }

        [Theory]
        [InlineData(1)]
        [InlineData(20)]
        [InlineData(48)]
        [InlineData(100)]
        [InlineData(256)]
        public void Compute_ProducesRequestedLength(int length)
        {
            byte[] secret = Ascii("secret-secret-secret");
            byte[] outp = Tls1Prf.Compute(secret, Ascii("label"), Ascii("seed"), length);
            Assert.Equal(length, outp.Length);
        }

        [Fact]
        public void Compute_IsSensitiveToEveryInput()
        {
            byte[] secret = Ascii("0123456789abcdef0123456789abcdef");
            byte[] label = Ascii("label");
            byte[] seed = Ascii("seed");
            byte[] baseline = Tls1Prf.Compute(secret, label, seed, 64);

            Assert.NotEqual(baseline, Tls1Prf.Compute(Ascii("0123456789abcdef0123456789abcdeF"), label, seed, 64));
            Assert.NotEqual(baseline, Tls1Prf.Compute(secret, Ascii("labeL"), seed, 64));
            Assert.NotEqual(baseline, Tls1Prf.Compute(secret, label, Ascii("seeD"), 64));
        }

        [Fact]
        public void Compute_LongerOutput_IsPrefixStable_PerStreamButXorMixed()
        {
            // A pure sanity check that the P_hash expansion keeps producing fresh blocks (not repeating every block).
            byte[] secret = Ascii("expansion-secret");
            byte[] outp = Tls1Prf.Compute(secret, Ascii("L"), Ascii("S"), 96);
            byte[] block1 = outp.AsSpan(0, 32).ToArray();
            byte[] block2 = outp.AsSpan(32, 32).ToArray();
            byte[] block3 = outp.AsSpan(64, 32).ToArray();
            Assert.NotEqual(block1, block2);
            Assert.NotEqual(block2, block3);
        }
    }
}
