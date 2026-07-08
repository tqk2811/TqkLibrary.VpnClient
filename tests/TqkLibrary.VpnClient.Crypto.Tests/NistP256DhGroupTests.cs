using TqkLibrary.VpnClient.Crypto;
using Xunit;

namespace TqkLibrary.VpnClient.Crypto.Tests
{
    public class NistP256DhGroupTests
    {
        // RFC 5903 §8.1 — "256-bit Random ECP Group" (IANA DH group 19) test vector.
        const string I = "C88F01F510D9AC3F70A292DAA2316DE544E9AAB8AFE84049C62A9C57862D1433";
        const string Gix = "DAD0B65394221CF9B051E1FECA5787D098DFE637FC90B9EF945D0C3772581180";
        const string Giy = "5271A0461CDB8252D61F1C456FA3E59AB1F45B33ACCF5F58389E0577B8990BB3";
        const string R = "C6EF9C5D78AE012A011164ACB397CE2088685D8F06BF9BE0B283AB46476BEE53";
        const string Grx = "D12DFB5289C8D4F81208B70270398C342296970A0BCCB74C736FC7554494BF63";
        const string Gry = "56FBF3CA366CC23E8157854C13C58D6AAC23F046ADA30F8353E74F33039872AB";
        const string Girx = "D6840F6B42F6EDAFD13116E0E12565202FEF8E9ECE7DCE03812464D04B9442DE";

        static string Hex(byte[] value) => Convert.ToHexString(value);

        [Fact]
        public void Rfc5903_Section81_PublicAndSharedMatch()
        {
            var dh = new NistP256DhGroup();
            byte[] i = Convert.FromHexString(I);
            byte[] r = Convert.FromHexString(R);
            byte[] pubI = Convert.FromHexString(Gix + Giy); // wire = x ‖ y, no 0x04 prefix
            byte[] pubR = Convert.FromHexString(Grx + Gry);

            // Public values g^i and g^r (64-byte x‖y).
            Assert.Equal(Gix + Giy, Hex(dh.DerivePublicValue(i)));
            Assert.Equal(Grx + Gry, Hex(dh.DerivePublicValue(r)));

            // Shared secret g^ir = x-coordinate (32 bytes), computed from either side.
            Assert.Equal(Girx, Hex(dh.DeriveSharedSecret(i, pubR)));
            Assert.Equal(Girx, Hex(dh.DeriveSharedSecret(r, pubI)));
        }

        [Fact]
        public void GroupIdAndSizes_MatchGroup19()
        {
            var dh = new NistP256DhGroup();
            Assert.Equal(19, dh.GroupId);
            Assert.Equal(64, dh.PublicValueSizeInBytes);

            byte[] priv = dh.GeneratePrivateKey();
            Assert.Equal(32, priv.Length);
            Assert.Equal(64, dh.DerivePublicValue(priv).Length);

            byte[] peerPriv = dh.GeneratePrivateKey();
            byte[] peerPub = dh.DerivePublicValue(peerPriv);
            Assert.Equal(32, dh.DeriveSharedSecret(priv, peerPub).Length);
        }

        [Theory]
        [InlineData(1)]
        [InlineData(2)]
        [InlineData(3)]
        [InlineData(4)]
        [InlineData(5)]
        public void GeneratedKeyPairs_BothPartiesAgree(int _)
        {
            var dh = new NistP256DhGroup();
            byte[] aPriv = dh.GeneratePrivateKey();
            byte[] aPub = dh.DerivePublicValue(aPriv);
            byte[] bPriv = dh.GeneratePrivateKey();
            byte[] bPub = dh.DerivePublicValue(bPriv);

            byte[] aShared = dh.DeriveSharedSecret(aPriv, bPub);
            byte[] bShared = dh.DeriveSharedSecret(bPriv, aPub);

            Assert.Equal(aShared, bShared);
            Assert.Contains(aShared, x => x != 0); // non-trivial secret
        }

        [Fact]
        public void InvalidPeerPoint_Throws()
        {
            var dh = new NistP256DhGroup();
            byte[] priv = dh.GeneratePrivateKey();

            // 64 zero bytes = point (0,0), which is not on the P-256 curve.
            Assert.Throws<ArgumentException>(() => dh.DeriveSharedSecret(priv, new byte[64]));
            // Valid x with a mismatched y (giy of the responder against gix of the initiator) is off-curve.
            byte[] offCurve = Convert.FromHexString(Gix + Gry);
            Assert.Throws<ArgumentException>(() => dh.DeriveSharedSecret(priv, offCurve));
            // Wrong public-value length.
            Assert.Throws<ArgumentException>(() => dh.DeriveSharedSecret(priv, new byte[63]));
        }

        [Fact]
        public void InvalidPrivateKey_Throws()
        {
            var dh = new NistP256DhGroup();
            byte[] validPub = dh.DerivePublicValue(dh.GeneratePrivateKey());

            // Wrong length.
            Assert.Throws<ArgumentException>(() => dh.DerivePublicValue(new byte[31]));
            Assert.Throws<ArgumentException>(() => dh.DeriveSharedSecret(new byte[16], validPub));
            // Out of range: all-0xFF scalar exceeds the group order n.
            byte[] tooBig = new byte[32];
            for (int k = 0; k < tooBig.Length; k++) tooBig[k] = 0xFF;
            Assert.Throws<ArgumentException>(() => dh.DerivePublicValue(tooBig));
        }
    }
}
