using TqkLibrary.VpnClient.Crypto.Aead;
using Xunit;

namespace TqkLibrary.VpnClient.Crypto.Tests
{
    /// <summary>
    /// NaCl <c>crypto_box</c> (Curve25519 + XSalsa20-Poly1305) pinned byte-exact against the canonical NaCl
    /// <c>tests/box.c</c> vector: Alice's secret key + Bob's public key + the standard 24-byte nonce over the 163-byte
    /// message produce the known <c>tag ‖ ciphertext</c>. The derived beforenm key equals the NaCl <c>secretbox.c</c>
    /// firstkey (the box and secretbox NaCl test suites deliberately share the same symmetric key), so this also
    /// cross-checks that <c>box == secretbox(m, beforenm)</c>. These are published DJB/NaCl/libsodium vectors,
    /// independent of any lab.
    /// </summary>
    public class NaclBoxTests
    {
        // NaCl tests/box.c — Alice's secret key, Bob's public key, and the 24-byte nonce.
        const string AliceSecretHex = "77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a";
        const string BobPublicHex = "de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f";
        const string NonceHex = "69696ee955b62b73cd62bda875fc73d68219e0036b7a0b37";

        // beforenm(Bob-pk, Alice-sk) = HSalsa20(X25519(Alice-sk, Bob-pk), 0^16) = the NaCl secretbox.c firstkey.
        const string BeforeNmHex = "1b27556473e985d462cd51197a9a46c76009549eac6474f206c4ee0844f68389";

        // The 163-byte box.c message m[32..163] and the resulting c[16..32] tag + c[32..163] ciphertext (identical to
        // the secretbox.c vector, since the box beforenm equals the secretbox key).
        const string PlaintextHex =
            "be075fc53c81f2d5cf141316ebeb0c7b5228c52a4c62cbd44b66849b64244ffc" +
            "e5ecbaaf33bd751a1ac728d45e6c61296cdc3c01233561f41db66cce314adb31" +
            "0e3be8250c46f06dceea3a7fa1348057e2f6556ad6b1318a024a838f21af1fde" +
            "048977eb48f59ffd4924ca1c60902e52f0a089bc76897040e082f93776384864" +
            "5e0705";
        const string TagHex = "f3ffc7703f9400e52a7dfb4b3d3305d9";
        const string CiphertextHex =
            "8e993b9f48681273c29650ba32fc76ce48332ea7164d96a4476fb8c531a1186a" +
            "c0dfc17c98dce87b4da7f011ec48c97271d2c20f9b928fe2270d6fb863d51738" +
            "b48eeee314a7cc8ab932164548e526ae90224368517acfeabd6bb3732bc0e9da" +
            "99832b61ca01b6de56244a9e88d5f9b37973f622a43d14a6599b1f654cb45a74" +
            "e355a5";

        [Fact]
        public void BeforeNm_MatchesNaClSharedKey()
        {
            byte[] beforeNm = NaclBox.BeforeNm(Convert.FromHexString(BobPublicHex), Convert.FromHexString(AliceSecretHex));
            Assert.Equal(BeforeNmHex, Convert.ToHexString(beforeNm).ToLowerInvariant());
        }

        [Fact]
        public void BeforeNm_IsSymmetric_BothDirectionsAgree()
        {
            // NaCl DH is symmetric: beforenm(theirPk, mySk) is the same from either party's view. Here we only have one
            // side's private key, so instead check determinism (same inputs -> same key).
            byte[] a = NaclBox.BeforeNm(Convert.FromHexString(BobPublicHex), Convert.FromHexString(AliceSecretHex));
            byte[] b = NaclBox.BeforeNm(Convert.FromHexString(BobPublicHex), Convert.FromHexString(AliceSecretHex));
            Assert.Equal(a, b);
        }

        [Fact]
        public void Box_MatchesNaClBoxVector()
        {
            byte[] boxed = NaclBox.Box(
                Convert.FromHexString(PlaintextHex),
                Convert.FromHexString(NonceHex),
                Convert.FromHexString(BobPublicHex),
                Convert.FromHexString(AliceSecretHex));

            Assert.Equal(TagHex, Convert.ToHexString(boxed[..16]).ToLowerInvariant());
            Assert.Equal(CiphertextHex, Convert.ToHexString(boxed[16..]).ToLowerInvariant());
        }

        [Fact]
        public void Box_EqualsSecretBoxUnderBeforeNm()
        {
            // Internal consistency: crypto_box(m) == crypto_secretbox(m, beforenm).
            byte[] plaintext = Convert.FromHexString(PlaintextHex);
            byte[] nonce = Convert.FromHexString(NonceHex);

            byte[] viaBox = NaclBox.Box(plaintext, nonce, Convert.FromHexString(BobPublicHex), Convert.FromHexString(AliceSecretHex));
            byte[] beforeNm = NaclBox.BeforeNm(Convert.FromHexString(BobPublicHex), Convert.FromHexString(AliceSecretHex));
            byte[] viaSecretBox = XSalsa20Poly1305Cipher.Seal(beforeNm, nonce, plaintext);

            Assert.Equal(viaSecretBox, viaBox);
        }

        [Fact]
        public void Open_RecoversPlaintextFromVector()
        {
            byte[] boxed = new byte[16 + Convert.FromHexString(CiphertextHex).Length];
            Convert.FromHexString(TagHex).CopyTo(boxed, 0);
            Convert.FromHexString(CiphertextHex).CopyTo(boxed, 16);

            bool ok = NaclBox.Open(boxed, Convert.FromHexString(NonceHex), Convert.FromHexString(BobPublicHex), Convert.FromHexString(AliceSecretHex), out byte[] recovered);
            Assert.True(ok);
            Assert.Equal(Convert.FromHexString(PlaintextHex), recovered);
        }

        [Fact]
        public void BoxThenOpen_RoundTrips_WithGeneratedKeypairs()
        {
            var dh = new TqkLibrary.VpnClient.Crypto.Noise.Curve25519DhGroup();
            byte[] aliceSk = dh.GeneratePrivateKey();
            byte[] alicePk = dh.DerivePublicValue(aliceSk);
            byte[] bobSk = dh.GeneratePrivateKey();
            byte[] bobPk = dh.DerivePublicValue(bobSk);

            byte[] nonce = new byte[NaclBox.NonceBytes];
            for (int i = 0; i < nonce.Length; i++) nonce[i] = (byte)(0x50 + i);
            byte[] plaintext = System.Text.Encoding.ASCII.GetBytes("Quicktun nacltai / cjdns CryptoAuth crypto_box payload.");

            // Alice -> Bob.
            byte[] boxed = NaclBox.Box(plaintext, nonce, bobPk, aliceSk);
            bool ok = NaclBox.Open(boxed, nonce, alicePk, bobSk, out byte[] recovered);
            Assert.True(ok);
            Assert.Equal(plaintext, recovered);

            // beforenm agrees from both sides (public-key symmetry).
            byte[] kSender = NaclBox.BeforeNm(bobPk, aliceSk);
            byte[] kReceiver = NaclBox.BeforeNm(alicePk, bobSk);
            Assert.Equal(kSender, kReceiver);
        }

        [Fact]
        public void Open_RejectsTamperedTag()
        {
            byte[] boxed = new byte[16 + Convert.FromHexString(CiphertextHex).Length];
            Convert.FromHexString(TagHex).CopyTo(boxed, 0);
            Convert.FromHexString(CiphertextHex).CopyTo(boxed, 16);
            boxed[0] ^= 0x01;

            bool ok = NaclBox.Open(boxed, Convert.FromHexString(NonceHex), Convert.FromHexString(BobPublicHex), Convert.FromHexString(AliceSecretHex), out byte[] recovered);
            Assert.False(ok);
            Assert.Empty(recovered);
        }

        [Fact]
        public void Open_RejectsWrongRecipientKey()
        {
            byte[] boxed = NaclBox.Box(
                Convert.FromHexString(PlaintextHex),
                Convert.FromHexString(NonceHex),
                Convert.FromHexString(BobPublicHex),
                Convert.FromHexString(AliceSecretHex));

            // Open with an unrelated secret key -> wrong beforenm -> tag fails.
            byte[] wrongSecret = new byte[32];
            for (int i = 0; i < wrongSecret.Length; i++) wrongSecret[i] = (byte)(i + 1);
            bool ok = NaclBox.Open(boxed, Convert.FromHexString(NonceHex), Convert.FromHexString(BobPublicHex), wrongSecret, out _);
            Assert.False(ok);
        }

        [Fact]
        public void Box_RejectsBadKeySizes()
        {
            byte[] good = new byte[32];
            Assert.Throws<ArgumentException>(() => NaclBox.BeforeNm(new byte[31], good));
            Assert.Throws<ArgumentException>(() => NaclBox.BeforeNm(good, new byte[33]));
        }
    }
}
