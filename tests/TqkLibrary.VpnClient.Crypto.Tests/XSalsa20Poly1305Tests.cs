using TqkLibrary.VpnClient.Crypto;
using TqkLibrary.VpnClient.Crypto.Aead;
using Xunit;

namespace TqkLibrary.VpnClient.Crypto.Tests
{
    /// <summary>
    /// HSalsa20 + XSalsa20 + XSalsa20-Poly1305 (NaCl <c>crypto_secretbox</c>) pinned byte-exact against the canonical
    /// DJB / NaCl / libsodium test vectors: HSalsa20 subkey = libsodium <c>test/default/core2.c</c> +
    /// <c>core3.c</c> SECONDKEY; the secretbox tag+ciphertext = libsodium <c>test/default/secretbox.c</c> /
    /// <c>secretbox.exp</c>. These are the standard published vectors, independent of any lab.
    /// </summary>
    public class XSalsa20Poly1305Tests
    {
        // NaCl secretbox.c firstkey / nonce (libsodium test/default/secretbox.c).
        const string KeyHex = "1b27556473e985d462cd51197a9a46c76009549eac6474f206c4ee0844f68389";
        const string NonceHex = "69696ee955b62b73cd62bda875fc73d68219e0036b7a0b37";

        // NaCl secretbox.c message m[32..163] (the 32 leading zero bytes of the NaCl API are dropped) and the resulting
        // c[16..32] tag + c[32..163] ciphertext.
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

        // ---- HSalsa20 core (DJB "Extending the Salsa20 nonce" / libsodium crypto_core_hsalsa20, core2/core3) ----

        [Fact]
        public void HSalsa20_MatchesDjbVector()
        {
            byte[] key = Convert.FromHexString(KeyHex);                             // core2 firstkey
            byte[] in16 = Convert.FromHexString("69696ee955b62b73cd62bda875fc73d6"); // core2 nonceprefix = nonce[0:16]
            byte[] expected = Convert.FromHexString("dc908dda0b9344a953629b733820778880f3ceb421bb61b91cbd4c3e66256ce4"); // core3 SECONDKEY

            byte[] output = new byte[HSalsa20.OutputBytes];
            HSalsa20.Hash(key, in16, output);
            Assert.Equal(expected, output);
        }

        [Fact]
        public void HSalsa20_RejectsBadSizes()
        {
            Assert.Throws<ArgumentException>(() => HSalsa20.Hash(new byte[31], new byte[16], new byte[32]));
            Assert.Throws<ArgumentException>(() => HSalsa20.Hash(new byte[32], new byte[15], new byte[32]));
            Assert.Throws<ArgumentException>(() => HSalsa20.Hash(new byte[32], new byte[16], new byte[31]));
        }

        // ---- XSalsa20 keystream (NaCl crypto_stream_xsalsa20 — first 32 bytes = secretbox one-time "rs" key) ----

        [Fact]
        public void XSalsa20_KeystreamMatchesNaClVector()
        {
            byte[] key = Convert.FromHexString(KeyHex);
            byte[] nonce = Convert.FromHexString(NonceHex);
            byte[] expectedRs = Convert.FromHexString("eea6a7251c1e72916d11c2cb214d3c252539121d8e234e652d651fa4c8cff880");

            byte[] ks = new byte[32];
            XSalsa20.GenerateKeystream(key, nonce, ks);
            Assert.Equal(expectedRs, ks);
        }

        [Fact]
        public void XSalsa20_EncryptThenDecrypt_RoundTrips()
        {
            byte[] key = Convert.FromHexString(KeyHex);
            byte[] nonce = Convert.FromHexString(NonceHex);
            byte[] plaintext = System.Text.Encoding.ASCII.GetBytes("XSalsa20 24-byte nonce stream cipher round-trip.");

            byte[] ct = new byte[plaintext.Length];
            XSalsa20.Transform(key, nonce, plaintext, ct);
            Assert.NotEqual(plaintext, ct);

            byte[] recovered = new byte[plaintext.Length];
            XSalsa20.Transform(key, nonce, ct, recovered);
            Assert.Equal(plaintext, recovered);

            // Transform of zeros equals the raw keystream.
            byte[] ks = new byte[plaintext.Length];
            XSalsa20.GenerateKeystream(key, nonce, ks);
            byte[] viaXor = new byte[plaintext.Length];
            for (int i = 0; i < plaintext.Length; i++) viaXor[i] = (byte)(plaintext[i] ^ ks[i]);
            Assert.Equal(ct, viaXor);
        }

        // ---- XSalsa20-Poly1305 = NaCl crypto_secretbox (tests/secretbox.c) ----

        [Fact]
        public void SecretBox_Seal_MatchesNaClVector()
        {
            byte[] key = Convert.FromHexString(KeyHex);
            byte[] nonce = Convert.FromHexString(NonceHex);
            byte[] plaintext = Convert.FromHexString(PlaintextHex);
            byte[] expectedTag = Convert.FromHexString(TagHex);
            byte[] expectedCipher = Convert.FromHexString(CiphertextHex);

            byte[] boxed = XSalsa20Poly1305Cipher.Seal(key, nonce, plaintext);
            Assert.Equal(expectedTag, boxed[..16]);
            Assert.Equal(expectedCipher, boxed[16..]);
        }

        [Fact]
        public void SecretBox_Open_RecoversPlaintext()
        {
            byte[] key = Convert.FromHexString(KeyHex);
            byte[] nonce = Convert.FromHexString(NonceHex);
            byte[] plaintext = Convert.FromHexString(PlaintextHex);
            byte[] tag = Convert.FromHexString(TagHex);
            byte[] cipher = Convert.FromHexString(CiphertextHex);

            bool ok = XSalsa20Poly1305Cipher.Open(key, nonce, tag, cipher, out byte[] recovered);
            Assert.True(ok);
            Assert.Equal(plaintext, recovered);
        }

        [Fact]
        public void SecretBox_SealThenOpen_RoundTrips()
        {
            byte[] key = new byte[32];
            byte[] nonce = new byte[24];
            for (int i = 0; i < key.Length; i++) key[i] = (byte)(i * 7 + 3);
            for (int i = 0; i < nonce.Length; i++) nonce[i] = (byte)(0x40 + i);

            byte[] plaintext = System.Text.Encoding.ASCII.GetBytes("nacltai / cjdns CryptoAuth secretbox payload.");
            byte[] boxed = XSalsa20Poly1305Cipher.Seal(key, nonce, plaintext);

            bool ok = XSalsa20Poly1305Cipher.Open(key, nonce, boxed[..16], boxed[16..], out byte[] recovered);
            Assert.True(ok);
            Assert.Equal(plaintext, recovered);
        }

        [Fact]
        public void SecretBox_Open_RejectsTamperedTag()
        {
            byte[] key = Convert.FromHexString(KeyHex);
            byte[] nonce = Convert.FromHexString(NonceHex);
            byte[] tag = Convert.FromHexString(TagHex);
            byte[] cipher = Convert.FromHexString(CiphertextHex);
            tag[0] ^= 0x01;

            bool ok = XSalsa20Poly1305Cipher.Open(key, nonce, tag, cipher, out byte[] recovered);
            Assert.False(ok);
            Assert.Empty(recovered);
        }

        [Fact]
        public void SecretBox_Open_RejectsTamperedCiphertext()
        {
            byte[] key = Convert.FromHexString(KeyHex);
            byte[] nonce = Convert.FromHexString(NonceHex);
            byte[] tag = Convert.FromHexString(TagHex);
            byte[] cipher = Convert.FromHexString(CiphertextHex);
            cipher[0] ^= 0x01;

            bool ok = XSalsa20Poly1305Cipher.Open(key, nonce, tag, cipher, out byte[] recovered);
            Assert.False(ok);
        }
    }
}
