using System.Globalization;
using TqkLibrary.VpnClient.Crypto.Aead;
using TqkLibrary.VpnClient.WireGuard;
using TqkLibrary.VpnClient.WireGuard.Handshake;
using TqkLibrary.VpnClient.WireGuard.Handshake.Models;
using Xunit;

namespace TqkLibrary.VpnClient.WireGuard.Tests
{
    /// <summary>
    /// Offline tests for the V3.c DoS-mitigation layer: mac1 (keyed-BLAKE2s over the recipient's static key), mac2
    /// (keyed by a cookie), and the XChaCha20-Poly1305 cookie-reply (type 3). Covers mac1 agreement between
    /// initiator and responder, rejection of a forged mac1, and a full cookie-reply round-trip whose recovered
    /// cookie produces a mac2 the responder re-validates. Also pins HChaCha20 / XChaCha20-Poly1305 against the
    /// draft-irtf-cfrg-xchacha test vectors so the cookie cipher is correct on both TFMs.
    /// </summary>
    public class WireGuardMacCookieTests
    {
        static readonly WireGuardMessageCodec Codec = new();

        static WireGuardKeyPair NewStatic() => new WireGuardHandshake(
            new WireGuardKeyPair { PrivateKey = new byte[32], PublicKey = new byte[32] }).GenerateKeyPair();

        static (WireGuardHandshake initiator, WireGuardHandshake responder, WireGuardKeyPair iStatic, WireGuardKeyPair rStatic) BuildPair()
        {
            WireGuardKeyPair iStatic = NewStatic();
            WireGuardKeyPair rStatic = NewStatic();
            var initiator = new WireGuardHandshake(iStatic, remoteStaticPublic: rStatic.PublicKey);
            var responder = new WireGuardHandshake(rStatic, remoteStaticPublic: null);
            return (initiator, responder, iStatic, rStatic);
        }

        // ---- mac1 ----

        [Fact]
        public void Mac1_Matches_Between_Initiator_And_Responder()
        {
            var (initiator, responder, _, rStatic) = BuildPair();

            WireGuardInitiationMessage init = initiator.CreateInitiation(0x11223344);
            byte[] wire = Codec.EncodeInitiation(init);
            initiator.StampOutgoingMacs(wire);

            // mac1 is non-zero and equals what a fresh MAC keyed by the responder's static public produces.
            byte[] mac1 = Codec.ReadMac1(wire);
            Assert.NotEqual(new byte[16], mac1);

            var recipientMac = WireGuardMac.ForRecipient(rStatic.PublicKey);
            Assert.True(recipientMac.VerifyMac1(wire.AsSpan(0, WireGuardMessageCodec.InitiationMaccedLength), mac1));

            // The responder (keyed by its own static public) accepts the datagram.
            Assert.True(responder.VerifyIncomingMac1(wire));

            // mac2 is all-zero before any cookie is in play.
            byte[] mac2 = wire.AsSpan(WireGuardMessageCodec.InitiationMaccedLength + 16, 16).ToArray();
            Assert.Equal(new byte[16], mac2);
        }

        [Fact]
        public void Mac1_On_Response_Verified_By_Initiator()
        {
            var (initiator, responder, _, _) = BuildPair();

            WireGuardInitiationMessage init = initiator.CreateInitiation(1);
            Assert.True(responder.ConsumeInitiation(init, out _, out _));

            WireGuardResponseMessage resp = responder.CreateResponse(2, init.SenderIndex);
            byte[] wire = Codec.EncodeResponse(resp);
            responder.StampOutgoingMacs(wire);

            Assert.True(initiator.VerifyIncomingMac1(wire)); // keyed by initiator's own static public
        }

        [Fact]
        public void Tampered_Mac1_Is_Rejected()
        {
            var (initiator, responder, _, _) = BuildPair();

            WireGuardInitiationMessage init = initiator.CreateInitiation(1);
            byte[] wire = Codec.EncodeInitiation(init);
            initiator.StampOutgoingMacs(wire);

            wire[WireGuardMessageCodec.InitiationMaccedLength] ^= 0xFF; // flip a mac1 byte
            Assert.False(responder.VerifyIncomingMac1(wire));
        }

        [Fact]
        public void Wrong_Recipient_Key_Rejects_Mac1()
        {
            var (initiator, _, _, _) = BuildPair();
            WireGuardInitiationMessage init = initiator.CreateInitiation(1);
            byte[] wire = Codec.EncodeInitiation(init);
            initiator.StampOutgoingMacs(wire);

            // A different responder identity must not accept the mac1 (it was keyed to someone else).
            var stranger = new WireGuardHandshake(NewStatic());
            Assert.False(stranger.VerifyIncomingMac1(wire));
        }

        // ---- cookie-reply round-trip ----

        [Fact]
        public void CookieReply_RoundTrips_And_Next_Initiation_Carries_Valid_Mac2()
        {
            var (initiator, responder, _, rStatic) = BuildPair();

            // 1) Initiator sends an initiation with mac1.
            WireGuardInitiationMessage init = initiator.CreateInitiation(0xABCDEF01);
            byte[] wire1 = Codec.EncodeInitiation(init);
            initiator.StampOutgoingMacs(wire1);

            // 2) Responder is "under load": instead of a response it issues a cookie-reply bound to wire1's mac1.
            byte[] changingSecret = Fill(32, 0x5A);
            byte[] sourceAddress = { 192, 0, 2, 10, 0xC0, 0x01 }; // ip(4) + port(2)
            WireGuardCookieReplyMessage reply = responder.CreateCookieReply(init.SenderIndex, wire1, changingSecret, sourceAddress);

            byte[] wire3 = Codec.EncodeCookieReply(reply);
            Assert.Equal(WireGuardMessageCodec.CookieReplyMessageLength, wire3.Length);
            Assert.Equal(WireGuardConstants.MessageTypeCookieReply, wire3[0]);
            Assert.True(Codec.TryDecodeCookieReply(wire3, out WireGuardCookieReplyMessage reply2));
            Assert.Equal(init.SenderIndex, reply2.ReceiverIndex);

            // 3) Initiator decrypts the cookie and stamps mac2 on its next initiation.
            Assert.True(initiator.ConsumeCookieReply(reply2));
            byte[]? cookie = initiator.CurrentCookie;
            Assert.NotNull(cookie);
            Assert.Equal(16, cookie!.Length);

            WireGuardInitiationMessage init2 = initiator.CreateInitiation(0xABCDEF02);
            byte[] wire4 = Codec.EncodeInitiation(init2);
            initiator.StampOutgoingMacs(wire4);

            // mac2 is now non-zero and the responder, recomputing the same cookie, re-validates it.
            byte[] mac2 = wire4.AsSpan(WireGuardMessageCodec.InitiationMaccedLength + 16, 16).ToArray();
            Assert.NotEqual(new byte[16], mac2);

            byte[] expectedCookie = new WireGuardCookie().ComputeCookie(changingSecret, sourceAddress);
            Assert.Equal(expectedCookie, cookie);

            var responderMac = WireGuardMac.ForRecipient(rStatic.PublicKey);
            byte[] mac2Content = wire4.AsSpan(0, WireGuardMessageCodec.InitiationMaccedLength + 16).ToArray();
            Assert.True(responderMac.VerifyMac2(expectedCookie, mac2Content, mac2));
        }

        [Fact]
        public void CookieReply_For_Different_Mac1_Fails_To_Open()
        {
            var (initiator, responder, _, _) = BuildPair();

            WireGuardInitiationMessage init = initiator.CreateInitiation(1);
            byte[] wire1 = Codec.EncodeInitiation(init);
            initiator.StampOutgoingMacs(wire1);

            byte[] changingSecret = Fill(32, 0x33);
            byte[] addr = { 10, 0, 0, 1, 0, 80 };
            WireGuardCookieReplyMessage reply = responder.CreateCookieReply(init.SenderIndex, wire1, changingSecret, addr);

            // The initiator now sends a *different* message, changing its last-sent mac1, then receives the old reply.
            WireGuardInitiationMessage init2 = initiator.CreateInitiation(2);
            byte[] wire2 = Codec.EncodeInitiation(init2);
            initiator.StampOutgoingMacs(wire2);

            // AAD (mac1) no longer matches → the cookie-reply fails to authenticate, no cookie is learned.
            Assert.False(initiator.ConsumeCookieReply(reply));
            Assert.Null(initiator.CurrentCookie);
        }

        [Fact]
        public void CookieReplyCodec_Rejects_Wrong_Length_And_Type()
        {
            Assert.False(Codec.TryDecodeCookieReply(new byte[WireGuardMessageCodec.CookieReplyMessageLength - 1], out _));

            byte[] wrongType = new byte[WireGuardMessageCodec.CookieReplyMessageLength];
            wrongType[0] = WireGuardConstants.MessageTypeInitiation;
            Assert.False(Codec.TryDecodeCookieReply(wrongType, out _));

            byte[] reserved = new byte[WireGuardMessageCodec.CookieReplyMessageLength];
            reserved[0] = WireGuardConstants.MessageTypeCookieReply;
            reserved[1] = 1; // reserved must be zero
            Assert.False(Codec.TryDecodeCookieReply(reserved, out _));
        }

        // ---- XChaCha20-Poly1305 / HChaCha20 known-answer vectors (draft-irtf-cfrg-xchacha) ----

        [Fact]
        public void HChaCha20_Matches_Draft_Test_Vector()
        {
            // draft-irtf-cfrg-xchacha §2.2.1
            byte[] key = Hex("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f");
            byte[] nonce = Hex("000000090000004a0000000031415927");
            byte[] expected = Hex("82413b4227b27bfed30e42508a877d73a0f9e4d58a74a853c12ec41326d3ecdc");

            byte[] subkey = new byte[32];
            XChaCha20Poly1305Cipher.HChaCha20(key, nonce, subkey);
            Assert.Equal(expected, subkey);
        }

        [Fact]
        public void XChaCha20Poly1305_Matches_Draft_Aead_Test_Vector()
        {
            // draft-irtf-cfrg-xchacha §A.3.1 (AEAD_XCHACHA20_POLY1305).
            byte[] plaintext = Hex(
                "4c616469657320616e642047656e746c656d656e206f662074686520636c6173" +
                "73206f66202739393a204966204920636f756c64206f6666657220796f75206f" +
                "6e6c79206f6e652074697020666f7220746865206675747572652c2073756e73" +
                "637265656e20776f756c642062652069742e");
            byte[] aad = Hex("50515253c0c1c2c3c4c5c6c7");
            byte[] key = Hex("808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f");
            byte[] nonce = Hex("404142434445464748494a4b4c4d4e4f5051525354555657");
            byte[] expectedCt = Hex(
                "bd6d179d3e83d43b9576579493c0e939572a1700252bfaccbed2902c21396cbb" +
                "731c7f1b0b4aa6440bf3a82f4eda7e39ae64c6708c54c216cb96b72e1213b452" +
                "2f8c9ba40db5d945b11b69b982c1bb9e3f3fac2bc369488f76b2383565d3fff9" +
                "21f9664c97637da9768812f615c68b13b52e");
            byte[] expectedTag = Hex("c0875924c1c7987947deafd8780acf49");

            var cipher = new XChaCha20Poly1305Cipher();
            byte[] ct = new byte[plaintext.Length];
            byte[] tag = new byte[16];
            cipher.Seal(key, nonce, plaintext, aad, ct, tag);
            Assert.Equal(expectedCt, ct);
            Assert.Equal(expectedTag, tag);

            byte[] recovered = new byte[plaintext.Length];
            Assert.True(cipher.Open(key, nonce, expectedCt, expectedTag, aad, recovered));
            Assert.Equal(plaintext, recovered);
        }

        [Fact]
        public void XChaCha20Poly1305_Seal_Then_Open_RoundTrips()
        {
            var cipher = new XChaCha20Poly1305Cipher();
            Assert.Equal(32, cipher.KeySizeInBytes);
            Assert.Equal(24, cipher.NonceSizeInBytes);
            Assert.Equal(16, cipher.TagSizeInBytes);

            byte[] key = Fill(32, 0x11);
            byte[] nonce = Fill(24, 0x22);
            byte[] aad = Fill(16, 0x33);
            byte[] plaintext = Fill(40, 0x44);

            byte[] ct = new byte[plaintext.Length];
            byte[] tag = new byte[16];
            cipher.Seal(key, nonce, plaintext, aad, ct, tag);

            byte[] recovered = new byte[plaintext.Length];
            Assert.True(cipher.Open(key, nonce, ct, tag, aad, recovered));
            Assert.Equal(plaintext, recovered);

            // A flipped AAD byte breaks authentication.
            byte[] badAad = (byte[])aad.Clone();
            badAad[0] ^= 0xFF;
            Assert.False(cipher.Open(key, nonce, ct, tag, badAad, new byte[plaintext.Length]));
        }

        static byte[] Fill(int length, byte value)
        {
            byte[] b = new byte[length];
            for (int i = 0; i < length; i++) b[i] = value;
            return b;
        }

        static byte[] Hex(string hex)
        {
            byte[] b = new byte[hex.Length / 2];
            for (int i = 0; i < b.Length; i++)
                b[i] = byte.Parse(hex.Substring(i * 2, 2), NumberStyles.HexNumber, CultureInfo.InvariantCulture);
            return b;
        }
    }
}
