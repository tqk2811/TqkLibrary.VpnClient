using TqkLibrary.VpnClient.Crypto;
using TqkLibrary.VpnClient.Crypto.Mppe;
using TqkLibrary.VpnClient.Crypto.Mppe.Enums;
using Xunit;

namespace TqkLibrary.VpnClient.Crypto.Tests
{
    /// <summary>
    /// Known-answer tests for MPPE key derivation (RFC 3078 §7 + RFC 3079 §3.5) — the SHA-1/RC4 schedule that turns
    /// MS-CHAPv2 credentials into RC4 session keys. Vectors are taken from the RFC 3079 §3.5 worked example
    /// (password "clientPass", a fixed NT-Response) and exercise the 40/56/128-bit strengths. MPPE is broken —
    /// these tests pin the legacy PPTP/CCP behavior, not endorse it.
    /// </summary>
    public class MppeKeyDerivationTests
    {
        static byte[] Hex(string hex) => Convert.FromHexString(hex.Replace(" ", ""));

        // RFC 3079 §3.5 worked example.
        const string Password = "clientPass";
        static readonly byte[] NtResponse = Hex("82309ECD8D708B5EA08FAA3981CD83544233114A3D85D6DF");
        static readonly byte[] ExpectedMasterKey = Hex("FDECE3717A8C838CB388E527AE3CDD31");

        [Fact]
        public void DeriveMppeMasterKey_MatchesRfc3079()
        {
            byte[] masterKey = MsChapV2.DeriveMppeMasterKey(Password, NtResponse);
            Assert.Equal(ExpectedMasterKey, masterKey);
        }

        // RFC 3079 §3.5 computes the example from the SERVER perspective:
        //   GetAsymmetricStartKey(MasterKey, ..., IsSend=TRUE, IsServer=TRUE) ⇒ Magic3.
        // The server's send key equals the client's RECEIVE key, so we reproduce it via the client-perspective
        // receive key (Magic3) or, equivalently, the server-perspective send key (isServer: true) — both Magic3.
        static byte[] Rfc3079StartKey() => MsChapV2.DeriveMppeReceiveStartKey(ExpectedMasterKey);

        [Fact]
        public void DeriveMppeStartKey_MatchesRfc3079()
        {
            // RFC 3079 §3.5.1: SendStartKey (GetAsymmetricStartKey output, first 8 octets) = 8B 7C DC 14 9B 99 3A 1B.
            byte[] startKey = Rfc3079StartKey();
            Assert.Equal("8B7CDC149B993A1B", Convert.ToHexString(startKey.AsSpan(0, 8).ToArray()));

            // Equivalence: client-receive (Magic3) == server-send (isServer: true, Magic3).
            byte[] serverSend = MsChapV2.DeriveMppeSendStartKey(ExpectedMasterKey, isServer: true);
            Assert.Equal(startKey, serverSend);
        }

        [Fact]
        public void DeriveInitialSessionKey_40Bit_MatchesRfc3079()
        {
            // RFC 3079 §3.5.1: SendSessionKey40 = D1 26 9E C4 9F A6 2E 3E.
            byte[] sessionKey = MppeKeyDerivation.DeriveInitialSessionKey(Rfc3079StartKey(), MppeKeyStrength.Bits40);
            Assert.Equal("D1269EC49FA62E3E", Convert.ToHexString(sessionKey));
        }

        [Fact]
        public void DeriveInitialSessionKey_56Bit_MatchesRfc3079()
        {
            // RFC 3079 §3.5.2: SendSessionKey56 = D1 5C 00 C4 9F A6 2E 3E (only first octet forced to 0xD1).
            byte[] sessionKey = MppeKeyDerivation.DeriveInitialSessionKey(Rfc3079StartKey(), MppeKeyStrength.Bits56);
            Assert.Equal("D15C00C49FA62E3E", Convert.ToHexString(sessionKey));
        }

        [Fact]
        public void DeriveMppeStartKey_128Bit_MatchesRfc3079()
        {
            // RFC 3079 §3.5.3: SendStartKey128 = 8B 7C DC 14 9B 99 3A 1B A1 18 CB 15 3F 56 DC CB.
            Assert.Equal("8B7CDC149B993A1BA118CB153F56DCCB", Convert.ToHexString(Rfc3079StartKey()));
        }

        [Fact]
        public void DeriveInitialSessionKey_128Bit_MatchesRfc3079()
        {
            // RFC 3079 §3.5.3: SendSessionKey128 = 40 5C B2 24 7A 79 56 E6 E2 11 00 7A E2 7B 22 D4 (no reduction).
            byte[] sessionKey = MppeKeyDerivation.DeriveInitialSessionKey(Rfc3079StartKey(), MppeKeyStrength.Bits128);
            Assert.Equal("405CB2247A7956E6E211007AE27B22D4", Convert.ToHexString(sessionKey));
        }

        [Fact]
        public void ClientSendKey_EqualsServerReceiveKey()
        {
            // Symmetry (RFC 3079 §3.3): client-send (Magic2) must equal server-receive (Magic2).
            byte[] clientSend = MsChapV2.DeriveMppeSendStartKey(ExpectedMasterKey, isServer: false);
            byte[] serverRecv = MsChapV2.DeriveMppeReceiveStartKey(ExpectedMasterKey, isServer: true);
            Assert.Equal(clientSend, serverRecv);
            Assert.NotEqual(clientSend, Rfc3079StartKey()); // the two directions differ (Magic2 vs Magic3)
        }

        // End-to-end KAT: RFC 3079 §3.5 "Sample Encrypted Message" rc4(SendSessionKey, "test message").
        // This pins the full chain — credentials → start key → initial session key → RC4 cipher.
        [Theory]
        [InlineData(MppeKeyStrength.Bits40, "929137917E5803D668D75898")]
        // RFC §3.5.2 prints "...57 58"; the last octet is a known RFC erratum — RC4 of the documented
        // 56-bit key (D1 5C 00 C4 9F A6 2E 3E) over "test message" actually ends in B8 (verified).
        [InlineData(MppeKeyStrength.Bits56, "3F106833FA448DA842BC57B8")]
        [InlineData(MppeKeyStrength.Bits128, "81848317DF68846272FB5ABE")]
        public void SampleEncryptedMessage_MatchesRfc3079(MppeKeyStrength strength, string expectedHex)
        {
            byte[] sessionKey = MppeKeyDerivation.DeriveInitialSessionKey(Rfc3079StartKey(), strength);
            byte[] cipher = Rc4.Apply(sessionKey, System.Text.Encoding.ASCII.GetBytes("test message"));
            Assert.Equal(expectedHex, Convert.ToHexString(cipher));
        }

        [Fact]
        public void SessionKeyLength_MatchesStrength()
        {
            Assert.Equal(8, MppeKeyDerivation.SessionKeyLength(MppeKeyStrength.Bits40));
            Assert.Equal(8, MppeKeyDerivation.SessionKeyLength(MppeKeyStrength.Bits56));
            Assert.Equal(16, MppeKeyDerivation.SessionKeyLength(MppeKeyStrength.Bits128));
        }

        [Fact]
        public void ReduceStrength_AppliesFixedPrefixes()
        {
            byte[] key40 = new byte[8]; for (int i = 0; i < 8; i++) key40[i] = (byte)(i + 1);
            MppeKeyDerivation.ReduceStrength(key40, MppeKeyStrength.Bits40);
            Assert.Equal(new byte[] { 0xD1, 0x26, 0x9E, 4, 5, 6, 7, 8 }, key40);

            byte[] key56 = new byte[8]; for (int i = 0; i < 8; i++) key56[i] = (byte)(i + 1);
            MppeKeyDerivation.ReduceStrength(key56, MppeKeyStrength.Bits56);
            Assert.Equal(new byte[] { 0xD1, 2, 3, 4, 5, 6, 7, 8 }, key56);

            byte[] key128 = new byte[16]; for (int i = 0; i < 16; i++) key128[i] = (byte)(i + 1);
            byte[] before = (byte[])key128.Clone();
            MppeKeyDerivation.ReduceStrength(key128, MppeKeyStrength.Bits128);
            Assert.Equal(before, key128); // 128-bit: untouched
        }

        [Fact]
        public void DeriveNextSessionKey_ChangesKeyAndIsDeterministic()
        {
            byte[] startKey = MsChapV2.DeriveMppeSendStartKey(ExpectedMasterKey);
            byte[] initial = MppeKeyDerivation.DeriveInitialSessionKey(startKey, MppeKeyStrength.Bits128);

            byte[] next1 = MppeKeyDerivation.DeriveNextSessionKey(startKey, initial, MppeKeyStrength.Bits128);
            byte[] next2 = MppeKeyDerivation.DeriveNextSessionKey(startKey, initial, MppeKeyStrength.Bits128);

            Assert.Equal(next1, next2);          // deterministic
            Assert.NotEqual(initial, next1);     // re-key actually changes the key
        }
    }
}
