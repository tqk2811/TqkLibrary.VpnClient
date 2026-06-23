using TqkLibrary.VpnClient.Crypto;
using Xunit;

namespace TqkLibrary.VpnClient.Ppp.Auth.Tests
{
    public class MsChapV2Tests
    {
        // RFC 2759, Section D — worked example.
        const string UserName = "User";
        const string Password = "clientPass";
        static readonly byte[] AuthenticatorChallenge = Convert.FromHexString("5B5D7C7D7B3F2F3E3C2C602132262628");
        static readonly byte[] PeerChallenge = Convert.FromHexString("21402324255E262A28295F2B3A337C7E");

        [Fact]
        public void NtPasswordHash_MatchesRfc2759()
        {
            byte[] hash = MsChapV2.NtPasswordHash(Password);
            Assert.Equal("44EBBA8D5312B8D611474411F56989AE", Convert.ToHexString(hash));
        }

        [Fact]
        public void ChallengeHash_MatchesRfc2759()
        {
            byte[] challenge = MsChapV2.ChallengeHash(PeerChallenge, AuthenticatorChallenge, UserName);
            Assert.Equal("D02E4386BCE91226", Convert.ToHexString(challenge));
        }

        [Fact]
        public void GenerateNTResponse_MatchesRfc2759()
        {
            byte[] response = MsChapV2.GenerateNTResponse(AuthenticatorChallenge, PeerChallenge, UserName, Password);
            Assert.Equal("82309ECD8D708B5EA08FAA3981CD83544233114A3D85D6DF", Convert.ToHexString(response));
        }

        [Fact]
        public void GenerateAuthenticatorResponse_MatchesRfc2759()
        {
            // RFC 2759 §D worked example: AuthenticatorResponse = "S=407A5589115FD0D6209F510FE9C04566932CDA56".
            byte[] ntResponse = MsChapV2.GenerateNTResponse(AuthenticatorChallenge, PeerChallenge, UserName, Password);
            byte[] digest = MsChapV2.GenerateAuthenticatorResponse(
                AuthenticatorChallenge, PeerChallenge, ntResponse, UserName, Password);
            Assert.Equal("407A5589115FD0D6209F510FE9C04566932CDA56", Convert.ToHexString(digest));
        }

        [Fact]
        public void DeriveMsk_IsSendThenRecv_PaddedTo64()
        {
            // EAP-MSCHAPv2 MSK is laid out from the authenticator/server view so peer and server agree; the peer (this
            // client) therefore emits its own send-key || receive-key (the dual of the server's recv||send). That is the
            // SAME ordering as the HLAK (MasterSendKey || MasterReceiveKey), so cross-checking against HLAK pins the
            // ordering without an external vector. (Validated live against strongSwan: the reversed order still passes
            // EAP but fails the gateway's IKEv2 AUTH-with-MSK check — see lab/ikev2-native.)
            byte[] ntResponse = MsChapV2.GenerateNTResponse(AuthenticatorChallenge, PeerChallenge, UserName, Password);
            byte[] msk = MsChapV2.DeriveMsk(Password, ntResponse);
            byte[] hlak = MsChapV2.DeriveHlak(Password, ntResponse);

            Assert.Equal(64, msk.Length);
            Assert.Equal(hlak[0..16], msk[0..16]);    // MSK send-key    = HLAK's first half
            Assert.Equal(hlak[16..32], msk[16..32]);  // MSK receive-key = HLAK's second half
            Assert.All(msk[32..64], b => Assert.Equal(0, b));
        }
    }
}
