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
    }
}
