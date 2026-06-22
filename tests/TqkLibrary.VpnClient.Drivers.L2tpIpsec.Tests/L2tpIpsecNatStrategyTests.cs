using TqkLibrary.VpnClient.Drivers.L2tpIpsec;
using TqkLibrary.VpnClient.Drivers.L2tpIpsec.Enums;
using TqkLibrary.VpnClient.Ipsec.Ike.V1.Models;
using Xunit;

namespace TqkLibrary.VpnClient.Drivers.L2tpIpsec.Tests
{
    /// <summary>
    /// The pure honest-first carrier decision (<see cref="L2tpIpsecNatStrategy.Decide"/>): a real NAT floats to UDP/4500;
    /// no NAT carries native ESP only when a raw-IP transport is available and UDP/500 was bound; everything else falls
    /// back to forced NAT-T. Separated from the side effects so the table is exhaustively testable offline.
    /// </summary>
    public class L2tpIpsecNatStrategyTests
    {
        // NAT-D verdict shorthands.
        static IkeV1NatDetectionResult NatInFront() => new(serverSentNatD: true, localBehindNat: true, remoteBehindNat: false);
        static IkeV1NatDetectionResult NoNat() => new(serverSentNatD: true, localBehindNat: false, remoteBehindNat: false);
        static IkeV1NatDetectionResult NoNatD() => new(serverSentNatD: false, localBehindNat: false, remoteBehindNat: false);
        static IkeV1NatDetectionResult RemoteNat() => new(serverSentNatD: true, localBehindNat: false, remoteBehindNat: true);

        [Theory]
        [InlineData(true)]
        [InlineData(false)]
        public void NatInFront_AlwaysFloats(bool rawIpAvailable)
            => Assert.Equal(L2tpIpsecPhase1Strategy.FloatToNatT,
                L2tpIpsecNatStrategy.Decide(NatInFront(), rawIpAvailable, port500Bound: true));

        [Fact]
        public void NoNat_WithRawIpAndPort500_ChoosesNativeEsp()
            => Assert.Equal(L2tpIpsecPhase1Strategy.NativeEsp,
                L2tpIpsecNatStrategy.Decide(NoNat(), rawIpAvailable: true, port500Bound: true));

        [Fact]
        public void NoNat_WithoutRawIp_FallsBackForced()
            => Assert.Equal(L2tpIpsecPhase1Strategy.FallbackForced,
                L2tpIpsecNatStrategy.Decide(NoNat(), rawIpAvailable: false, port500Bound: true));

        [Fact]
        public void NoNat_WithRawIpButPort500NotBound_FallsBackForced()
            => Assert.Equal(L2tpIpsecPhase1Strategy.FallbackForced,
                L2tpIpsecNatStrategy.Decide(NoNat(), rawIpAvailable: true, port500Bound: false));

        [Fact]
        public void NoNatDAtAll_FallsBackForced()
            => Assert.Equal(L2tpIpsecPhase1Strategy.FallbackForced,
                L2tpIpsecNatStrategy.Decide(NoNatD(), rawIpAvailable: true, port500Bound: true));

        [Fact]
        public void RemoteBehindNat_NotNativeEsp_FallsBackForced()
            => Assert.Equal(L2tpIpsecPhase1Strategy.FallbackForced,
                L2tpIpsecNatStrategy.Decide(RemoteNat(), rawIpAvailable: true, port500Bound: true));
    }
}
