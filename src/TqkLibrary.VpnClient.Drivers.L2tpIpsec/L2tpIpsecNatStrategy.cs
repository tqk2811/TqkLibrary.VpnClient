using TqkLibrary.VpnClient.Drivers.L2tpIpsec.Enums;
using TqkLibrary.VpnClient.Ipsec.Ike.V1.Models;

namespace TqkLibrary.VpnClient.Drivers.L2tpIpsec
{
    /// <summary>
    /// Pure decision for the ESP carrier after an honest Phase 1 handshake, free of side effects so every branch is
    /// unit-testable. The honest path binds the real UDP/500 and reads the gateway's MM4 NAT-D verdict; this maps that
    /// verdict (plus whether a raw-IP transport is available) to one of <see cref="L2tpIpsecPhase1Strategy"/>.
    /// </summary>
    public static class L2tpIpsecNatStrategy
    {
        /// <summary>
        /// Chooses the carrier from the NAT-D <paramref name="nat"/> verdict. A real NAT in front of us floats to UDP/4500.
        /// No NAT on either side means the gateway expects native ESP: use it when a raw-IP transport is available
        /// (<paramref name="rawIpAvailable"/>) and UDP/500 was actually bound (<paramref name="port500Bound"/>, so the
        /// gateway sees ESP from the same source it authenticated IKE on); otherwise fall back to forced NAT-T. A gateway
        /// that sent no NAT-D at all also falls back (it does no NAT-T, so "no NAT" cannot be trusted for native ESP).
        /// </summary>
        public static L2tpIpsecPhase1Strategy Decide(IkeV1NatDetectionResult nat, bool rawIpAvailable, bool port500Bound)
        {
            if (nat.ShouldFloatToNatT) return L2tpIpsecPhase1Strategy.FloatToNatT;
            if (nat.ServerSentNatD && !nat.LocalBehindNat && !nat.RemoteBehindNat && rawIpAvailable && port500Bound)
                return L2tpIpsecPhase1Strategy.NativeEsp;
            return L2tpIpsecPhase1Strategy.FallbackForced;
        }
    }
}
