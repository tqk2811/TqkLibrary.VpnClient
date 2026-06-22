namespace TqkLibrary.VpnClient.Drivers.L2tpIpsec.Enums
{
    /// <summary>
    /// The ESP data-plane carrier chosen after the honest Phase 1 NAT-D verdict (RFC 3947). It is the pure decision
    /// output of <see cref="L2tpIpsecNatStrategy"/>, kept separate from the side effects (port float / native-ESP setup /
    /// teardown) so every branch is unit-testable.
    /// </summary>
    public enum L2tpIpsecPhase1Strategy
    {
        /// <summary>A NAT was detected in front of us: float to UDP/4500 and carry ESP-in-UDP (RFC 3948).</summary>
        FloatToNatT,

        /// <summary>No NAT anywhere and a raw-IP transport is available: keep IKE on UDP/500 and carry ESP natively over IP proto-50.</summary>
        NativeEsp,

        /// <summary>No NAT but native ESP is unavailable (no elevation / no factory / port 500 not bound): fall back to forced NAT-T.</summary>
        FallbackForced,
    }
}
