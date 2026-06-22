namespace TqkLibrary.VpnClient.Drivers.L2tpIpsec.Enums
{
    /// <summary>
    /// How the L2TP/IPsec client negotiates NAT-Traversal during IKEv1 Phase 1. The data plane stays userspace
    /// UDP either way; the difference is only how the gateway is steered onto UDP/4500.
    /// </summary>
    public enum L2tpIpsecNatTraversalMode
    {
        /// <summary>
        /// Always force NAT-T (the default, proven live on VPN Gate): send from an ephemeral port but claim source
        /// port 500 in NAT-D so every cooperating gateway concludes there is a NAT and floats to UDP/4500. Works
        /// without admin and without binding 500, but a gateway that refuses forced NAT-T fails (diagnosed as such).
        /// </summary>
        ForcedNatT = 0,

        /// <summary>
        /// Try an honest handshake first: bind the real source port 500 and send truthful NAT-D, then let the gateway's
        /// NAT-D verdict decide — a real NAT floats to UDP/4500. No NAT means the gateway expects native ESP: if the
        /// driver was given a raw-IP transport (<c>IRawIpTransportFactory</c>, requires elevation) it keeps IKE on
        /// UDP/500 and carries ESP natively over IP proto-50; otherwise it falls back to <see cref="ForcedNatT"/>. It also
        /// falls back when port 500 cannot be bound (e.g. the Windows IKEEXT service holds it).
        /// </summary>
        HonestFirst = 1,
    }
}
