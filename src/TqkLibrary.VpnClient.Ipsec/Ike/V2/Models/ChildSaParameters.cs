using TqkLibrary.VpnClient.Ipsec.Esp;

namespace TqkLibrary.VpnClient.Ipsec.Ike.V2.Models
{
    /// <summary>
    /// The fully-resolved parameters of a CHILD_SA the driver needs to build an <see cref="EspSession"/>: the inbound
    /// and outbound SPIs, the derived keys, and the negotiated suite. Returned by a CREATE_CHILD_SA rekey so the
    /// driver can install the fresh SA (make-before-break) without reaching into IKE internals.
    /// </summary>
    public sealed record ChildSaParameters(byte[] InboundSpi, byte[] OutboundSpi, ChildSaKeys Keys, EspSuiteSelection Suite);
}
