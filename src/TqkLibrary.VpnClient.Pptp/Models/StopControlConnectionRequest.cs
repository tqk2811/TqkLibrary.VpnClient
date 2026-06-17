using TqkLibrary.VpnClient.Pptp.Enums;
using TqkLibrary.VpnClient.Pptp.Interfaces;

namespace TqkLibrary.VpnClient.Pptp.Models
{
    /// <summary>
    /// Stop-Control-Connection-Request (RFC 2637 §2.3) — tears down the control connection (and implicitly all
    /// its calls). Body: Reason(1), Reserved1(1), Reserved2(2).
    /// </summary>
    public sealed class StopControlConnectionRequest : IPptpControlMessage
    {
        /// <inheritdoc/>
        public PptpControlMessageType ControlMessageType => PptpControlMessageType.StopControlConnectionRequest;

        /// <summary>Reason for stopping (1 = none/general, 2 = stop-protocol, 3 = stop-local-shutdown).</summary>
        public byte Reason { get; set; } = 1;
    }
}
