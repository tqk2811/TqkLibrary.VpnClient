using TqkLibrary.VpnClient.Drivers.Core.Models;

namespace TqkLibrary.VpnClient.Drivers.L2tpv3Eth
{
    /// <summary>
    /// The L2TPv3 Ethernet-pseudowire driver's auto-reconnect / backoff options. Derives from the shared
    /// <see cref="VpnReconnectOptions"/> so the supervisor in <c>ReconnectingVpnConnection</c> consumes one type while the
    /// driver keeps its own named options (mirrors <c>GeneveReconnectOptions</c>). Enabled by default.
    /// </summary>
    public sealed class L2tpv3EthReconnectOptions : VpnReconnectOptions
    {
    }
}
