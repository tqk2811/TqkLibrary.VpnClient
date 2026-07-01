using TqkLibrary.VpnClient.Drivers.Core.Models;

namespace TqkLibrary.VpnClient.Drivers.Vxlan
{
    /// <summary>
    /// The VXLAN driver's auto-reconnect / backoff options. Derives from the shared <see cref="VpnReconnectOptions"/> so
    /// the supervisor in <c>ReconnectingVpnConnection</c> consumes one type while the driver keeps its own named options
    /// (mirrors <c>N2nReconnectOptions</c>). Enabled by default.
    /// </summary>
    public sealed class VxlanReconnectOptions : VpnReconnectOptions
    {
    }
}
