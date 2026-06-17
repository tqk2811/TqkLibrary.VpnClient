using TqkLibrary.VpnClient.Drivers.Core.Models;

namespace TqkLibrary.VpnClient.Drivers.SoftEther
{
    /// <summary>
    /// Auto-reconnect policy for a <see cref="SoftEtherConnection"/>. Reconnect kicks in only after an initial successful
    /// connect, when the data session is declared dead (the TLS stream closed or a transport fault). Enabled by default;
    /// set <see cref="VpnReconnectOptions.Enabled"/> to false to keep single-shot behaviour. The knobs live on the shared
    /// <see cref="VpnReconnectOptions"/> base (roadmap F.6); this named type is kept for the driver's public API.
    /// </summary>
    public sealed class SoftEtherReconnectOptions : VpnReconnectOptions
    {
    }
}
