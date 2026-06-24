using TqkLibrary.VpnClient.Drivers.Core.Models;

namespace TqkLibrary.VpnClient.Drivers.CiscoIpsec
{
    /// <summary>
    /// Auto-reconnect policy for a <see cref="CiscoIpsecConnection"/>. Reconnect kicks in only after an initial
    /// successful connect, when the tunnel drops (DPD timeout or a server Delete). Enabled by default; set
    /// <see cref="VpnReconnectOptions.Enabled"/> to false to keep the old single-shot behaviour. The
    /// backoff/jitter/max-attempts knobs live on the shared <see cref="VpnReconnectOptions"/> base (roadmap F.6);
    /// Cisco IPsec adds no extra knobs, so this named type is kept only for the driver's public API.
    /// </summary>
    public sealed class CiscoIpsecReconnectOptions : VpnReconnectOptions
    {
    }
}
