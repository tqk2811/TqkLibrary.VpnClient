using TqkLibrary.VpnClient.Drivers.Core.Models;

namespace TqkLibrary.VpnClient.Drivers.Pptp
{
    /// <summary>
    /// Auto-reconnect policy for a <see cref="PptpConnection"/>. Reconnect kicks in only after an initial successful
    /// connect, when the tunnel drops (control-connection Echo timeout, server Stop-Control-Connection / CDN, or a GRE
    /// link loss). Enabled by default; set <see cref="VpnReconnectOptions.Enabled"/> to false to keep single-shot
    /// behaviour. The backoff/jitter/max-attempts knobs live on the shared <see cref="VpnReconnectOptions"/> base
    /// (roadmap F.6); PPTP adds no extra knobs, so this named type exists only for the driver's public API.
    /// </summary>
    public sealed class PptpReconnectOptions : VpnReconnectOptions
    {
    }
}
