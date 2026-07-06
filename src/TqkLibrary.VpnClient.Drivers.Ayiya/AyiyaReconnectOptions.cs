using TqkLibrary.VpnClient.Drivers.Core.Models;

namespace TqkLibrary.VpnClient.Drivers.Ayiya
{
    /// <summary>
    /// Auto-reconnect policy for a <see cref="AyiyaConnection"/>. The backoff/jitter/max-attempts knobs live on the shared
    /// <see cref="VpnReconnectOptions"/> base (roadmap F.6); this driver adds no extra knobs, so the named type exists only
    /// for the driver's public API.
    /// <para><b>Note:</b> AYIYA in static mode has no TIC control plane and no scheduled heartbeat, so a silent link loss
    /// cannot be detected and auto-reconnect never fires on its own. The supervisor machinery is inherited for symmetry and
    /// for a future keepalive; today reconnect occurs only if a caller explicitly signals link loss.</para>
    /// </summary>
    public sealed class AyiyaReconnectOptions : VpnReconnectOptions
    {
    }
}
