using TqkLibrary.VpnClient.Drivers.Core.Models;

namespace TqkLibrary.VpnClient.Drivers.Fou
{
    /// <summary>
    /// Auto-reconnect policy for a <see cref="FouConnection"/>. The backoff/jitter/max-attempts knobs live on the shared
    /// <see cref="VpnReconnectOptions"/> base (roadmap F.6); this driver adds no extra knobs, so the named type exists only
    /// for the driver's public API.
    /// <para><b>Note:</b> FOU/GUE are <i>connectionless</i> — there is no control plane (no handshake, keepalive or DPD),
    /// so a silent link loss cannot be detected and auto-reconnect never fires on its own. The supervisor machinery is
    /// inherited for symmetry and for a future control-plane keepalive; today reconnect occurs only if a caller explicitly
    /// signals link loss.</para>
    /// </summary>
    public sealed class FouReconnectOptions : VpnReconnectOptions
    {
    }
}
