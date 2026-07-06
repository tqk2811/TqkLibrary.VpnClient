using TqkLibrary.VpnClient.Drivers.Core.Models;

namespace TqkLibrary.VpnClient.Drivers.GtpU
{
    /// <summary>
    /// Auto-reconnect policy for a <see cref="GtpUConnection"/>. The backoff/jitter/max-attempts knobs live on the shared
    /// <see cref="VpnReconnectOptions"/> base (roadmap F.6); this driver adds no extra knobs, so the named type exists only
    /// for the driver's public API.
    /// <para><b>Note:</b> static GTP-U is <i>connectionless</i> — there is no GTP-C control plane (no handshake, keepalive or
    /// DPD), so a silent link loss cannot be detected and auto-reconnect never fires on its own. The supervisor machinery is
    /// inherited for symmetry; today reconnect occurs only if a caller explicitly signals link loss.</para>
    /// </summary>
    public sealed class GtpUReconnectOptions : VpnReconnectOptions
    {
    }
}
