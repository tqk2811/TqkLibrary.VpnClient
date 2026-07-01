using System;

namespace TqkLibrary.VpnClient.Drivers.Core.Models
{
    /// <summary>
    /// The shared auto-reconnect / backoff policy every protocol driver uses (roadmap F.6). Reconnect kicks in only
    /// after an initial successful connect, when the tunnel is declared dead (the specific trigger — DPD timeout, peer
    /// close, transport fault, rekey watermark — is the driver's concern; the policy here is identical across them).
    /// Enabled by default; set <see cref="Enabled"/> to false to keep single-shot behaviour. Each driver's named
    /// options type (<c>WireGuardReconnectOptions</c>, <c>SstpReconnectOptions</c>, …) derives from this so the shared
    /// supervisor (<see cref="ReconnectingVpnConnection"/>) consumes one type while drivers keep their public
    /// API; a driver that needs extra knobs (e.g. SSTP's read-timeout) adds them in the subclass.
    /// </summary>
    public class VpnReconnectOptions
    {
        /// <summary>Whether a dead tunnel is re-established automatically.</summary>
        public bool Enabled { get; set; } = true;

        /// <summary>Maximum reconnect attempts before giving up; 0 = retry indefinitely until DisconnectAsync.</summary>
        public int MaxAttempts { get; set; } = 0;

        /// <summary>Delay before the second attempt (the first retry runs immediately after the drop).</summary>
        public TimeSpan InitialBackoff { get; set; } = TimeSpan.FromSeconds(1);

        /// <summary>Upper bound the exponential backoff is capped at.</summary>
        public TimeSpan MaxBackoff { get; set; } = TimeSpan.FromSeconds(30);

        /// <summary>Factor the backoff grows by after each failed attempt.</summary>
        public double BackoffMultiplier { get; set; } = 2.0;

        /// <summary>Random jitter applied to each delay as ±(fraction × delay); 0 disables jitter.</summary>
        public double JitterFraction { get; set; } = 0.2;

        /// <summary>The next backoff in the geometric sequence, capped at <see cref="MaxBackoff"/> (jitter applied separately).</summary>
        public TimeSpan NextBackoff(TimeSpan current)
            => TimeSpan.FromMilliseconds(Math.Min(MaxBackoff.TotalMilliseconds, current.TotalMilliseconds * BackoffMultiplier));
    }
}
