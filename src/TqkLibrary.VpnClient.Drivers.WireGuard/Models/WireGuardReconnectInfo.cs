namespace TqkLibrary.VpnClient.Drivers.WireGuard.Models
{
    /// <summary>
    /// Describes a successful auto-reconnect. WireGuard's tunnel address is static (from the config, not negotiated), so
    /// a reconnect never changes it — the userspace IP stack keeps working across reconnects. The flag is kept for
    /// parity with the OpenVPN/IKEv2 reconnect info and the shared supervisor (roadmap F.6).
    /// </summary>
    public sealed class WireGuardReconnectInfo
    {
        /// <summary>Creates the info for a completed reconnect.</summary>
        public WireGuardReconnectInfo(bool addressChanged = false) => AddressChanged = addressChanged;

        /// <summary>
        /// Always false for WireGuard (the tunnel address is static config, not negotiated), so in-tunnel sockets keep
        /// working across a reconnect.
        /// </summary>
        public bool AddressChanged { get; }
    }
}
