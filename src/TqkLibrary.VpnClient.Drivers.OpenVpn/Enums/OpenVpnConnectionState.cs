namespace TqkLibrary.VpnClient.Drivers.OpenVpn.Enums
{
    /// <summary>The lifecycle state of an <see cref="OpenVpnConnection"/>, surfaced via its StateChanged event.</summary>
    public enum OpenVpnConnectionState
    {
        /// <summary>Not connected (initial state, or after a clean/forced teardown).</summary>
        Disconnected = 0,

        /// <summary>Running the reset → TLS → key-method-2 → PUSH handshake.</summary>
        Connecting = 1,

        /// <summary>The tunnel is up and carrying IP traffic.</summary>
        Connected = 2,

        /// <summary>The link dropped (ping-restart timeout or a rekey watermark); a reconnect may follow.</summary>
        Reconnecting = 3,
    }
}
