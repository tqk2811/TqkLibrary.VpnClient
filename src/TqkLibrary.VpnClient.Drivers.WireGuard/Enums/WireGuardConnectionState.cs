namespace TqkLibrary.VpnClient.Drivers.WireGuard.Enums
{
    /// <summary>The lifecycle state of a <see cref="WireGuardConnection"/>, surfaced via its StateChanged event.</summary>
    public enum WireGuardConnectionState
    {
        /// <summary>Not connected (initial state, or after a clean/forced teardown).</summary>
        Disconnected = 0,

        /// <summary>Running the Noise_IKpsk2 handshake (initiation → response → transport keys).</summary>
        Connecting = 1,

        /// <summary>The tunnel is up and carrying IP traffic.</summary>
        Connected = 2,

        /// <summary>The session was declared dead (a handshake could not be completed / re-established); a reconnect may follow.</summary>
        Reconnecting = 3,
    }
}
