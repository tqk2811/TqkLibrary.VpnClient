namespace TqkLibrary.VpnClient.Drivers.Core.Enums
{
    /// <summary>The lifecycle state shared by every reconnecting VPN driver connection.</summary>
    public enum VpnConnectionState
    {
        /// <summary>Not connected (initial state, or after a clean/forced teardown).</summary>
        Disconnected = 0,
        /// <summary>Running the handshake / bringing the transport up.</summary>
        Connecting = 1,
        /// <summary>The tunnel is up and carrying traffic.</summary>
        Connected = 2,
        /// <summary>The link dropped; a reconnect may follow.</summary>
        Reconnecting = 3,
    }
}
