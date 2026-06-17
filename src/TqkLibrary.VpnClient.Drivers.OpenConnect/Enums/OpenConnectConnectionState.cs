namespace TqkLibrary.VpnClient.Drivers.OpenConnect.Enums
{
    /// <summary>The lifecycle state of an <see cref="OpenConnectConnection"/>, surfaced via its StateChanged event.</summary>
    public enum OpenConnectConnectionState
    {
        /// <summary>Not connected (initial state, or after a clean/forced teardown).</summary>
        Disconnected = 0,

        /// <summary>Running the HTTPS auth handshake + HTTP CONNECT (before the CSTP tunnel is up).</summary>
        Connecting = 1,

        /// <summary>The CSTP-over-TLS tunnel is up and carrying IP traffic.</summary>
        Connected = 2,

        /// <summary>The session dropped (peer closed / DPD declared the peer dead / a transport fault); a reconnect may follow.</summary>
        Reconnecting = 3,
    }
}
