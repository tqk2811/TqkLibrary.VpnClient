namespace TqkLibrary.VpnClient.Drivers.Pptp.Enums
{
    /// <summary>The lifecycle state of a <see cref="PptpConnection"/>, surfaced via its StateChanged event.</summary>
    public enum PptpConnectionState
    {
        /// <summary>Not connected (initial state, or after a clean/forced teardown).</summary>
        Disconnected = 0,

        /// <summary>Running the PPTP control / GRE / PPP handshake.</summary>
        Connecting = 1,

        /// <summary>The tunnel is up and carrying traffic.</summary>
        Connected = 2,

        /// <summary>The link dropped (Echo timeout, control teardown, or GRE loss); a reconnect may follow.</summary>
        Reconnecting = 3,
    }
}
