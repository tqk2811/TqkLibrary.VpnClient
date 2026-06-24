namespace TqkLibrary.VpnClient.Drivers.CiscoIpsec.Enums
{
    /// <summary>The lifecycle state of a <see cref="CiscoIpsecConnection"/>, surfaced via its StateChanged event.</summary>
    public enum CiscoIpsecConnectionState
    {
        /// <summary>Not connected (initial state, or after a clean/forced teardown).</summary>
        Disconnected = 0,

        /// <summary>Running the Aggressive Mode + XAUTH + Mode-Config + Quick Mode handshake.</summary>
        Connecting = 1,

        /// <summary>The tunnel is up and carrying IP traffic.</summary>
        Connected = 2,

        /// <summary>The link dropped (DPD timeout or a server Delete); a reconnect may follow.</summary>
        Reconnecting = 3,
    }
}
