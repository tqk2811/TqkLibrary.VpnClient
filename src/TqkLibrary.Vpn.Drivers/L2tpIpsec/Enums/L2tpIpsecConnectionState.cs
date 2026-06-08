namespace TqkLibrary.Vpn.Drivers.L2tpIpsec.Enums
{
    /// <summary>The lifecycle state of an <see cref="L2tpIpsecConnection"/>, surfaced via its StateChanged event.</summary>
    public enum L2tpIpsecConnectionState
    {
        /// <summary>Not connected (initial state, or after a clean/forced teardown).</summary>
        Disconnected = 0,

        /// <summary>Running the IKE/L2TP/PPP handshake.</summary>
        Connecting = 1,

        /// <summary>The tunnel is up and carrying traffic.</summary>
        Connected = 2,

        /// <summary>The link dropped (DPD timeout, server Delete, or L2TP teardown); a reconnect may follow.</summary>
        Reconnecting = 3,
    }
}
