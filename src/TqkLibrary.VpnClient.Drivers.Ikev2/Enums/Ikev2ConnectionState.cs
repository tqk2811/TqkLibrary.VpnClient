namespace TqkLibrary.VpnClient.Drivers.Ikev2.Enums
{
    /// <summary>The lifecycle state of an <see cref="Ikev2Connection"/>, surfaced via its StateChanged event.</summary>
    public enum Ikev2ConnectionState
    {
        /// <summary>Not connected (initial state, or after a clean/forced teardown).</summary>
        Disconnected = 0,

        /// <summary>Running the IKE_SA_INIT + IKE_AUTH handshake.</summary>
        Connecting = 1,

        /// <summary>The tunnel is up and carrying IP traffic.</summary>
        Connected = 2,

        /// <summary>The link dropped (DPD timeout or a server DELETE); a reconnect may follow.</summary>
        Reconnecting = 3,
    }
}
