namespace TqkLibrary.VpnClient.Drivers.IpEncap.Enums
{
    /// <summary>The lifecycle state of an <see cref="IpEncapConnection"/>, surfaced via its StateChanged event.</summary>
    public enum IpEncapConnectionState
    {
        /// <summary>Not connected (initial state, or after a clean/forced teardown).</summary>
        Disconnected = 0,

        /// <summary>Opening the raw-IP transport and binding the encapsulation channel.</summary>
        Connecting = 1,

        /// <summary>The tunnel is up and carrying traffic.</summary>
        Connected = 2,

        /// <summary>The link is being re-established (reserved — plain encap has no control plane to detect loss).</summary>
        Reconnecting = 3,
    }
}
