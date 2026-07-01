namespace TqkLibrary.VpnClient.Drivers.Vxlan.Enums
{
    /// <summary>The lifecycle state of a <see cref="VxlanConnection"/> (mirrors the other drivers' state enums).</summary>
    public enum VxlanConnectionState
    {
        /// <summary>Not connected (initial state, or after a teardown / a final reconnect failure).</summary>
        Disconnected,
        /// <summary>Opening the UDP transport to the remote VTEP (VXLAN has no handshake — this is transient).</summary>
        Connecting,
        /// <summary>The UDP transport is open and the L2 data plane is carrying traffic.</summary>
        Connected,
        /// <summary>The link dropped and the supervisor is attempting to re-open the transport.</summary>
        Reconnecting,
    }
}
