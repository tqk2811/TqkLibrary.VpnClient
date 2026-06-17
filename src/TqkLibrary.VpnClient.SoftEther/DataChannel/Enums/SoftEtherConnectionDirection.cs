namespace TqkLibrary.VpnClient.SoftEther.DataChannel.Enums
{
    /// <summary>
    /// The traffic direction a single TCP/TLS connection of a SoftEther multi-connection session carries. In the default
    /// full-duplex mode every connection is <see cref="Both"/>. When the session negotiates <c>half_connection</c> the
    /// connections are split: some carry client→server data only (<see cref="Send"/>) and the rest server→client only
    /// (<see cref="Receive"/>), which lets a middlebox/NAT pin each socket to one direction.
    /// </summary>
    public enum SoftEtherConnectionDirection
    {
        /// <summary>Full-duplex: the connection both sends and receives data blocks.</summary>
        Both = 0,

        /// <summary>Half-duplex upstream: the connection only sends data blocks (client → server).</summary>
        Send = 1,

        /// <summary>Half-duplex downstream: the connection only receives data blocks (server → client).</summary>
        Receive = 2,
    }
}
