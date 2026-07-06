namespace TqkLibrary.VpnClient.Drivers.Ayiya.Enums
{
    /// <summary>
    /// AYIYA opcode (low nibble of header byte 2, draft-massar-v6ops-ayiya-02 §4). Names what a datagram carries. The data
    /// plane uses <see cref="Forward"/> (a forwarded inner packet, next-header 41 = IPv6); heartbeats/keepalives use
    /// <see cref="EchoRequest"/> with next-header 59 (no-next-header) and an empty payload.
    /// </summary>
    public enum AyiyaOpcode : byte
    {
        /// <summary>No operation.</summary>
        Noop = 0,

        /// <summary>Forward: the payload is a forwarded inner packet (data plane).</summary>
        Forward = 1,

        /// <summary>Echo request (used as a keepalive / liveness probe).</summary>
        EchoRequest = 2,

        /// <summary>Echo request AND forward: an echo probe that also carries a forwarded inner packet.</summary>
        EchoRequestForward = 3,

        /// <summary>Echo response (reply to an echo request).</summary>
        EchoResponse = 4,

        /// <summary>Message-of-the-day.</summary>
        Motd = 5,

        /// <summary>Query request.</summary>
        QueryRequest = 6,

        /// <summary>Query response.</summary>
        QueryResponse = 7,
    }
}
