namespace TqkLibrary.VpnClient.Drivers.Geneve
{
    /// <summary>Fixed values shared across the Geneve driver runtime (the wire constants live in <see cref="GeneveCodec"/>).</summary>
    public static class GeneveDriverConstants
    {
        /// <summary>The driver name tag used in the structured log lines and <see cref="GeneveDriver.Name"/>.</summary>
        public const string DriverName = "geneve";

        /// <summary>The default Geneve destination UDP port (RFC 8926 §3.3): 6081.</summary>
        public const int DefaultPort = GeneveCodec.DefaultPort;

        /// <summary>
        /// The default tunnel MTU. Geneve adds at least 50 bytes of overhead on a 1500-byte outer path (20 IPv4 + 8 UDP +
        /// 8 Geneve base header + 14 inner Ethernet), plus any options, so 1400 leaves headroom for the encapsulated
        /// Ethernet frame without fragmenting.
        /// </summary>
        public const int DefaultMtu = 1400;
    }
}
