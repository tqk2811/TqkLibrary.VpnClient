namespace TqkLibrary.VpnClient.Drivers.EoGre
{
    /// <summary>Fixed values shared across the EoGRE / NVGRE driver runtime (the wire constants live in <see cref="EoGreCodec"/>).</summary>
    public static class EoGreDriverConstants
    {
        /// <summary>The driver name tag for plain EoGRE / GRETAP mode (used in log lines and <c>EoGreDriver.Name</c>): <c>"eogre"</c>.</summary>
        public const string DriverNameEoGre = "eogre";

        /// <summary>The driver name tag for NVGRE mode (RFC 7637): <c>"nvgre"</c>.</summary>
        public const string DriverNameNvgre = "nvgre";

        /// <summary>The default GRE-in-UDP destination UDP port (RFC 8086): 4754.</summary>
        public const int DefaultPort = EoGreCodec.DefaultPort;

        /// <summary>
        /// The default tunnel MTU. GRE-in-UDP-TEB adds ≈46 bytes of overhead on a 1500-byte outer path (20 IPv4 + 8 UDP +
        /// 4 GRE base [+4 Key] + 14 inner Ethernet), so 1400 leaves headroom for the encapsulated Ethernet frame without
        /// fragmenting.
        /// </summary>
        public const int DefaultMtu = 1400;
    }
}
