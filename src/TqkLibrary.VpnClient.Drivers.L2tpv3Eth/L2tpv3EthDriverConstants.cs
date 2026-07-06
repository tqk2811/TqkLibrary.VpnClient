namespace TqkLibrary.VpnClient.Drivers.L2tpv3Eth
{
    /// <summary>Fixed values shared across the L2TPv3 Ethernet-pseudowire driver runtime (wire constants live in <see cref="L2tpv3DataHeader"/>).</summary>
    public static class L2tpv3EthDriverConstants
    {
        /// <summary>The driver name tag used in the structured log lines and <see cref="L2tpv3EthDriver.Name"/>.</summary>
        public const string DriverName = "l2tpv3-eth";

        /// <summary>The default L2TP UDP port (RFC 3931; shared with L2TPv2): 1701.</summary>
        public const int DefaultPort = L2tpv3DataHeader.DefaultPort;

        /// <summary>
        /// The default tunnel MTU. L2TPv3-over-UDP adds outer overhead on a 1500-byte path (20 IPv4 + 8 UDP + 4 Session ID +
        /// up to 8 Cookie + up to 4 sublayer + 14 inner Ethernet), so 1400 leaves headroom for the encapsulated Ethernet
        /// frame without fragmenting.
        /// </summary>
        public const int DefaultMtu = 1400;
    }
}
