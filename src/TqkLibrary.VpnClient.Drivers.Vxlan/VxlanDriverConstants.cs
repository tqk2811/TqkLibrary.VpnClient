namespace TqkLibrary.VpnClient.Drivers.Vxlan
{
    /// <summary>Fixed values shared across the VXLAN driver runtime (the wire constants live in <see cref="VxlanCodec"/>).</summary>
    public static class VxlanDriverConstants
    {
        /// <summary>The driver name tag used in the structured log lines and <see cref="VxlanDriver.Name"/>.</summary>
        public const string DriverName = "vxlan";

        /// <summary>The default VXLAN destination UDP port (RFC 7348 §5): 4789.</summary>
        public const int DefaultPort = VxlanCodec.DefaultPort;

        /// <summary>
        /// The default tunnel MTU. VXLAN adds 50 bytes of overhead on a 1500-byte outer path (20 IPv4 + 8 UDP + 8 VXLAN
        /// header + 14 inner Ethernet), so 1400 leaves headroom for the encapsulated Ethernet frame without fragmenting.
        /// </summary>
        public const int DefaultMtu = 1400;
    }
}
