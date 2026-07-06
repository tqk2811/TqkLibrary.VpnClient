namespace TqkLibrary.VpnClient.Drivers.VxlanGpe
{
    /// <summary>Fixed values shared across the VXLAN-GPE driver runtime (the wire constants live in <see cref="VxlanGpeHeader"/>).</summary>
    public static class VxlanGpeDriverConstants
    {
        /// <summary>The driver name tag used in the structured log lines and <see cref="VxlanGpeDriver.Name"/>.</summary>
        public const string DriverName = "vxlan-gpe";

        /// <summary>The default VXLAN-GPE destination UDP port (draft-ietf-nvo3-vxlan-gpe): 4790.</summary>
        public const int DefaultPort = VxlanGpeHeader.DefaultPort;

        /// <summary>
        /// The default tunnel MTU. VXLAN-GPE adds the same 50 bytes of overhead as VXLAN on a 1500-byte outer path
        /// (20 IPv4 + 8 UDP + 8 VXLAN-GPE header + 14 inner Ethernet), so 1400 leaves headroom for the encapsulated
        /// Ethernet frame without fragmenting.
        /// </summary>
        public const int DefaultMtu = 1400;
    }
}
