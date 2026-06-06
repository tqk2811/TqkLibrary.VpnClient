namespace TqkLibrary.Vpn.Abstractions.Channels.Enums
{
    /// <summary>Whether a link channel carries bare IP packets (L3) or full Ethernet frames (L2).</summary>
    /// <remarks>Mirrors smoltcp's <c>Medium</c> and gVisor's <c>ARPHardwareType</c>.</remarks>
    public enum LinkMedium
    {
        /// <summary>Layer 3: bare IP packets, no MAC, no ARP/NDISC.</summary>
        Ip = 0,

        /// <summary>Layer 2: full Ethernet frames, requires MAC addressing and ARP/NDISC.</summary>
        Ethernet = 1,
    }
}
