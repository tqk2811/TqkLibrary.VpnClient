namespace TqkLibrary.VpnClient.Drivers.VxlanGpe.Enums
{
    /// <summary>
    /// The VXLAN-GPE Next Protocol (draft-ietf-nvo3-vxlan-gpe, header byte 3): names the encapsulated payload so one UDP
    /// port can multiplex several inner protocols. Only <see cref="Ethernet"/> is wired to the L2 data plane in this driver
    /// (the other values are parsed and validated on the wire, but there is no L3 IP / NSH data plane yet).
    /// </summary>
    public enum VxlanGpeNextProtocol : byte
    {
        /// <summary>0x01 — the payload is an IPv4 packet (parsed/validated only; no L3 data plane wired).</summary>
        Ipv4 = VxlanGpeHeader.NextProtocolIpv4,

        /// <summary>0x02 — the payload is an IPv6 packet (parsed/validated only; no L3 data plane wired).</summary>
        Ipv6 = VxlanGpeHeader.NextProtocolIpv6,

        /// <summary>0x03 — the payload is a full Ethernet frame (the wired L2 data plane).</summary>
        Ethernet = VxlanGpeHeader.NextProtocolEthernet,

        /// <summary>0x04 — the payload is an NSH frame (parsed/validated only; no NSH data plane wired).</summary>
        Nsh = VxlanGpeHeader.NextProtocolNsh,
    }
}
