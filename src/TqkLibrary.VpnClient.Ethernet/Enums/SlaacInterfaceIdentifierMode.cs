namespace TqkLibrary.VpnClient.Ethernet.Enums
{
    /// <summary>
    /// How <see cref="Ipv6AddressConfigurator"/> derives the 64-bit interface identifier of a SLAAC address from the
    /// advertised prefix (RFC 4862 §5.5.3).
    /// </summary>
    public enum SlaacInterfaceIdentifierMode
    {
        /// <summary>Modified EUI-64 from the host MAC (RFC 4291 Appendix A) — the classic, MAC-derived identifier.</summary>
        ModifiedEui64 = 0,

        /// <summary>Stable opaque identifier (RFC 7217) — constant per (prefix, interface) but not the bare MAC.</summary>
        StableOpaque = 1,
    }
}
