namespace TqkLibrary.VpnClient.Drivers.IpEncap.Enums
{
    /// <summary>
    /// The plain IP-in-IP encapsulation a <see cref="IpEncapConnection"/> carries — selects both the IANA IP protocol
    /// number used to open the raw-IP transport and the data-plane channel built over it.
    /// </summary>
    public enum IpEncapKind
    {
        /// <summary>Standard GRE (RFC 2784/2890), IANA IP protocol 47 — carries IPv4/IPv6 via a GRE header.</summary>
        Gre = 0,

        /// <summary>IP-in-IP (RFC 2003), IANA IP protocol 4 — header-less IPv4-in-IPv4.</summary>
        IpIp = 1,

        /// <summary>SIT / 6in4 (RFC 4213), IANA IP protocol 41 — header-less IPv6-in-IPv4.</summary>
        Sit = 2,
    }
}
