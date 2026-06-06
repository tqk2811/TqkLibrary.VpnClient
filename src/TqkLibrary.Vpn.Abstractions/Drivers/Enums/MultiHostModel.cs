namespace TqkLibrary.Vpn.Abstractions.Drivers.Enums
{
    /// <summary>How (and whether) one connection can host more than one virtual IP endpoint.</summary>
    public enum MultiHostModel
    {
        /// <summary>One assigned IP per connection (SSTP, OpenVPN-tun default).</summary>
        None = 0,

        /// <summary>One identity, but routes additional prefixes at L3 (WireGuard AllowedIPs, IKEv2 site-to-site).</summary>
        RoutedPrefixes = 1,

        /// <summary>A shared L2 segment hosting many MAC/IP stations (SoftEther, OpenVPN-tap).</summary>
        L2BroadcastDomain = 2,
    }
}
