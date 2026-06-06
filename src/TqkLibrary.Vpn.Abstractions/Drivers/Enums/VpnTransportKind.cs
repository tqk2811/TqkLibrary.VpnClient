namespace TqkLibrary.Vpn.Abstractions.Drivers.Enums
{
    /// <summary>Transport(s) a driver can use. <see cref="RawIp"/> requires elevation (see <c>VpnDriverCapabilities</c>).</summary>
    [Flags]
    public enum VpnTransportKind
    {
        None = 0,
        Tcp = 1 << 0,
        Udp = 1 << 1,
        Tls = 1 << 2,
        Dtls = 1 << 3,
        RawIp = 1 << 4,
    }
}
