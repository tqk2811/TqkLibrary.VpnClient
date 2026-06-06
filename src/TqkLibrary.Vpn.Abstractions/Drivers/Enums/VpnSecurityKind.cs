namespace TqkLibrary.Vpn.Abstractions.Drivers.Enums
{
    /// <summary>Security layer(s) a driver supports.</summary>
    [Flags]
    public enum VpnSecurityKind
    {
        None = 0,
        Tls = 1 << 0,
        Dtls = 1 << 1,
        Esp = 1 << 2,
        Noise = 1 << 3,
        Mppe = 1 << 4,
    }
}
