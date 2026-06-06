namespace TqkLibrary.Vpn.Abstractions.Drivers.Enums
{
    /// <summary>Authentication method(s) a driver supports.</summary>
    [Flags]
    public enum VpnAuthMethod
    {
        None = 0,
        PreSharedKey = 1 << 0,
        Certificate = 1 << 1,
        UserPassword = 1 << 2,
        Eap = 1 << 3,
        Saml = 1 << 4,
        Otp = 1 << 5,
    }
}
