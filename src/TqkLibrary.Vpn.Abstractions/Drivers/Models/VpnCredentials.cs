namespace TqkLibrary.Vpn.Abstractions.Drivers.Models
{
    /// <summary>Credentials presented to the server. Which fields are used depends on the driver's auth method.</summary>
    public sealed class VpnCredentials
    {
        /// <summary>User name (MS-CHAPv2/PAP/EAP user-password auth).</summary>
        public string? Username { get; set; }

        /// <summary>Password (MS-CHAPv2/PAP/EAP user-password auth).</summary>
        public string? Password { get; set; }

        /// <summary>Pre-shared key (L2TP/IPsec IKE PSK).</summary>
        public byte[]? PreSharedKey { get; set; }
    }
}
