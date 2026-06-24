namespace TqkLibrary.VpnClient.Ssh.Channel.Enums
{
    /// <summary>
    /// The address-family tag OpenSSH prefixes to each layer-3 tun@openssh.com packet (PROTOCOL §2.3). These are the
    /// OpenSSH on-wire constants (<c>SSH_TUN_AF_INET</c> / <c>SSH_TUN_AF_INET6</c>), <b>not</b> the host's native
    /// <c>AF_*</c> values, so they are fixed across platforms.
    /// </summary>
    public enum SshTunAddressFamily : uint
    {
        /// <summary>IPv4 packet (SSH_TUN_AF_INET).</summary>
        Inet = 2,

        /// <summary>IPv6 packet (SSH_TUN_AF_INET6).</summary>
        Inet6 = 24,
    }
}
