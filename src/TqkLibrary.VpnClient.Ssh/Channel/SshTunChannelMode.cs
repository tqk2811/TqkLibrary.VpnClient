namespace TqkLibrary.VpnClient.Ssh.Channel
{
    /// <summary>The tun@openssh.com tunnel mode (OpenSSH PROTOCOL §2.3): layer-3 packets or layer-2 frames.</summary>
    public enum SshTunChannelMode : uint
    {
        /// <summary>SSH_TUNMODE_POINTOPOINT — forward layer-3 IP packets (this driver's mode).</summary>
        PointToPoint = 1,

        /// <summary>SSH_TUNMODE_ETHERNET — forward layer-2 Ethernet frames.</summary>
        Ethernet = 2,
    }
}
