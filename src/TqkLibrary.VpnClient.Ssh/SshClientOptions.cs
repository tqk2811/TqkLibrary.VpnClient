using TqkLibrary.VpnClient.Ssh.Transport;

namespace TqkLibrary.VpnClient.Ssh
{
    /// <summary>
    /// The parameters a <see cref="SshClient"/> needs to bring up a tun@openssh.com tunnel: the login user, one
    /// authentication method (an Ed25519 private key for publickey auth, or a password), the remote tun unit number, an
    /// optional client identification banner and an optional host-key validator (TOFU pinning).
    /// </summary>
    public sealed class SshClientOptions
    {
        /// <summary>The remote tun unit number that lets the server choose the interface (SSH_TUNMODE constant 0x7fffffff).</summary>
        public const uint AnyTunUnit = 0x7fffffff;

        /// <summary>The login user name. Required.</summary>
        public required string Username { get; init; }

        /// <summary>The 32-byte Ed25519 private-key seed for publickey auth; null to use <see cref="Password"/> instead.</summary>
        public byte[]? PrivateKeyEd25519 { get; init; }

        /// <summary>The password for password auth; used only when <see cref="PrivateKeyEd25519"/> is null.</summary>
        public string? Password { get; init; }

        /// <summary>The remote tun interface unit number to request (default: let the server choose).</summary>
        public uint RemoteTunUnit { get; init; } = AnyTunUnit;

        /// <summary>An override for the client identification string (no CR LF); null uses the default banner.</summary>
        public string? ClientId { get; init; }

        /// <summary>
        /// An optional host-key validator (TOFU pinning): returns true to accept the verified host key, false to refuse
        /// the connection. Null accepts any host key whose signature over the exchange hash verified.
        /// </summary>
        public Func<SshEd25519HostKey, bool>? HostKeyValidator { get; init; }
    }
}
