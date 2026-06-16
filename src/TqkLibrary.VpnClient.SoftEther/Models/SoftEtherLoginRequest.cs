using TqkLibrary.VpnClient.SoftEther.Enums;

namespace TqkLibrary.VpnClient.SoftEther.Models
{
    /// <summary>
    /// Everything the client needs to build a SoftEther <c>login</c> PACK: the target hub, the user name, the
    /// authentication method and credential, and the <see cref="Session"/> parameters. For
    /// <see cref="SoftEtherAuthType.Password"/> the <see cref="Password"/> is hashed locally into <c>secure_password</c>
    /// (SHA-0) and never crosses the wire.
    /// </summary>
    public sealed record SoftEtherLoginRequest
    {
        /// <summary>Target Virtual Hub name (e.g. <c>"DEFAULT"</c>).</summary>
        public required string HubName { get; init; }

        /// <summary>User name.</summary>
        public required string UserName { get; init; }

        /// <summary>Authentication method. Defaults to <see cref="SoftEtherAuthType.Password"/>.</summary>
        public SoftEtherAuthType AuthType { get; init; } = SoftEtherAuthType.Password;

        /// <summary>
        /// Plaintext password for <see cref="SoftEtherAuthType.Password"/> (hashed to <c>secure_password</c> locally)
        /// or <see cref="SoftEtherAuthType.PlainPassword"/> (sent as-is). Ignored for anonymous auth.
        /// </summary>
        public string Password { get; init; } = string.Empty;

        /// <summary>Session parameters (parallel connections, encryption/compression flags, unique id).</summary>
        public SoftEtherSessionParams Session { get; init; } = new();
    }
}
