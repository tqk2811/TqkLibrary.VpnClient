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

        /// <summary>
        /// The product name the client announces (<c>client_str</c>). Sent together with
        /// <see cref="ClientVer"/> and <see cref="ClientBuild"/>, and <b>not optional in practice</b>: a login PACK
        /// without these three is still accepted — the server allocates the session and returns a full welcome — but the
        /// data session that follows is then refused at the TLS layer, with no protocol-level reason given (measured
        /// against VPN Gate, 2026-09: every server answered the first data block with a <c>protocol_version</c> alert
        /// until these three fields were present).
        /// </summary>
        public string ClientStr { get; init; } = SoftEtherProtocol.DefaultClientStr;

        /// <summary>The product version the client announces (<c>client_ver</c>). See <see cref="ClientStr"/>.</summary>
        public uint ClientVer { get; init; } = SoftEtherProtocol.DefaultClientVer;

        /// <summary>The build number the client announces (<c>client_build</c>). See <see cref="ClientStr"/>.</summary>
        public uint ClientBuild { get; init; } = SoftEtherProtocol.DefaultClientBuild;
    }
}
