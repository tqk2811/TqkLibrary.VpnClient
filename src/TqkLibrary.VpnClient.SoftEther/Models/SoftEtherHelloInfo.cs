namespace TqkLibrary.VpnClient.SoftEther.Models
{
    /// <summary>
    /// The parsed contents of a SoftEther server <c>hello</c> PACK: the greeting string, the server protocol
    /// <see cref="Version"/> and <see cref="Build"/>, and the 20-byte <see cref="Random"/> challenge the client mixes
    /// into its password hash. Produced by <see cref="SoftEtherHandshake.ParseHello"/>.
    /// </summary>
    public sealed record SoftEtherHelloInfo
    {
        /// <summary>The server greeting string (normally <c>"softether"</c>).</summary>
        public required string Hello { get; init; }

        /// <summary>The server protocol version.</summary>
        public required uint Version { get; init; }

        /// <summary>The server build number.</summary>
        public required uint Build { get; init; }

        /// <summary>The 20-byte per-session random challenge used to compute <c>secure_password</c>.</summary>
        public required byte[] Random { get; init; }
    }
}
