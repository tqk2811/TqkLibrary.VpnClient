using System.Text.Json.Serialization;

namespace TqkLibrary.VpnClient.Tailscale.Control.Messages
{
    /// <summary>
    /// The body of <c>POST /machine/register</c> over the Noise channel (<c>tailcfg.RegisterRequest</c>). The wire
    /// structs use Go field names verbatim as JSON keys (PascalCase, no rename policy), so the properties keep their
    /// PascalCase names. The minimal preauth-key registration sets <see cref="Version"/>, <see cref="NodeKey"/>,
    /// <see cref="Auth"/> (with the preauth key) and a <see cref="Hostinfo"/>.
    /// </summary>
    public sealed class RegisterRequest
    {
        /// <summary>The client's advertised capability version (must be in the server's supported range; Headscale min 113).</summary>
        public int Version { get; set; }

        /// <summary>This node's public key (<c>nodekey:&lt;hex&gt;</c>) — the same Curve25519 key used as the WireGuard public key.</summary>
        public string NodeKey { get; set; } = string.Empty;

        /// <summary>The previous node key when re-registering an existing node (<c>nodekey:&lt;hex&gt;</c>); omitted when empty.</summary>
        [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
        public string? OldNodeKey { get; set; }

        /// <summary>The authentication block carrying the preauth key; omitted when null.</summary>
        [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
        public RegisterResponseAuth? Auth { get; set; }

        /// <summary>Node key expiry (RFC 3339); the Go zero value <c>0001-01-01T00:00:00Z</c> means "no expiry".</summary>
        public string Expiry { get; set; } = "0001-01-01T00:00:00Z";

        /// <summary>Whether this node should be registered as ephemeral (removed when it disconnects); omitted when false.</summary>
        [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingDefault)]
        public bool Ephemeral { get; set; }

        /// <summary>Host metadata (hostname, OS, advertised routes); omitted when null.</summary>
        [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
        public Hostinfo? Hostinfo { get; set; }
    }
}
