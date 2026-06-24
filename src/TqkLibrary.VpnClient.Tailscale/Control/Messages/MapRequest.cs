using System.Text.Json.Serialization;

namespace TqkLibrary.VpnClient.Tailscale.Control.Messages
{
    /// <summary>
    /// The body of <c>POST /machine/map</c> over the Noise channel (<c>tailcfg.MapRequest</c>). Setting
    /// <see cref="Stream"/> requests a long-poll: the server keeps the response open and writes successive
    /// <see cref="MapResponse"/> blocks as the netmap changes. <see cref="Compress"/> empty asks for uncompressed JSON
    /// (Headscale only compresses when it equals <c>"zstd"</c>). JSON keys are PascalCase.
    /// </summary>
    public sealed class MapRequest
    {
        /// <summary>The client's advertised capability version (same value as in <see cref="RegisterRequest.Version"/>).</summary>
        public int Version { get; set; }

        /// <summary>This node's public key (<c>nodekey:&lt;hex&gt;</c>).</summary>
        public string NodeKey { get; set; } = string.Empty;

        /// <summary>This node's disco public key (<c>discokey:&lt;hex&gt;</c>); used for NAT traversal (DERP/disco).</summary>
        [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
        public string? DiscoKey { get; set; }

        /// <summary>Long-poll flag: keep the connection open and stream netmap updates.</summary>
        public bool Stream { get; set; }

        /// <summary>The body compression, <c>"zstd"</c> or <c>""</c> (no compression). Empty here for plain JSON.</summary>
        public string Compress { get; set; } = string.Empty;

        /// <summary>This node's UDP endpoints (<c>ip:port</c> strings); omitted when empty.</summary>
        [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
        public IReadOnlyList<string>? Endpoints { get; set; }

        /// <summary>Host metadata; omitted when null.</summary>
        [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
        public Hostinfo? Hostinfo { get; set; }

        /// <summary>Whether this is a read-only poll (no endpoint update); omitted when false.</summary>
        [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingDefault)]
        public bool ReadOnly { get; set; }

        /// <summary>Whether to omit the peer list from the response; omitted when false.</summary>
        [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingDefault)]
        public bool OmitPeers { get; set; }
    }
}
