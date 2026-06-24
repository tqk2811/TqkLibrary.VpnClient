using System.Text.Json.Serialization;

namespace TqkLibrary.VpnClient.Tailscale.Control.Messages
{
    /// <summary>
    /// One node in the netmap (<c>tailcfg.Node</c>) — either this client (<see cref="MapResponse.Node"/>) or a peer
    /// (<see cref="MapResponse.Peers"/>). The fields that build a WireGuard config:
    /// <list type="bullet">
    /// <item><see cref="Key"/> (<c>nodekey:&lt;hex&gt;</c>) is the peer's WireGuard public key, unchanged.</item>
    /// <item><see cref="Addresses"/> are the node's own tunnel IPs (CIDR strings, e.g. <c>100.64.0.1/32</c>).</item>
    /// <item><see cref="AllowedIPs"/> are the prefixes routed to this peer (the WireGuard peer's allowed-IPs).</item>
    /// <item><see cref="Endpoints"/> are the peer's candidate UDP endpoints (<c>ip:port</c> strings).</item>
    /// </list>
    /// JSON keys are the Go field names verbatim (PascalCase); the one rename is <c>DERP</c> (Go field
    /// <c>LegacyDERPString</c>), captured by <see cref="Derp"/>.
    /// </summary>
    public sealed class TailscaleNode
    {
        /// <summary>The node id (control-assigned integer).</summary>
        public long ID { get; set; }

        /// <summary>The stable node id string (survives key changes).</summary>
        public string? StableID { get; set; }

        /// <summary>A display name for the node.</summary>
        public string? Name { get; set; }

        /// <summary>The node (WireGuard) public key, <c>nodekey:&lt;hex&gt;</c>.</summary>
        public string Key { get; set; } = string.Empty;

        /// <summary>The machine public key, <c>mkey:&lt;hex&gt;</c>.</summary>
        public string? Machine { get; set; }

        /// <summary>The disco public key, <c>discokey:&lt;hex&gt;</c>.</summary>
        public string? DiscoKey { get; set; }

        /// <summary>The node's own tunnel addresses as CIDR strings (the local tunnel IPs for <see cref="MapResponse.Node"/>).</summary>
        public IReadOnlyList<string>? Addresses { get; set; }

        /// <summary>The prefixes routed to this peer as CIDR strings (the WireGuard peer allowed-IPs).</summary>
        public IReadOnlyList<string>? AllowedIPs { get; set; }

        /// <summary>The peer's candidate UDP endpoints as <c>ip:port</c> strings.</summary>
        public IReadOnlyList<string>? Endpoints { get; set; }

        /// <summary>The legacy DERP home string (<c>127.3.3.40:&lt;region&gt;</c>); JSON key <c>DERP</c> (Go <c>LegacyDERPString</c>).</summary>
        [JsonPropertyName("DERP")]
        public string? Derp { get; set; }

        /// <summary>The DERP home region id (newer field).</summary>
        public int HomeDERP { get; set; }

        /// <summary>Whether the peer is currently online; null when unknown.</summary>
        public bool? Online { get; set; }
    }
}
