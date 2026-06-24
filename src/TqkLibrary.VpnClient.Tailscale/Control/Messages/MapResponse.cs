namespace TqkLibrary.VpnClient.Tailscale.Control.Messages
{
    /// <summary>
    /// One netmap update from <c>POST /machine/map</c> (<c>tailcfg.MapResponse</c>). On a streamed poll the server sends
    /// a full map first (<see cref="Node"/> + <see cref="Peers"/>), then incremental updates; a bare
    /// <see cref="KeepAlive"/> message carries no map. <see cref="Node"/> is this client's own node (its
    /// <see cref="TailscaleNode.Addresses"/> are the local tunnel IPs); <see cref="Peers"/> are the other nodes (each a
    /// WireGuard peer). JSON keys are PascalCase.
    /// <para>
    /// On the wire each MapResponse JSON is prefixed by a 4-byte little-endian length inside the HTTP body; that framing
    /// is handled by the control client, not this DTO.
    /// </para>
    /// </summary>
    public sealed class MapResponse
    {
        /// <summary>A keepalive-only message (no map content) when true.</summary>
        public bool KeepAlive { get; set; }

        /// <summary>This client's own node (present on a full map); its <c>Addresses</c> are the local tunnel IPs.</summary>
        public TailscaleNode? Node { get; set; }

        /// <summary>The full peer list (present on a full map). Each peer becomes a WireGuard peer.</summary>
        public IReadOnlyList<TailscaleNode>? Peers { get; set; }

        /// <summary>Peers that changed since the last map (incremental update).</summary>
        public IReadOnlyList<TailscaleNode>? PeersChanged { get; set; }

        /// <summary>Node ids removed since the last map (incremental update).</summary>
        public IReadOnlyList<long>? PeersRemoved { get; set; }

        /// <summary>The tailnet domain name.</summary>
        public string? Domain { get; set; }
    }
}
