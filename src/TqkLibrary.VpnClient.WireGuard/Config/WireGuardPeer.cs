using System.Net;

namespace TqkLibrary.VpnClient.WireGuard.Config
{
    /// <summary>
    /// One <c>[Peer]</c> block of a WireGuard configuration: the peer's static public key, an optional preshared key,
    /// the CIDR list it is allowed to carry (<c>AllowedIPs</c>, both families), its own persistent-keepalive interval
    /// and an optional explicit endpoint. A <see cref="WireGuardConfig"/> may list several of these; the data plane
    /// crypto-routes each outbound packet to the peer whose <see cref="AllowedIps"/> covers the destination by
    /// longest-prefix match (<see cref="Routing.WireGuardCryptoRouter"/>).
    /// </summary>
    public sealed class WireGuardPeer
    {
        /// <summary>The peer's 32-byte X25519 public key (<c>[Peer] PublicKey</c>).</summary>
        public required byte[] PublicKey { get; init; }

        /// <summary>The optional 32-byte preshared key for this peer (<c>[Peer] PresharedKey</c>); <c>null</c> = no PSK.</summary>
        public byte[]? PresharedKey { get; init; }

        /// <summary>
        /// This peer's allowed-IPs (<c>[Peer] AllowedIPs</c>) as CIDR text, both families. An outbound packet is sent
        /// to this peer when its destination falls inside one of these prefixes and no other peer has a more specific
        /// one. The full-tunnel default is <c>0.0.0.0/0, ::/0</c> (all traffic to this one peer).
        /// </summary>
        public IReadOnlyList<string> AllowedIps { get; init; } = new[] { "0.0.0.0/0", "::/0" };

        /// <summary>
        /// Persistent-keepalive interval in seconds for this peer (<c>[Peer] PersistentKeepalive</c>); 0 disables it
        /// (the WireGuard default).
        /// </summary>
        public int PersistentKeepaliveSeconds { get; init; }

        /// <summary>
        /// An explicit UDP endpoint for this peer (<c>[Peer] Endpoint</c>), or <c>null</c> to use the connection's
        /// endpoint. The driver opens one UDP transport per distinct endpoint, so each peer's handshake and data go to
        /// its own address; peers that leave this <c>null</c> (or that share an endpoint) share one socket — the
        /// single-listen-socket case is just every peer falling back to the connection's host:port. (Interop with a
        /// real WireGuard peer at a distinct endpoint is validated live, lab Q.1.)
        /// </summary>
        public IPEndPoint? Endpoint { get; init; }
    }
}
