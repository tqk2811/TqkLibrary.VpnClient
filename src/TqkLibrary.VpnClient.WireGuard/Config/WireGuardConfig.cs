using System.Net;
using TqkLibrary.VpnClient.Abstractions.Drivers.Models;

namespace TqkLibrary.VpnClient.WireGuard.Config
{
    /// <summary>
    /// A static WireGuard configuration — the userspace equivalent of one <c>[Interface]</c> plus one or more
    /// <c>[Peer]</c> blocks in a <c>wg-quick</c> file. WireGuard does no in-tunnel address negotiation (no IPCP/DHCP):
    /// the local tunnel address, each peer's static public key, the optional preshared key, the endpoint and the
    /// allowed-IPs are all known up front, so this maps straight to a static <see cref="TunnelConfig"/>.
    /// <para>
    /// The common single-peer <b>full-tunnel point-to-point</b> shape (one peer with allowed-ips <c>0.0.0.0/0, ::/0</c>)
    /// is configured directly through <see cref="PeerPublicKey"/>/<see cref="PresharedKey"/>/<see cref="AllowedIps"/>.
    /// For <b>multi-peer</b> setups, list several <see cref="WireGuardPeer"/> in <see cref="Peers"/>: each peer carries
    /// its own allowed-IPs and the data plane crypto-routes every outbound packet to the peer whose allowed-IPs cover
    /// the destination by longest-prefix match. The default <see cref="Mtu"/> is 1420
    /// (1500 − 60 IPv6 − 8 UDP − the 32-byte WireGuard transport header), the WireGuard default.
    /// </para>
    /// </summary>
    public sealed class WireGuardConfig
    {
        /// <summary>The local interface's 32-byte X25519 private key (<c>[Interface] PrivateKey</c>).</summary>
        public required byte[] PrivateKey { get; init; }

        /// <summary>
        /// The single peer's 32-byte X25519 public key (<c>[Peer] PublicKey</c>) — the convenience shape for a
        /// point-to-point tunnel. Ignored when <see cref="Peers"/> is non-empty (multi-peer is configured there).
        /// </summary>
        public byte[]? PeerPublicKey { get; init; }

        /// <summary>The optional 32-byte preshared key for the single peer (<c>[Peer] PresharedKey</c>); <c>null</c> = no PSK (the WireGuard default).</summary>
        public byte[]? PresharedKey { get; init; }

        /// <summary>The local tunnel IPv4 address (<c>[Interface] Address</c>), or <c>null</c> if only IPv6 is configured.</summary>
        public IPAddress? Address { get; init; }

        /// <summary>The prefix length of <see cref="Address"/> (a point-to-point WireGuard interface is typically /32).</summary>
        public int PrefixLength { get; init; } = 32;

        /// <summary>The local tunnel IPv6 address (<c>[Interface] Address</c>), or <c>null</c> if only IPv4 is configured.</summary>
        public IPAddress? AddressV6 { get; init; }

        /// <summary>The prefix length of <see cref="AddressV6"/> (typically /128 for a point-to-point WireGuard interface).</summary>
        public int PrefixLengthV6 { get; init; } = 128;

        /// <summary>DNS servers to use inside the tunnel (<c>[Interface] DNS</c>); empty when none is configured.</summary>
        public IReadOnlyList<IPAddress> DnsServers { get; init; } = Array.Empty<IPAddress>();

        /// <summary>
        /// The single peer's allowed-IPs (<c>[Peer] AllowedIPs</c>) as CIDR text — the convenience shape for a
        /// point-to-point tunnel. The full-tunnel default is <c>0.0.0.0/0, ::/0</c> (all traffic to the one peer).
        /// Ignored when <see cref="Peers"/> is non-empty.
        /// </summary>
        public IReadOnlyList<string> AllowedIps { get; init; } = new[] { "0.0.0.0/0", "::/0" };

        /// <summary>
        /// Persistent-keepalive interval in seconds for the single peer (<c>[Peer] PersistentKeepalive</c>); 0 disables
        /// it (the WireGuard default). When set, an empty transport packet is sent every interval of silence to keep a
        /// NAT mapping open. Ignored when <see cref="Peers"/> is non-empty (each peer there has its own interval).
        /// </summary>
        public int PersistentKeepaliveSeconds { get; init; }

        /// <summary>
        /// The peers of a <b>multi-peer</b> interface — each with its own public key, optional PSK and allowed-IPs.
        /// When non-empty, this list is authoritative and the single-peer convenience fields
        /// (<see cref="PeerPublicKey"/>/<see cref="PresharedKey"/>/<see cref="AllowedIps"/>/
        /// <see cref="PersistentKeepaliveSeconds"/>) are ignored. When empty, those single-peer fields define one peer.
        /// </summary>
        public IReadOnlyList<WireGuardPeer> Peers { get; init; } = Array.Empty<WireGuardPeer>();

        /// <summary>The tunnel MTU (<c>[Interface] MTU</c>); defaults to 1420, the WireGuard default.</summary>
        public int Mtu { get; init; } = WireGuardConstants.DefaultMtu;

        /// <summary>
        /// Normalises the configuration to the list of peers the driver actually uses: <see cref="Peers"/> when it is
        /// non-empty, otherwise the single peer described by the convenience fields. Throws
        /// <see cref="InvalidOperationException"/> when neither form yields a usable peer (no
        /// <see cref="PeerPublicKey"/> and no <see cref="Peers"/>).
        /// </summary>
        public IReadOnlyList<WireGuardPeer> EnumeratePeers()
        {
            if (Peers.Count > 0) return Peers;
            if (PeerPublicKey is null)
                throw new InvalidOperationException("WireGuard config has neither a PeerPublicKey nor any Peers.");
            return new[]
            {
                new WireGuardPeer
                {
                    PublicKey = PeerPublicKey,
                    PresharedKey = PresharedKey,
                    AllowedIps = AllowedIps,
                    PersistentKeepaliveSeconds = PersistentKeepaliveSeconds,
                },
            };
        }

        /// <summary>
        /// Projects this static configuration onto a <see cref="TunnelConfig"/> — the same shape every driver hands to
        /// the userspace IP stack, but filled directly from the config rather than from any in-tunnel negotiation. The
        /// routes are the union of every peer's allowed-IPs (each prefix is reachable through the tunnel).
        /// </summary>
        public TunnelConfig ToTunnelConfig()
        {
            var config = new TunnelConfig
            {
                AssignedAddress = Address,
                PrefixLength = PrefixLength,
                AssignedAddressV6 = AddressV6,
                PrefixLengthV6 = PrefixLengthV6,
                Mtu = Mtu,
            };
            foreach (IPAddress dns in DnsServers) config.DnsServers.Add(dns);
            foreach (WireGuardPeer peer in EnumeratePeers())
                foreach (string allowed in peer.AllowedIps)
                    config.Routes.Add(allowed);
            return config;
        }
    }
}
