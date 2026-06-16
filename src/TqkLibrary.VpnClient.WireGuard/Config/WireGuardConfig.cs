using System.Net;
using TqkLibrary.VpnClient.Abstractions.Drivers.Models;

namespace TqkLibrary.VpnClient.WireGuard.Config
{
    /// <summary>
    /// A static WireGuard point-to-point configuration — the userspace equivalent of a single <c>[Interface]</c> +
    /// one <c>[Peer]</c> block in a <c>wg-quick</c> file. WireGuard does no in-tunnel address negotiation (no
    /// IPCP/DHCP): the local tunnel address, the peer's static public key, the optional preshared key, the endpoint
    /// and the allowed-IPs are all known up front, so this maps straight to a static <see cref="TunnelConfig"/>.
    /// <para>
    /// This release wires the common <b>full-tunnel point-to-point</b> shape: a single peer with allowed-ips
    /// <c>0.0.0.0/0, ::/0</c> (all traffic to the one peer), so the <see cref="IPacketChannel"/> needs no per-prefix
    /// routing table. Multi-peer allowed-ips routing is future work. The default <see cref="Mtu"/> is 1420
    /// (1500 − 60 IPv6 − 8 UDP − the 32-byte WireGuard transport header), the WireGuard default.
    /// </para>
    /// </summary>
    public sealed class WireGuardConfig
    {
        /// <summary>The local interface's 32-byte X25519 private key (<c>[Interface] PrivateKey</c>).</summary>
        public required byte[] PrivateKey { get; init; }

        /// <summary>The peer's 32-byte X25519 public key (<c>[Peer] PublicKey</c>).</summary>
        public required byte[] PeerPublicKey { get; init; }

        /// <summary>The optional 32-byte preshared key (<c>[Peer] PresharedKey</c>); <c>null</c> = no PSK (the WireGuard default).</summary>
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
        /// The peer's allowed-IPs (<c>[Peer] AllowedIPs</c>) as CIDR text. The full-tunnel default is
        /// <c>0.0.0.0/0, ::/0</c> — all traffic flows to the single peer.
        /// </summary>
        public IReadOnlyList<string> AllowedIps { get; init; } = new[] { "0.0.0.0/0", "::/0" };

        /// <summary>
        /// Persistent-keepalive interval in seconds (<c>[Peer] PersistentKeepalive</c>); 0 disables it (the WireGuard
        /// default). When set, an empty transport packet is sent every interval of silence to keep a NAT mapping open.
        /// </summary>
        public int PersistentKeepaliveSeconds { get; init; }

        /// <summary>The tunnel MTU (<c>[Interface] MTU</c>); defaults to 1420, the WireGuard default.</summary>
        public int Mtu { get; init; } = WireGuardConstants.DefaultMtu;

        /// <summary>
        /// Projects this static configuration onto a <see cref="TunnelConfig"/> — the same shape every driver hands to
        /// the userspace IP stack, but filled directly from the config rather than from any in-tunnel negotiation.
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
            foreach (string allowed in AllowedIps) config.Routes.Add(allowed);
            return config;
        }
    }
}
