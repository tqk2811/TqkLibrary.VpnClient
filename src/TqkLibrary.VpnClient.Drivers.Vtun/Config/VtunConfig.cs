using System.Net;
using TqkLibrary.VpnClient.Abstractions.Drivers.Models;

namespace TqkLibrary.VpnClient.Drivers.Vtun.Config
{
    /// <summary>
    /// A static vtun client configuration — what the client needs to bring a point-to-point tunnel up to one vtund host.
    /// vtun does no in-tunnel address negotiation (the server's <c>up</c>/<c>down</c> scripts run <c>ifconfig</c> on its
    /// own tun device), so the client's tunnel address / peer / routes are supplied out-of-band here and map straight to
    /// a <see cref="TunnelConfig"/>.
    /// <para>
    /// <see cref="HostName"/> selects the server's config block (the <c>HOST:</c> line) and <see cref="Password"/> is the
    /// shared secret that keys the challenge-response (its MD5 is the Blowfish key). The server dictates the link type
    /// (tun/tap), transport (tcp/udp) and feature flags; this config only validates that the negotiated link is one the
    /// driver supports (tun over tcp). <see cref="TunnelAddress"/> is the client's own tunnel IP (the address the
    /// server's <c>up</c> script set as its <c>pointopoint</c> peer), <see cref="PeerAddress"/> is the server's tunnel IP.
    /// </para>
    /// </summary>
    public sealed class VtunConfig
    {
        /// <summary>The session/host name the server matches against its config blocks (the <c>HOST:</c> line). Required.</summary>
        public required string HostName { get; init; }

        /// <summary>The shared password (MD5'd into the Blowfish challenge key). Required.</summary>
        public required string Password { get; init; }

        /// <summary>This client's tunnel IP address (the server's <c>pointopoint</c> peer). Required for a working tunnel.</summary>
        public IPAddress? TunnelAddress { get; init; }

        /// <summary>The prefix length of <see cref="TunnelAddress"/> (default /32 for a point-to-point link).</summary>
        public int PrefixLength { get; init; } = 32;

        /// <summary>The server's tunnel IP address (the inner gateway / ping target); used to add a host route.</summary>
        public IPAddress? PeerAddress { get; init; }

        /// <summary>
        /// This client's MAC address for <c>type ether</c> (tap) mode — the L2 identity the Ethernet fabric (ARP +
        /// <c>VirtualHost</c>) uses. Ignored in tun mode. Format <c>aa:bb:cc:dd:ee:ff</c>; <c>null</c> ⇒ a deterministic
        /// locally-administered MAC derived from <see cref="TunnelAddress"/>.
        /// </summary>
        public string? MacAddress { get; init; }

        /// <summary>DNS servers to use inside the tunnel; empty when none is configured.</summary>
        public IReadOnlyList<IPAddress> DnsServers { get; init; } = Array.Empty<IPAddress>();

        /// <summary>The tunnel MTU; defaults to <see cref="VtunDriverConstants.DefaultMtu"/>.</summary>
        public int Mtu { get; init; } = VtunDriverConstants.DefaultMtu;

        /// <summary>
        /// Projects this configuration onto a <see cref="TunnelConfig"/> — the same shape every driver hands to the
        /// userspace IP stack. The address/prefix come from <see cref="TunnelAddress"/>; a host route to
        /// <see cref="PeerAddress"/> is added so traffic to the server's tunnel IP goes through the tunnel.
        /// </summary>
        public TunnelConfig ToTunnelConfig()
        {
            var config = new TunnelConfig
            {
                AssignedAddress = TunnelAddress,
                PrefixLength = PrefixLength,
                Mtu = Mtu,
            };
            foreach (IPAddress dns in DnsServers) config.DnsServers.Add(dns);
            if (PeerAddress is not null) config.Routes.Add($"{PeerAddress}/32");
            return config;
        }
    }
}
