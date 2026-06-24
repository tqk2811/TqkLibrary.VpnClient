using System.Net;
using TqkLibrary.VpnClient.Abstractions.Drivers.Models;
using TqkLibrary.VpnClient.Nebula.Certificate;
using TqkLibrary.VpnClient.Nebula.Certificate.Models;

namespace TqkLibrary.VpnClient.Drivers.Nebula.Config
{
    /// <summary>
    /// A static Nebula configuration — the parts of a <c>config.yml</c> the client needs to bring a tunnel up to one
    /// peer. Nebula does no in-tunnel address negotiation (the overlay IP is baked into the host certificate), so the
    /// tunnel address / routes / MTU are all known up front and map straight to a <see cref="TunnelConfig"/>.
    /// <para>
    /// The cryptographic identity is the trusted <see cref="CaCertificate"/> (the network CA — verifies the peer's
    /// cert), this host's <see cref="ClientCertificate"/> (signed by that CA, carrying the overlay IP) and its 32-byte
    /// <see cref="ClientX25519PrivateKey"/> (the Noise static DH key). The <see cref="PeerEndpoint"/> is the
    /// <c>static_host_map</c> entry for the peer — its real UDP address (lighthouse discovery is bypassed for the
    /// point-to-point case; a 2-node lab handshakes directly).
    /// </para>
    /// </summary>
    public sealed class NebulaConfig
    {
        /// <summary>The trusted CA certificate (its 32-byte Ed25519 key verifies the peer's certificate). Required.</summary>
        public required NebulaCertificate CaCertificate { get; init; }

        /// <summary>This host's certificate (signed by the CA, carrying this host's overlay IP and 32-byte X25519 static public key). Required.</summary>
        public required NebulaCertificate ClientCertificate { get; init; }

        /// <summary>This host's 32-byte X25519 static private key (the Noise static DH key). Required.</summary>
        public required byte[] ClientX25519PrivateKey { get; init; }

        /// <summary>
        /// The peer's real UDP endpoint (its <c>static_host_map</c> entry). The connect-time <see cref="VpnEndpoint"/>
        /// host/port supplies it when this is left null (so the demo can pass a host:port like the other drivers).
        /// </summary>
        public IPEndPoint? PeerEndpoint { get; init; }

        /// <summary>The local overlay (tunnel) IPv4 address. Defaults to the address baked into <see cref="ClientCertificate"/> when null.</summary>
        public IPAddress? OverlayAddress { get; init; }

        /// <summary>The prefix length of <see cref="OverlayAddress"/> (the Nebula overlay subnet, e.g. /24).</summary>
        public int PrefixLength { get; init; } = 24;

        /// <summary>DNS servers to use inside the tunnel; empty when none is configured.</summary>
        public IReadOnlyList<IPAddress> DnsServers { get; init; } = Array.Empty<IPAddress>();

        /// <summary>
        /// The overlay routes reachable through the tunnel (CIDR text). Defaults to the overlay subnet derived from
        /// <see cref="OverlayAddress"/>/<see cref="PrefixLength"/> when empty.
        /// </summary>
        public IReadOnlyList<string> Routes { get; init; } = Array.Empty<string>();

        /// <summary>The tunnel MTU; defaults to 1300, the Nebula default.</summary>
        public int Mtu { get; init; } = NebulaDriverConstants.DefaultMtu;

        /// <summary>
        /// The overlay address this host uses: <see cref="OverlayAddress"/> when set, otherwise the first IPv4 address
        /// baked into the host certificate's <c>Ips</c> (field 2, network byte order). Null if neither is available.
        /// </summary>
        public IPAddress? ResolveOverlayAddress()
        {
            if (OverlayAddress is not null) return OverlayAddress;
            NebulaCertificateDetails details = ClientCertificate.Details;
            if (details.Ips.Count >= 1)
            {
                uint ip = details.Ips[0]; // (IPv4, netmask) interleaved pairs, network byte order
                return new IPAddress(new[] { (byte)(ip >> 24), (byte)(ip >> 16), (byte)(ip >> 8), (byte)ip });
            }
            return null;
        }

        /// <summary>
        /// Projects this configuration onto a <see cref="TunnelConfig"/> — the same shape every driver hands to the
        /// userspace IP stack, filled directly from the static config rather than from any in-tunnel negotiation.
        /// </summary>
        public TunnelConfig ToTunnelConfig()
        {
            var config = new TunnelConfig
            {
                AssignedAddress = ResolveOverlayAddress(),
                PrefixLength = PrefixLength,
                Mtu = Mtu,
            };
            foreach (IPAddress dns in DnsServers) config.DnsServers.Add(dns);
            if (Routes.Count > 0)
            {
                foreach (string route in Routes) config.Routes.Add(route);
            }
            else
            {
                IPAddress? overlay = ResolveOverlayAddress();
                if (overlay is not null) config.Routes.Add($"{overlay}/{PrefixLength}");
            }
            return config;
        }
    }
}
