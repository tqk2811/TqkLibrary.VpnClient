using System.Net;
using TqkLibrary.VpnClient.Tailscale.Control.Messages;
using TqkLibrary.VpnClient.Tailscale.Keys;
using TqkLibrary.VpnClient.WireGuard.Config;

namespace TqkLibrary.VpnClient.Tailscale.Netmap
{
    /// <summary>
    /// Projects a Tailscale netmap (<see cref="MapResponse"/>: this node + its peers) onto a multi-peer
    /// <see cref="WireGuardConfig"/>, which the WireGuard data plane then carries unchanged. The mapping is purely the
    /// control-plane glue Tailscale adds on top of WireGuard:
    /// <list type="bullet">
    /// <item>self tunnel addresses come from <see cref="MapResponse.Node"/>.<see cref="TailscaleNode.Addresses"/>
    /// (the CGNAT <c>100.64.x/32</c> and the <c>fd7a:.../128</c>).</item>
    /// <item>each peer's WireGuard public key = <see cref="TailscaleNode.Key"/> (the <c>nodekey:</c>, used verbatim).</item>
    /// <item>each peer's allowed-IPs = <see cref="TailscaleNode.AllowedIPs"/> (CIDR strings, kept as-is).</item>
    /// <item>each peer's endpoint = the first directly-routable <see cref="TailscaleNode.Endpoints"/> entry (DERP relay
    /// is future work, so a peer with no direct endpoint is skipped in the lab).</item>
    /// </list>
    /// The data plane's crypto-router (<see cref="WireGuard.Routing.WireGuardCryptoRouter"/>) then routes each outbound
    /// packet to the peer whose allowed-IPs cover the destination by longest-prefix match. The local machine private key
    /// (which is also the WireGuard private key — Tailscale's node key is the WireGuard key) is supplied separately.
    /// </summary>
    public sealed class NetmapToWireGuardConfig
    {
        readonly int _mtu;

        /// <summary>Creates the mapper. <paramref name="mtu"/> is the tunnel MTU (Tailscale default 1280).</summary>
        public NetmapToWireGuardConfig(int mtu = 1280)
        {
            if (mtu < 576) throw new ArgumentOutOfRangeException(nameof(mtu));
            _mtu = mtu;
        }

        /// <summary>
        /// Builds the multi-peer <see cref="WireGuardConfig"/> from <paramref name="map"/>. <paramref name="nodePrivateKey"/>
        /// is the 32-byte X25519 node/WireGuard private key. <paramref name="presharedKey"/> is an optional 32-byte WG
        /// preshared key (Tailscale does not use one by default; pass null). Peers without a usable direct endpoint are
        /// dropped (logged via <paramref name="onPeerSkipped"/>) — DERP relaying is future work.
        /// </summary>
        public WireGuardConfig Build(MapResponse map, byte[] nodePrivateKey, byte[]? presharedKey = null,
            Action<string>? onPeerSkipped = null)
        {
            if (map is null) throw new ArgumentNullException(nameof(map));
            if (nodePrivateKey is null || nodePrivateKey.Length != TailscaleKey.KeyLength)
                throw new ArgumentException("Node private key must be 32 bytes.", nameof(nodePrivateKey));
            if (map.Node is null)
                throw new InvalidOperationException("Netmap has no self node; cannot derive the local tunnel address.");

            (IPAddress? v4, int v4Prefix, IPAddress? v6, int v6Prefix) = SelfAddresses(map.Node);

            var peers = new List<WireGuardPeer>();
            IReadOnlyList<TailscaleNode> peerNodes = map.Peers ?? Array.Empty<TailscaleNode>();
            foreach (TailscaleNode peer in peerNodes)
            {
                if (string.IsNullOrEmpty(peer.Key))
                {
                    onPeerSkipped?.Invoke($"peer ID={peer.ID} has no node key");
                    continue;
                }
                byte[] peerPublicKey;
                try { peerPublicKey = TailscaleKey.DecodeNodePublic(peer.Key); }
                catch (FormatException ex) { onPeerSkipped?.Invoke($"peer ID={peer.ID} bad node key: {ex.Message}"); continue; }

                IReadOnlyList<string> allowed = peer.AllowedIPs ?? peer.Addresses ?? Array.Empty<string>();
                if (allowed.Count == 0)
                {
                    onPeerSkipped?.Invoke($"peer ID={peer.ID} has no allowed-IPs");
                    continue;
                }

                IPEndPoint? endpoint = PickDirectEndpoint(peer.Endpoints);
                if (endpoint is null)
                {
                    onPeerSkipped?.Invoke($"peer ID={peer.ID} has no direct endpoint (DERP relay is not implemented)");
                    continue;
                }

                peers.Add(new WireGuardPeer
                {
                    PublicKey = peerPublicKey,
                    PresharedKey = presharedKey,
                    AllowedIps = allowed,
                    Endpoint = endpoint,
                    PersistentKeepaliveSeconds = 25, // Tailscale keeps NAT mappings alive on direct paths
                });
            }

            return new WireGuardConfig
            {
                PrivateKey = (byte[])nodePrivateKey.Clone(),
                Address = v4,
                PrefixLength = v4Prefix,
                AddressV6 = v6,
                PrefixLengthV6 = v6Prefix,
                Peers = peers,
                Mtu = _mtu,
            };
        }

        // Split the self node's CIDR addresses into the first IPv4 and the first IPv6 (with their prefix lengths).
        static (IPAddress? V4, int V4Prefix, IPAddress? V6, int V6Prefix) SelfAddresses(TailscaleNode self)
        {
            IPAddress? v4 = null; int v4Prefix = 32;
            IPAddress? v6 = null; int v6Prefix = 128;
            foreach (string cidr in self.Addresses ?? Array.Empty<string>())
            {
                if (!TryParseCidr(cidr, out IPAddress addr, out int prefix)) continue;
                if (addr.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork && v4 is null) { v4 = addr; v4Prefix = prefix; }
                else if (addr.AddressFamily == System.Net.Sockets.AddressFamily.InterNetworkV6 && v6 is null) { v6 = addr; v6Prefix = prefix; }
            }
            return (v4, v4Prefix, v6, v6Prefix);
        }

        // Pick the first endpoint that parses as a real ip:port (a direct UDP path). IPv6 endpoints use [addr]:port.
        static IPEndPoint? PickDirectEndpoint(IReadOnlyList<string>? endpoints)
        {
            if (endpoints is null) return null;
            foreach (string ep in endpoints)
                if (TryParseEndpoint(ep, out IPEndPoint result))
                    return result;
            return null;
        }

        static bool TryParseCidr(string cidr, out IPAddress address, out int prefixLength)
        {
            address = IPAddress.None;
            prefixLength = 0;
            if (string.IsNullOrEmpty(cidr)) return false;
            int slash = cidr.IndexOf('/');
            string addrPart = slash < 0 ? cidr : cidr.Substring(0, slash);
            if (!IPAddress.TryParse(addrPart, out IPAddress? parsed) || parsed is null) return false;
            address = parsed;
            if (slash < 0)
            {
                prefixLength = parsed.AddressFamily == System.Net.Sockets.AddressFamily.InterNetworkV6 ? 128 : 32;
                return true;
            }
            return int.TryParse(cidr.Substring(slash + 1), out prefixLength);
        }

        static bool TryParseEndpoint(string text, out IPEndPoint endpoint)
        {
            endpoint = new IPEndPoint(IPAddress.None, 0);
            if (string.IsNullOrEmpty(text)) return false;
            int colon = text.LastIndexOf(':');
            if (colon <= 0 || colon == text.Length - 1) return false;
            string hostPart = text.Substring(0, colon);
            string portPart = text.Substring(colon + 1);
            // IPv6 endpoints are bracketed: [fe80::1]:41641
            if (hostPart.StartsWith("[", StringComparison.Ordinal) && hostPart.EndsWith("]", StringComparison.Ordinal))
                hostPart = hostPart.Substring(1, hostPart.Length - 2);
            if (!IPAddress.TryParse(hostPart, out IPAddress? ip) || ip is null) return false;
            if (!int.TryParse(portPart, out int port) || port <= 0 || port > 65535) return false;
            endpoint = new IPEndPoint(ip, port);
            return true;
        }
    }
}
