using System.Net;

namespace TqkLibrary.VpnClient.WireGuard.Routing
{
    /// <summary>
    /// The outbound crypto-routing table of a WireGuard interface: it maps each peer's <c>AllowedIPs</c> to that peer's
    /// index, then for an outbound packet picks the peer by <b>longest-prefix match</b> on the destination address —
    /// exactly how the real WireGuard data plane decides which peer (and thus which key) seals a packet. A more
    /// specific prefix always wins, so a peer with <c>10.0.0.0/24</c> takes precedence over one with <c>0.0.0.0/0</c>
    /// for an address in <c>10.0.0.0/24</c>. Ties (two peers claiming the same prefix length cover the destination)
    /// resolve to the peer added first, matching WireGuard's "first matching most-specific allowed-ip wins".
    /// <para>
    /// This is a pure, immutable lookup structure built once from the parsed config (no I/O); the data channel calls
    /// <see cref="TryRoute"/> per outbound packet. Entries with an unparseable CIDR are skipped at build time.
    /// </para>
    /// </summary>
    public sealed class WireGuardCryptoRouter
    {
        // One (prefix → peer index) entry; kept in insertion order so a length-tie resolves to the earlier peer.
        readonly Entry[] _entries;

        WireGuardCryptoRouter(Entry[] entries) => _entries = entries;

        /// <summary>The number of routing entries (one per parseable allowed-ip across all peers).</summary>
        public int Count => _entries.Length;

        /// <summary>
        /// Builds the table from a peer-indexed list of allowed-ips: <paramref name="peerAllowedIps"/>[i] is peer i's
        /// CIDR list. Unparseable CIDR text is skipped (it can never match). The table preserves peer order so a
        /// prefix-length tie picks the earlier peer.
        /// </summary>
        public static WireGuardCryptoRouter Build(IReadOnlyList<IReadOnlyList<string>> peerAllowedIps)
        {
            if (peerAllowedIps is null) throw new ArgumentNullException(nameof(peerAllowedIps));
            var entries = new List<Entry>();
            for (int peerIndex = 0; peerIndex < peerAllowedIps.Count; peerIndex++)
            {
                IReadOnlyList<string> allowed = peerAllowedIps[peerIndex];
                if (allowed is null) continue;
                foreach (string cidr in allowed)
                    if (IpPrefix.TryParse(cidr, out IpPrefix prefix))
                        entries.Add(new Entry(prefix, peerIndex));
            }
            return new WireGuardCryptoRouter(entries.ToArray());
        }

        /// <summary>
        /// Picks the peer that should carry a packet to <paramref name="destination"/> by longest-prefix match. Returns
        /// <c>false</c> (caller drops the packet) when no peer's allowed-ips cover the destination. On a tie in prefix
        /// length the earliest-added peer wins.
        /// </summary>
        public bool TryRoute(IPAddress destination, out int peerIndex)
        {
            peerIndex = -1;
            if (destination is null) return false;

            int bestLength = -1;
            for (int i = 0; i < _entries.Length; i++)
            {
                Entry entry = _entries[i];
                if (entry.Prefix.PrefixLength <= bestLength) continue; // can't beat the current best — skip the match work
                if (entry.Prefix.Contains(destination))
                {
                    bestLength = entry.Prefix.PrefixLength;
                    peerIndex = entry.PeerIndex;
                }
            }
            return peerIndex >= 0;
        }

        readonly struct Entry
        {
            public Entry(IpPrefix prefix, int peerIndex) { Prefix = prefix; PeerIndex = peerIndex; }
            public IpPrefix Prefix { get; }
            public int PeerIndex { get; }
        }
    }
}
