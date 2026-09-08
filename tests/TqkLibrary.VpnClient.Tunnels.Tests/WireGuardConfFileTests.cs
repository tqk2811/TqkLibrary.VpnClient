using TqkLibrary.VpnClient.Tunnels;
using TqkLibrary.VpnClient.WireGuard.Config;
using Xunit;

namespace TqkLibrary.VpnClient.Tunnels.Tests
{
    /// <summary>
    /// Reading a provider's wg-quick file — and the one thing the reader is allowed to supply that
    /// the file does not say.
    /// </summary>
    public class WireGuardConfFileTests
    {
        const string Minimal = """
            [Interface]
            PrivateKey = QFHmv5F0h0EDRuWYPuT3ZoIRCLJFYnGKpZ7YgpJJVVg=
            Address = 10.7.0.2/32

            [Peer]
            PublicKey = xTIBA5rboUvnH4htodjb6e697QjLERt1NAB4mZqp8Dg=
            AllowedIPs = 0.0.0.0/0
            Endpoint = vpn.example.com:51820
            """;

        [Fact]
        public void The_file_is_read_exactly_as_written_by_default()
        {
            (WireGuardConfig config, string host, int port) = WireGuardConfFile.Parse(Minimal);

            Assert.Equal("vpn.example.com", host);
            Assert.Equal(51820, port);
            Assert.Equal(0, config.PersistentKeepaliveSeconds);
        }

        // WireGuard's default is off, and that assumes something else keeps the path open. A caller
        // holding the tunnel up in its own process has nothing else: the peer is behind NAT, and a
        // mapping dropped after a minute of silence takes the tunnel with it — with no link-loss in
        // the protocol to report it.
        [Fact]
        public void A_caller_can_supply_the_keepalive_a_providers_file_leaves_out()
        {
            (WireGuardConfig config, _, _) = WireGuardConfFile.Parse(Minimal, 25);

            Assert.Equal(25, config.PersistentKeepaliveSeconds);
        }

        // The file wins wherever it has an opinion — including the explicit "off" that a peer with a
        // public endpoint may genuinely want. Zero is indistinguishable from absent in the file, so
        // "off" written down still takes the caller's default; anything else is the file's.
        [Fact]
        public void The_file_keeps_its_own_keepalive_when_it_has_one()
        {
            string withKeepalive = Minimal + "\nPersistentKeepalive = 15\n";

            (WireGuardConfig config, _, _) = WireGuardConfFile.Parse(withKeepalive, 25);

            Assert.Equal(15, config.PersistentKeepaliveSeconds);
        }

        [Fact]
        public void The_single_peer_carries_the_keepalive_into_the_driver()
        {
            (WireGuardConfig config, _, _) = WireGuardConfFile.Parse(Minimal, 25);

            WireGuardPeer peer = Assert.Single(config.EnumeratePeers());
            Assert.Equal(25, peer.PersistentKeepaliveSeconds);
        }
    }
}
