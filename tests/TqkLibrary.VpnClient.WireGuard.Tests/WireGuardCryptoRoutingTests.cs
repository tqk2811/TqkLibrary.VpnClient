using System.Collections.Generic;
using System.Net;
using TqkLibrary.VpnClient.WireGuard.Routing;
using Xunit;

namespace TqkLibrary.VpnClient.WireGuard.Tests
{
    /// <summary>
    /// Offline tests for WireGuard crypto-routing (V.3 multi-peer): an outbound packet is sent to the peer whose
    /// <c>AllowedIPs</c> cover its destination by <b>longest-prefix match</b>, IPv4 and IPv6 alike, and a destination
    /// no peer claims is dropped (no route). Pure value-object logic — no sockets, no crypto.
    /// </summary>
    public class WireGuardCryptoRoutingTests
    {
        static WireGuardCryptoRouter Build(params string[][] perPeer)
        {
            var list = new List<IReadOnlyList<string>>();
            foreach (string[] p in perPeer) list.Add(p);
            return WireGuardCryptoRouter.Build(list);
        }

        // ---- IpPrefix ----

        [Theory]
        [InlineData("10.0.0.0/24", "10.0.0.5", true)]
        [InlineData("10.0.0.0/24", "10.0.1.5", false)]
        [InlineData("0.0.0.0/0", "8.8.8.8", true)]
        [InlineData("192.168.1.128/25", "192.168.1.200", true)]
        [InlineData("192.168.1.128/25", "192.168.1.5", false)]
        [InlineData("2001:db8::/32", "2001:db8::1", true)]
        [InlineData("2001:db8::/32", "2001:dead::1", false)]
        [InlineData("::/0", "fe80::1", true)]
        public void IpPrefix_Contains_MatchesByPrefix(string cidr, string address, bool expected)
        {
            Assert.True(IpPrefix.TryParse(cidr, out IpPrefix prefix));
            Assert.Equal(expected, prefix.Contains(IPAddress.Parse(address)));
        }

        [Fact]
        public void IpPrefix_BareHost_IsFullLengthPrefix()
        {
            Assert.True(IpPrefix.TryParse("10.0.0.7", out IpPrefix v4));
            Assert.Equal(32, v4.PrefixLength);
            Assert.True(v4.Contains(IPAddress.Parse("10.0.0.7")));
            Assert.False(v4.Contains(IPAddress.Parse("10.0.0.8")));

            Assert.True(IpPrefix.TryParse("2001:db8::1", out IpPrefix v6));
            Assert.Equal(128, v6.PrefixLength);
        }

        [Fact]
        public void IpPrefix_HostBitsAreMasked_SoEqualNetworksAreEqual()
        {
            Assert.True(IpPrefix.TryParse("10.0.0.0/24", out IpPrefix a));
            Assert.True(IpPrefix.TryParse("10.0.0.99/24", out IpPrefix b)); // host bits set in the input
            Assert.Equal(a, b);
        }

        [Theory]
        [InlineData("not-an-ip")]
        [InlineData("10.0.0.0/33")]    // prefix too long for IPv4
        [InlineData("2001:db8::/129")] // prefix too long for IPv6
        [InlineData("10.0.0.0/-1")]
        [InlineData("")]
        public void IpPrefix_TryParse_RejectsBadInput(string text)
            => Assert.False(IpPrefix.TryParse(text, out _));

        [Fact]
        public void IpPrefix_DoesNotMatchAcrossFamilies()
        {
            Assert.True(IpPrefix.TryParse("0.0.0.0/0", out IpPrefix v4Default));
            Assert.False(v4Default.Contains(IPAddress.Parse("2001:db8::1"))); // v4 /0 never matches a v6 address
        }

        // ---- WireGuardCryptoRouter ----

        [Fact]
        public void Route_TwoPeers_DefaultAndSpecific_PicksByDestination()
        {
            // peer 0 = full tunnel; peer 1 = a LAN. A LAN address goes to peer 1, everything else to peer 0.
            var router = Build(new[] { "0.0.0.0/0", "::/0" }, new[] { "10.0.0.0/24" });

            Assert.True(router.TryRoute(IPAddress.Parse("10.0.0.5"), out int lan));
            Assert.Equal(1, lan);

            Assert.True(router.TryRoute(IPAddress.Parse("8.8.8.8"), out int internet));
            Assert.Equal(0, internet);
        }

        [Fact]
        public void Route_LongestPrefixWins_OverLessSpecificPeer()
        {
            // peer 0 owns 10.0.0.0/8, peer 1 owns the more specific 10.1.2.0/24 inside it.
            var router = Build(new[] { "10.0.0.0/8" }, new[] { "10.1.2.0/24" });

            Assert.True(router.TryRoute(IPAddress.Parse("10.1.2.50"), out int specific));
            Assert.Equal(1, specific); // /24 beats /8

            Assert.True(router.TryRoute(IPAddress.Parse("10.9.9.9"), out int broad));
            Assert.Equal(0, broad); // only the /8 covers it
        }

        [Fact]
        public void Route_IPv6_PicksCorrectPeer()
        {
            var router = Build(new[] { "::/0" }, new[] { "2001:db8:abcd::/48" });

            Assert.True(router.TryRoute(IPAddress.Parse("2001:db8:abcd::1"), out int specific));
            Assert.Equal(1, specific);

            Assert.True(router.TryRoute(IPAddress.Parse("2606:4700::1"), out int other));
            Assert.Equal(0, other);
        }

        [Fact]
        public void Route_NoMatch_ReturnsFalse()
        {
            // Neither peer carries a default route, so an address outside both prefixes has no route.
            var router = Build(new[] { "10.0.0.0/24" }, new[] { "192.168.0.0/24" });

            Assert.False(router.TryRoute(IPAddress.Parse("8.8.8.8"), out int peer));
            Assert.Equal(-1, peer);
        }

        [Fact]
        public void Route_PrefixLengthTie_PicksEarliestPeer()
        {
            // Both peers claim the same /24; WireGuard's "first matching most-specific" picks the earlier peer.
            var router = Build(new[] { "10.0.0.0/24" }, new[] { "10.0.0.0/24" });

            Assert.True(router.TryRoute(IPAddress.Parse("10.0.0.5"), out int peer));
            Assert.Equal(0, peer);
        }

        [Fact]
        public void Route_SkipsUnparseableCidr()
        {
            var router = Build(new[] { "garbage", "10.0.0.0/24" });
            Assert.True(router.TryRoute(IPAddress.Parse("10.0.0.5"), out int peer));
            Assert.Equal(0, peer);
            Assert.False(router.TryRoute(IPAddress.Parse("8.8.8.8"), out _));
        }
    }
}
