using System;
using System.Linq;
using System.Net;
using System.Security.Cryptography;
using TqkLibrary.VpnClient.Tailscale.Control.Messages;
using TqkLibrary.VpnClient.Tailscale.Keys;
using TqkLibrary.VpnClient.Tailscale.Netmap;
using TqkLibrary.VpnClient.WireGuard.Config;
using Xunit;

namespace TqkLibrary.VpnClient.Tailscale.Tests
{
    public class NetmapToWireGuardConfigTests
    {
        static byte[] Random32()
        {
            var b = new byte[32];
            RandomNumberGenerator.Fill(b);
            return b;
        }

        [Fact]
        public void Build_MapsSelfAddress_PeerKey_AllowedIps_Endpoint()
        {
            byte[] peerKeyBytes = Random32();
            byte[] nodePriv = Random32();

            var map = new MapResponse
            {
                Node = new TailscaleNode
                {
                    ID = 1,
                    Key = TailscaleKey.EncodeNodePublic(Random32()),
                    Addresses = new[] { "100.64.0.1/32", "fd7a:115c:a1e0::1/128" },
                },
                Peers = new[]
                {
                    new TailscaleNode
                    {
                        ID = 2,
                        Key = TailscaleKey.EncodeNodePublic(peerKeyBytes),
                        Addresses = new[] { "100.64.0.2/32" },
                        AllowedIPs = new[] { "100.64.0.2/32" },
                        Endpoints = new[] { "192.168.1.7:41641" },
                    },
                },
            };

            var mapper = new NetmapToWireGuardConfig(mtu: 1280);
            WireGuardConfig cfg = mapper.Build(map, nodePriv);

            Assert.Equal(IPAddress.Parse("100.64.0.1"), cfg.Address);
            Assert.Equal(32, cfg.PrefixLength);
            Assert.Equal(IPAddress.Parse("fd7a:115c:a1e0::1"), cfg.AddressV6);
            Assert.Equal(128, cfg.PrefixLengthV6);
            Assert.Equal(nodePriv, cfg.PrivateKey);
            Assert.Equal(1280, cfg.Mtu);

            Assert.Single(cfg.Peers);
            WireGuardPeer peer = cfg.Peers[0];
            Assert.Equal(peerKeyBytes, peer.PublicKey);
            Assert.Equal(new[] { "100.64.0.2/32" }, peer.AllowedIps.ToArray());
            Assert.Equal(new IPEndPoint(IPAddress.Parse("192.168.1.7"), 41641), peer.Endpoint);
            Assert.Equal(25, peer.PersistentKeepaliveSeconds);
        }

        [Fact]
        public void Build_SkipsPeerWithoutDirectEndpoint()
        {
            string skipped = null!;
            var map = new MapResponse
            {
                Node = new TailscaleNode { ID = 1, Key = TailscaleKey.EncodeNodePublic(Random32()), Addresses = new[] { "100.64.0.1/32" } },
                Peers = new[]
                {
                    new TailscaleNode
                    {
                        ID = 9,
                        Key = TailscaleKey.EncodeNodePublic(Random32()),
                        AllowedIPs = new[] { "100.64.0.9/32" },
                        Endpoints = Array.Empty<string>(), // no direct endpoint -> DERP only -> skipped
                    },
                },
            };
            var cfg = new NetmapToWireGuardConfig().Build(map, Random32(), onPeerSkipped: m => skipped = m);
            Assert.Empty(cfg.Peers);
            Assert.Contains("no direct endpoint", skipped);
        }

        [Fact]
        public void Build_NoSelfNode_Throws()
        {
            var map = new MapResponse { Node = null };
            Assert.Throws<InvalidOperationException>(() => new NetmapToWireGuardConfig().Build(map, Random32()));
        }

        [Fact]
        public void Build_Ipv6Endpoint_Parsed()
        {
            var map = new MapResponse
            {
                Node = new TailscaleNode { ID = 1, Key = TailscaleKey.EncodeNodePublic(Random32()), Addresses = new[] { "100.64.0.1/32" } },
                Peers = new[]
                {
                    new TailscaleNode
                    {
                        ID = 3,
                        Key = TailscaleKey.EncodeNodePublic(Random32()),
                        AllowedIPs = new[] { "100.64.0.3/32" },
                        Endpoints = new[] { "[fd00::7]:41641" },
                    },
                },
            };
            var cfg = new NetmapToWireGuardConfig().Build(map, Random32());
            Assert.Single(cfg.Peers);
            Assert.Equal(new IPEndPoint(IPAddress.Parse("fd00::7"), 41641), cfg.Peers[0].Endpoint);
        }
    }
}
