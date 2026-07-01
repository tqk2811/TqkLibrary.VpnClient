using System;
using System.Collections.Generic;
using System.Net;
using System.Threading;
using System.Threading.Channels;
using System.Threading.Tasks;
using TqkLibrary.VpnClient.Drivers.Core.Enums;
using TqkLibrary.VpnClient.WireGuard;
using TqkLibrary.VpnClient.WireGuard.Config;
using TqkLibrary.VpnClient.WireGuard.Handshake.Models;
using Xunit;

namespace TqkLibrary.VpnClient.Drivers.WireGuard.Tests
{
    /// <summary>
    /// Drives the WireGuard driver offline with a multi-peer config whose peers have <b>distinct per-peer endpoints</b>
    /// (<see cref="WireGuardPeer.Endpoint"/>). Each endpoint is backed by its own in-process UDP loopback + responder, so
    /// the test proves a peer's outbound (handshake and data) goes to <i>that peer's own endpoint</i>: peer A's LAN
    /// packet comes back tagged "epA" (its responder echoed it), peer B's internet packet comes back tagged "epB". It
    /// also proves peers that leave Endpoint unset share the connection's single socket (the unchanged single-listen
    /// model). The responders are throwaway test scaffolding — the library is a client.
    /// </summary>
    public class WireGuardPerPeerEndpointTests
    {
        [Fact]
        public async Task TwoPeers_DistinctEndpoints_OutboundGoesToOwnEndpoint()
        {
            // peer 0 (LAN 10.0.0.0/24) lives at endpoint A; peer 1 (default route) at endpoint B — different addresses.
            WireGuardKeyPair client = WireGuardTestKeys.NewStatic();
            WireGuardKeyPair serverA = WireGuardTestKeys.NewStatic();
            WireGuardKeyPair serverB = WireGuardTestKeys.NewStatic();

            var endpointA = new IPEndPoint(IPAddress.Parse("203.0.113.1"), 51820);
            var endpointB = new IPEndPoint(IPAddress.Parse("198.51.100.2"), 41820);

            var config = new WireGuardConfig
            {
                PrivateKey = client.PrivateKey,
                Address = IPAddress.Parse("10.0.0.2"),
                PrefixLength = 24,
                Mtu = WireGuardConstants.DefaultMtu,
                Peers = new[]
                {
                    new WireGuardPeer { PublicKey = serverA.PublicKey, AllowedIps = new[] { "10.0.0.0/24" }, Endpoint = endpointA },
                    new WireGuardPeer { PublicKey = serverB.PublicKey, AllowedIps = new[] { "0.0.0.0/0", "::/0" }, Endpoint = endpointB },
                },
            };

            // One loopback + responder per endpoint. Each responder echoes its own per-endpoint tag so the echoed inner
            // packet identifies which endpoint carried it.
            var linkA = new LoopbackUdpLink();
            var linkB = new LoopbackUdpLink();
            using var responderA = new MultiPeerResponder(linkA.Server, client.PublicKey, (serverA, "epA"));
            using var responderB = new MultiPeerResponder(linkB.Server, client.PublicKey, (serverB, "epB"));

            var factory = new EndpointRoutingWireGuardTransportFactory(new Dictionary<IPEndPoint, LoopbackUdpLink.Endpoint>
            {
                [endpointA] = linkA.Client,
                [endpointB] = linkB.Client,
            });

            using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(30));
            // The connection host/port is irrelevant here — both peers carry an explicit endpoint.
            var connection = new WireGuardConnection("127.0.0.1", 1, config, factory);

            var inbound = Channel.CreateUnbounded<byte[]>();
            connection.PacketChannel.InboundIpPacket += m => inbound.Writer.TryWrite(m.ToArray());

            await connection.ConnectAsync(cts.Token);
            Assert.Equal(VpnConnectionState.Connected, connection.State);

            // The connection opened a transport to each peer's own endpoint (and only those).
            Assert.Contains(endpointA, factory.ConnectedEndpoints);
            Assert.Contains(endpointB, factory.ConnectedEndpoints);

            // A LAN packet routes to peer 0 → sealed and sent over peer 0's transport → endpoint A's responder echoes "epA".
            byte[] lanPacket = BuildIpv4("10.0.0.2", "10.0.0.50", payload: 0x11);
            await connection.PacketChannel.WriteIpPacketAsync(lanPacket, cts.Token);
            Assert.Equal(MultiPeerResponder.EchoTag("epA"), await inbound.Reader.ReadAsync(cts.Token));

            // An internet packet routes to peer 1 → peer 1's transport → endpoint B's responder echoes "epB".
            byte[] netPacket = BuildIpv4("10.0.0.2", "8.8.8.8", payload: 0x22);
            await connection.PacketChannel.WriteIpPacketAsync(netPacket, cts.Token);
            Assert.Equal(MultiPeerResponder.EchoTag("epB"), await inbound.Reader.ReadAsync(cts.Token));

            await connection.DisposeAsync();
        }

        [Fact]
        public async Task PeersWithoutEndpoint_ShareTheConnectionSocket()
        {
            // Neither peer sets an explicit endpoint → both fall back to the connection's host:port → one shared socket
            // (the unchanged single-listen-socket model). One loopback + one multi-peer responder hosts both peers.
            WireGuardKeyPair client = WireGuardTestKeys.NewStatic();
            WireGuardKeyPair server0 = WireGuardTestKeys.NewStatic();
            WireGuardKeyPair server1 = WireGuardTestKeys.NewStatic();

            var config = new WireGuardConfig
            {
                PrivateKey = client.PrivateKey,
                Address = IPAddress.Parse("10.0.0.2"),
                PrefixLength = 24,
                Mtu = WireGuardConstants.DefaultMtu,
                Peers = new[]
                {
                    new WireGuardPeer { PublicKey = server0.PublicKey, AllowedIps = new[] { "10.0.0.0/24" } },
                    new WireGuardPeer { PublicKey = server1.PublicKey, AllowedIps = new[] { "0.0.0.0/0", "::/0" } },
                },
            };

            var connectionEndpoint = new IPEndPoint(IPAddress.Parse("127.0.0.1"), 51820);
            var link = new LoopbackUdpLink();
            using var responder = new MultiPeerResponder(link.Server, client.PublicKey, (server0, "p0"), (server1, "p1"));

            var factory = new EndpointRoutingWireGuardTransportFactory(new Dictionary<IPEndPoint, LoopbackUdpLink.Endpoint>
            {
                [connectionEndpoint] = link.Client,
            });

            using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(30));
            var connection = new WireGuardConnection("127.0.0.1", 51820, config, factory);

            var inbound = Channel.CreateUnbounded<byte[]>();
            connection.PacketChannel.InboundIpPacket += m => inbound.Writer.TryWrite(m.ToArray());

            await connection.ConnectAsync(cts.Token);
            Assert.Equal(VpnConnectionState.Connected, connection.State);

            // Both peers resolved to the same endpoint → the factory was asked for exactly one transport (de-dup).
            Assert.Single(factory.ConnectedEndpoints);
            Assert.Equal(connectionEndpoint, factory.ConnectedEndpoints[0]);

            // Both peers still route correctly over the one shared socket.
            await connection.PacketChannel.WriteIpPacketAsync(BuildIpv4("10.0.0.2", "10.0.0.9", 0x33), cts.Token);
            Assert.Equal(MultiPeerResponder.EchoTag("p0"), await inbound.Reader.ReadAsync(cts.Token));

            await connection.PacketChannel.WriteIpPacketAsync(BuildIpv4("10.0.0.2", "8.8.8.8", 0x44), cts.Token);
            Assert.Equal(MultiPeerResponder.EchoTag("p1"), await inbound.Reader.ReadAsync(cts.Token));

            await connection.DisposeAsync();
        }

        static byte[] BuildIpv4(string src, string dst, byte payload)
        {
            byte[] packet = new byte[20 + 1];
            packet[0] = 0x45; // version 4, IHL 5
            IPAddress.Parse(src).GetAddressBytes().CopyTo(packet, 12);
            IPAddress.Parse(dst).GetAddressBytes().CopyTo(packet, 16);
            packet[20] = payload;
            return packet;
        }
    }
}
