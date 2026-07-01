using System;
using System.Collections.Generic;
using System.Net;
using System.Threading;
using System.Threading.Channels;
using System.Threading.Tasks;
using TqkLibrary.VpnClient.Drivers.Core.Enums;
using TqkLibrary.VpnClient.WireGuard;
using TqkLibrary.VpnClient.WireGuard.Config;
using TqkLibrary.VpnClient.WireGuard.DataChannel;
using TqkLibrary.VpnClient.WireGuard.Handshake;
using TqkLibrary.VpnClient.WireGuard.Handshake.Models;
using Xunit;

namespace TqkLibrary.VpnClient.Drivers.WireGuard.Tests
{
    /// <summary>
    /// Drives the WireGuard driver offline with a <b>multi-peer</b> config against an in-process responder that hosts
    /// several peers on one UDP loopback (demuxing initiations by mac1 and data by receiver index). It proves the
    /// driver runs an independent handshake per peer, and that the data plane crypto-routes each outbound packet to the
    /// peer whose allowed-ips cover its destination by longest-prefix match (IPv4 + IPv6), dropping a destination no
    /// peer claims. The responder is throwaway test scaffolding — the library is a client.
    /// </summary>
    public class WireGuardMultiPeerTests
    {
        [Fact]
        public async Task TwoPeers_RoutesByLongestPrefix_AndDropsUnroutable()
        {
            // peer 0 = full tunnel (0.0.0.0/0); peer 1 = the LAN 10.0.0.0/24. A LAN packet must reach peer 1, an
            // internet packet peer 0. The two responders echo, so we can tell which peer carried a packet by its tag.
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
                    new WireGuardPeer { PublicKey = server0.PublicKey, AllowedIps = new[] { "0.0.0.0/0", "::/0" } },
                    new WireGuardPeer { PublicKey = server1.PublicKey, AllowedIps = new[] { "10.0.0.0/24" } },
                },
            };

            var link = new LoopbackUdpLink();
            using var responder = new MultiPeerResponder(link.Server, client.PublicKey,
                (server0, "peer0"), (server1, "peer1"));

            using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(30));
            var connection = new WireGuardConnection("127.0.0.1", 51820, config,
                new InProcessWireGuardTransportFactory(link.Client));

            var inbound = Channel.CreateUnbounded<byte[]>();
            connection.PacketChannel.InboundIpPacket += m => inbound.Writer.TryWrite(m.ToArray());

            await connection.ConnectAsync(cts.Token);
            Assert.Equal(VpnConnectionState.Connected, connection.State);

            // A LAN-destined IPv4 packet → peer 1 (10.0.0.0/24, the longest prefix).
            byte[] lanPacket = BuildIpv4("10.0.0.2", "10.0.0.50", payload: 0x11);
            await connection.PacketChannel.WriteIpPacketAsync(lanPacket, cts.Token);
            byte[] lanEcho = await ReadEchoedPayloadAsync(inbound, cts.Token);
            Assert.Equal(MultiPeerResponder.EchoTag("peer1"), lanEcho);

            // An internet-destined IPv4 packet → peer 0 (only its 0.0.0.0/0 covers it).
            byte[] netPacket = BuildIpv4("10.0.0.2", "8.8.8.8", payload: 0x22);
            await connection.PacketChannel.WriteIpPacketAsync(netPacket, cts.Token);
            byte[] netEcho = await ReadEchoedPayloadAsync(inbound, cts.Token);
            Assert.Equal(MultiPeerResponder.EchoTag("peer0"), netEcho);

            // An IPv6 packet → peer 0 (its ::/0 is the only v6 route).
            byte[] v6Packet = BuildIpv6("2001:db8::2", "2606:4700::1111", payload: 0x33);
            await connection.PacketChannel.WriteIpPacketAsync(v6Packet, cts.Token);
            byte[] v6Echo = await ReadEchoedPayloadAsync(inbound, cts.Token);
            Assert.Equal(MultiPeerResponder.EchoTag("peer0"), v6Echo);

            await connection.DisposeAsync();
        }

        [Fact]
        public async Task NoPeerCoversDestination_PacketIsDropped()
        {
            // Neither peer carries a default route; an address outside both prefixes has no route and is dropped.
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
                    new WireGuardPeer { PublicKey = server1.PublicKey, AllowedIps = new[] { "192.168.0.0/24" } },
                },
            };

            var link = new LoopbackUdpLink();
            using var responder = new MultiPeerResponder(link.Server, client.PublicKey,
                (server0, "peer0"), (server1, "peer1"));

            using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(30));
            var connection = new WireGuardConnection("127.0.0.1", 51820, config,
                new InProcessWireGuardTransportFactory(link.Client));

            var inbound = Channel.CreateUnbounded<byte[]>();
            connection.PacketChannel.InboundIpPacket += m => inbound.Writer.TryWrite(m.ToArray());

            await connection.ConnectAsync(cts.Token);

            // 8.8.8.8 matches no peer → dropped → no echo arrives. A routable LAN packet sent afterwards proves the
            // channel is still live (the drop did not wedge anything), and that it is the only thing that comes back.
            byte[] unroutable = BuildIpv4("10.0.0.2", "8.8.8.8", payload: 0x44);
            await connection.PacketChannel.WriteIpPacketAsync(unroutable, cts.Token);

            byte[] routable = BuildIpv4("10.0.0.2", "10.0.0.9", payload: 0x55);
            await connection.PacketChannel.WriteIpPacketAsync(routable, cts.Token);

            byte[] echo = await ReadEchoedPayloadAsync(inbound, cts.Token);
            Assert.Equal(MultiPeerResponder.EchoTag("peer0"), echo); // only the routable packet echoed

            await connection.DisposeAsync();
        }

        // ---- helpers ----

        // The responder echoes a fixed per-peer tag, so the echoed inner packet identifies the peer that carried it.
        static async Task<byte[]> ReadEchoedPayloadAsync(Channel<byte[]> inbound, CancellationToken ct)
            => await inbound.Reader.ReadAsync(ct);

        static byte[] BuildIpv4(string src, string dst, byte payload)
        {
            byte[] packet = new byte[20 + 1];
            packet[0] = 0x45; // version 4, IHL 5
            IPAddress.Parse(src).GetAddressBytes().CopyTo(packet, 12);
            IPAddress.Parse(dst).GetAddressBytes().CopyTo(packet, 16);
            packet[20] = payload;
            return packet;
        }

        static byte[] BuildIpv6(string src, string dst, byte payload)
        {
            byte[] packet = new byte[40 + 1];
            packet[0] = 0x60; // version 6
            IPAddress.Parse(src).GetAddressBytes().CopyTo(packet, 8);
            IPAddress.Parse(dst).GetAddressBytes().CopyTo(packet, 24);
            packet[40] = payload;
            return packet;
        }
    }

    /// <summary>
    /// A throwaway responder hosting several WireGuard peers on one UDP loopback. It demuxes an inbound type-1
    /// initiation to a peer by trying each peer's mac1 (each peer has its own static key), answers with a type-2
    /// response, and for inbound type-4 data tries each peer's transport in turn and echoes a fixed per-peer tag back
    /// so a test can tell which peer carried the packet. Lossless ordered loopback — no retransmit/reorder logic.
    /// </summary>
    sealed class MultiPeerResponder : IDisposable
    {
        readonly LoopbackUdpLink.Endpoint _transport;
        readonly byte[] _clientPublic;
        readonly WireGuardMessageCodec _codec = new();
        readonly object _sync = new();
        readonly List<PeerSlot> _peers = new();

        public MultiPeerResponder(LoopbackUdpLink.Endpoint transport, byte[] clientPublic,
            params (WireGuardKeyPair staticKey, string name)[] peers)
        {
            _transport = transport;
            _clientPublic = clientPublic;
            foreach ((WireGuardKeyPair staticKey, string name) in peers)
                _peers.Add(new PeerSlot(staticKey, name));
            _transport.SetReceiver(OnInbound);
        }

        /// <summary>The single-byte inner packet a peer echoes — a stable per-peer identity the test asserts on.</summary>
        public static byte[] EchoTag(string name) => System.Text.Encoding.ASCII.GetBytes("echo:" + name);

        void OnInbound(ReadOnlyMemory<byte> datagram)
        {
            ReadOnlySpan<byte> span = datagram.Span;
            if (span.Length < 1) return;
            byte type = span[0];
            if (type == WireGuardConstants.MessageTypeInitiation) HandleInitiation(span);
            else if (type == WireGuardConstants.MessageTypeTransportData) HandleData(span);
        }

        void HandleInitiation(ReadOnlySpan<byte> span)
        {
            if (!_codec.TryDecodeInitiation(span, out WireGuardInitiationMessage init)) return;

            // Demux to the peer whose static key verifies mac1 (WireGuard's own first-cut filter under a single socket).
            foreach (PeerSlot peer in _peers)
            {
                var handshake = new WireGuardHandshake(peer.StaticKey, remoteStaticPublic: _clientPublic);
                if (!handshake.VerifyIncomingMac1(span)) continue;
                if (!handshake.ConsumeInitiation(init, out _, out _)) return;

                uint localIndex = peer.NextLocalIndex();
                WireGuardResponseMessage resp = handshake.CreateResponse(localIndex, init.SenderIndex);
                byte[] wire = _codec.EncodeResponse(resp);
                handshake.StampOutgoingMacs(wire);

                WireGuardTransportKeys keys = handshake.DeriveTransportKeys();
                lock (_sync)
                    peer.Data = new WireGuardTransport(keys, sendReceiverIndex: init.SenderIndex, localReceiverIndex: localIndex);
                _ = _transport.SendAsync(wire);
                return;
            }
        }

        void HandleData(ReadOnlySpan<byte> span)
        {
            // The receiver index addresses one peer's session; try each peer's transport and echo its tag back.
            foreach (PeerSlot peer in _peers)
            {
                WireGuardTransport? data;
                lock (_sync) data = peer.Data;
                if (data is null) continue;
                if (!data.TryOpen(span, out byte[] inner)) continue;
                if (inner.Length == 0) return; // keepalive
                _ = _transport.SendAsync(data.Seal(EchoTag(peer.Name)));
                return;
            }
        }

        public void Dispose() { }

        sealed class PeerSlot
        {
            uint _next = 0xB0000000u;
            public PeerSlot(WireGuardKeyPair staticKey, string name) { StaticKey = staticKey; Name = name; }
            public WireGuardKeyPair StaticKey { get; }
            public string Name { get; }
            public WireGuardTransport? Data { get; set; }
            public uint NextLocalIndex() => _next++;
        }
    }
}
