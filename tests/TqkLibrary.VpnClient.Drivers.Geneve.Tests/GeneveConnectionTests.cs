using System;
using System.Net;
using System.Threading;
using System.Threading.Channels;
using System.Threading.Tasks;
using TqkLibrary.VpnClient.Abstractions.Drivers.Enums;
using TqkLibrary.VpnClient.Abstractions.Drivers.Interfaces;
using TqkLibrary.VpnClient.Abstractions.Drivers.Models;
using TqkLibrary.VpnClient.Drivers.Core.Enums;
using TqkLibrary.VpnClient.Drivers.Geneve;
using TqkLibrary.VpnClient.Drivers.Geneve.Config;
using TqkLibrary.VpnClient.Ethernet;
using Xunit;

namespace TqkLibrary.VpnClient.Drivers.Geneve.Tests
{
    /// <summary>
    /// Drives the whole Geneve driver offline against an in-process peer: the real <see cref="GeneveConnection"/> opens the
    /// UDP transport, brings up the L2 Ethernet data plane bridged to L3 via ARP + the VirtualHost, and round-trips IP
    /// packets both directions (ARP-resolving the gateway, then echoing). No sockets — the peer is a throwaway harness.
    /// </summary>
    public class GeneveConnectionTests
    {
        const uint Vni = 0x00CAFE;
        static readonly IPAddress OverlayAddress = IPAddress.Parse("10.20.0.2");
        static readonly IPAddress Gateway = IPAddress.Parse("10.20.0.1");

        static byte[] BuildIpv4Packet(IPAddress src, IPAddress dst, byte tail)
        {
            byte[] packet = new byte[28];
            packet[0] = 0x45;                 // IPv4, IHL 5
            packet[8] = 64;                   // TTL
            packet[9] = 253;                  // protocol (experimental)
            src.GetAddressBytes().CopyTo(packet, 12);
            dst.GetAddressBytes().CopyTo(packet, 16);
            packet[27] = tail;
            return packet;
        }

        static GeneveConfig BuildConfig() => new GeneveConfig
        {
            Vni = Vni,
            OverlayAddress = OverlayAddress,
            PrefixLength = 24,
            LocalMac = MacAddress.Parse("02:00:00:00:00:aa").ToArray(),
        };

        // The host is an IP literal so DnsHostResolver parses it without a DNS lookup (the loopback ignores the resolved
        // endpoint anyway — it self-pumps).
        static GeneveConnection BuildConnection(LoopbackUdpLink link, GeneveConfig config)
        {
            var factory = new InProcessGeneveTransportFactory(link.Client);
            return new GeneveConnection("127.0.0.1", factory, config,
                reconnectOptions: new GeneveReconnectOptions { Enabled = false });
        }

        [Fact]
        public async Task Connect_OpensTransport_AndReachesConnectedState()
        {
            var link = new LoopbackUdpLink();
            using var peer = new SimulatedGenevePeer(link.Server, Vni);
            await using var connection = BuildConnection(link, BuildConfig());

            using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(10));
            await connection.ConnectAsync(cts.Token);

            Assert.Equal(VpnConnectionState.Connected, connection.State);
            Assert.Equal(OverlayAddress, connection.AssignedAddress);
            Assert.Equal(OverlayAddress, connection.Config.AssignedAddress);
        }

        [Fact]
        public async Task Connect_RoundTripsIp_OverL2Fabric()
        {
            var link = new LoopbackUdpLink();
            using var peer = new SimulatedGenevePeer(link.Server, Vni);
            await using var connection = BuildConnection(link, BuildConfig());

            var inbound = Channel.CreateUnbounded<byte[]>();
            connection.PacketChannel.InboundIpPacket += m => inbound.Writer.TryWrite(m.ToArray());

            using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(10));
            await connection.ConnectAsync(cts.Token);

            // Client → peer (ARP-resolve the gateway, then echo) → client: an IP packet survives the L2 Geneve path both ways.
            byte[] packet = BuildIpv4Packet(OverlayAddress, Gateway, 0xAB);
            await connection.PacketChannel.WriteIpPacketAsync(packet, cts.Token);
            byte[] echoed = await inbound.Reader.ReadAsync(cts.Token);
            Assert.Equal(packet, echoed);
            Assert.True(peer.DatagramCount >= 2, "the peer must have received the ARP request and the IP packet as Geneve datagrams");
        }

        [Fact]
        public async Task Driver_Connect_RoundTripsIp_ThroughAdapters()
        {
            var link = new LoopbackUdpLink();
            using var peer = new SimulatedGenevePeer(link.Server, Vni);
            var factory = new InProcessGeneveTransportFactory(link.Client);
            var driver = new GeneveDriver(BuildConfig(), new GeneveReconnectOptions { Enabled = false }, factory);

            using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(10));
            IVpnConnection connection = await driver.ConnectAsync(new VpnEndpoint("127.0.0.1", GeneveCodec.DefaultPort), new VpnCredentials(), cts.Token);
            await using (connection)
            {
                IVpnSession session = Assert.Single(connection.Sessions);
                var inbound = Channel.CreateUnbounded<byte[]>();
                session.PacketChannel.InboundIpPacket += m => inbound.Writer.TryWrite(m.ToArray());

                Assert.Equal(OverlayAddress, session.Config.AssignedAddress);

                byte[] packet = BuildIpv4Packet(OverlayAddress, Gateway, 0xCD);
                await session.PacketChannel.WriteIpPacketAsync(packet, cts.Token);
                byte[] echoed = await inbound.Reader.ReadAsync(cts.Token);
                Assert.Equal(packet, echoed);
            }
        }
    }
}
