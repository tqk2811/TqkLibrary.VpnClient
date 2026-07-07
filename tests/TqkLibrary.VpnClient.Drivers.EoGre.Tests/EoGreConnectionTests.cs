using System;
using System.Net;
using System.Threading;
using System.Threading.Channels;
using System.Threading.Tasks;
using TqkLibrary.VpnClient.Abstractions.Drivers.Enums;
using TqkLibrary.VpnClient.Abstractions.Drivers.Interfaces;
using TqkLibrary.VpnClient.Abstractions.Drivers.Models;
using TqkLibrary.VpnClient.Drivers.Core.Enums;
using TqkLibrary.VpnClient.Drivers.EoGre;
using TqkLibrary.VpnClient.Drivers.EoGre.Config;
using TqkLibrary.VpnClient.Drivers.EoGre.Enums;
using TqkLibrary.VpnClient.Ethernet;
using Xunit;

namespace TqkLibrary.VpnClient.Drivers.EoGre.Tests
{
    /// <summary>
    /// Drives the whole EoGRE / NVGRE driver offline against an in-process peer: the real <see cref="EoGreConnection"/>
    /// opens the UDP transport, brings up the L2 Ethernet data plane bridged to L3 via ARP + the VirtualHost, and
    /// round-trips IP packets both directions (ARP-resolving the gateway, then echoing). No sockets — the peer is a
    /// throwaway harness. Covers both driver modes and the strict-VSID drop.
    /// </summary>
    public class EoGreConnectionTests
    {
        const uint Vsid = 0x00CAFE;
        static readonly IPAddress OverlayAddress = IPAddress.Parse("10.20.0.2");
        static readonly IPAddress Gateway = IPAddress.Parse("10.20.0.1");
        static readonly byte[] ClientMac = MacAddress.Parse("02:00:00:00:00:aa").ToArray();

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

        static EoGreConfig BuildConfig(uint? vsid) => new EoGreConfig
        {
            Vsid = vsid,
            OverlayAddress = OverlayAddress,
            PrefixLength = 24,
            LocalMac = ClientMac,
        };

        // The host is an IP literal so DnsHostResolver parses it without a DNS lookup (the loopback ignores the resolved
        // endpoint anyway — it self-pumps).
        static EoGreConnection BuildConnection(LoopbackUdpLink link, EoGreConfig config, EoGreMode mode)
        {
            var factory = new InProcessEoGreTransportFactory(link.Client);
            return new EoGreConnection("127.0.0.1", factory, config, mode,
                reconnectOptions: new EoGreReconnectOptions { Enabled = false });
        }

        [Fact]
        public async Task Connect_OpensTransport_AndReachesConnectedState()
        {
            var link = new LoopbackUdpLink();
            using var peer = new SimulatedEoGrePeer(link.Server, Vsid);
            await using var connection = BuildConnection(link, BuildConfig(Vsid), EoGreMode.EoGre);

            using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(10));
            await connection.ConnectAsync(cts.Token);

            Assert.Equal(VpnConnectionState.Connected, connection.State);
            Assert.Equal(OverlayAddress, connection.AssignedAddress);
            Assert.Equal(OverlayAddress, connection.Config.AssignedAddress);
        }

        [Theory]
        [InlineData(EoGreMode.EoGre, 0x00CAFEu)]   // EoGRE with a VSID in the Key
        [InlineData(EoGreMode.EoGre, null)]        // plain GRETAP, no VSID
        [InlineData(EoGreMode.Nvgre, 0x00CAFEu)]   // NVGRE (mandatory VSID, strict)
        public async Task Connect_RoundTripsIp_OverL2Fabric(EoGreMode mode, uint? vsid)
        {
            var link = new LoopbackUdpLink();
            using var peer = new SimulatedEoGrePeer(link.Server, vsid);
            await using var connection = BuildConnection(link, BuildConfig(vsid), mode);

            var inbound = Channel.CreateUnbounded<byte[]>();
            connection.PacketChannel.InboundIpPacket += m => inbound.Writer.TryWrite(m.ToArray());

            using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(10));
            await connection.ConnectAsync(cts.Token);

            // Client → peer (ARP-resolve the gateway, then echo) → client: an IP packet survives the L2 GRE path both ways.
            byte[] packet = BuildIpv4Packet(OverlayAddress, Gateway, 0xAB);
            await connection.PacketChannel.WriteIpPacketAsync(packet, cts.Token);
            byte[] echoed = await inbound.Reader.ReadAsync(cts.Token);
            Assert.Equal(packet, echoed);
            Assert.True(peer.DatagramCount >= 2, "the peer must have received the ARP request and the IP packet as GRE datagrams");
        }

        [Fact]
        public async Task Nvgre_DropsInbound_WithMismatchedVsid()
        {
            var link = new LoopbackUdpLink();
            await using var connection = BuildConnection(link, BuildConfig(Vsid), EoGreMode.Nvgre);

            var inbound = Channel.CreateUnbounded<byte[]>();
            connection.PacketChannel.InboundIpPacket += m => inbound.Writer.TryWrite(m.ToArray());

            using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(10));
            await connection.ConnectAsync(cts.Token);

            MacAddress clientMac = MacAddress.FromBytes(ClientMac);
            MacAddress gatewayMac = MacAddress.Parse("5e:00:00:00:7e:01");
            byte[] ip = BuildIpv4Packet(Gateway, OverlayAddress, 0xCD);
            byte[] frame = EthernetFrame.Build(clientMac, gatewayMac, EthernetFrame.EtherTypeIpv4, ip);

            // A datagram carrying a DIFFERENT VSID must be dropped by the strict-VSID connection (RFC 7637 tenant isolation).
            await link.Server.SendAsync(EoGreCodec.EncodeEoGre(frame, vsid: Vsid ^ 0x01u), cts.Token);
            await Task.Delay(200, cts.Token);
            Assert.False(inbound.Reader.TryRead(out _), "a mismatched-VSID datagram must not reach the IP stack");

            // The very same frame under the correct VSID is delivered — confirms the drop above was the VSID check, not the path.
            await link.Server.SendAsync(EoGreCodec.EncodeEoGre(frame, vsid: Vsid), cts.Token);
            byte[] delivered = await inbound.Reader.ReadAsync(cts.Token);
            Assert.Equal(ip, delivered);
        }

        [Fact]
        public async Task Driver_Connect_RoundTripsIp_ThroughAdapters_Nvgre()
        {
            var link = new LoopbackUdpLink();
            using var peer = new SimulatedEoGrePeer(link.Server, Vsid);
            var factory = new InProcessEoGreTransportFactory(link.Client);
            var driver = new EoGreDriver(BuildConfig(Vsid), EoGreMode.Nvgre, new EoGreReconnectOptions { Enabled = false }, factory);

            using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(10));
            IVpnConnection connection = await driver.ConnectAsync(new VpnEndpoint("127.0.0.1", EoGreCodec.DefaultPort), new VpnCredentials(), cts.Token);
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
