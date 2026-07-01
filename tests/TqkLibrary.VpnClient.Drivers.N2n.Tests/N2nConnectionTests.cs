using System.Net;
using System.Threading.Channels;
using TqkLibrary.VpnClient.Abstractions.Drivers;
using TqkLibrary.VpnClient.Drivers.N2n.Config;
using TqkLibrary.VpnClient.Drivers.Core.Enums;
using TqkLibrary.VpnClient.N2n.Transform;
using Xunit;

namespace TqkLibrary.VpnClient.Drivers.N2n.Tests
{
    /// <summary>
    /// Drives the whole n2n driver offline against an in-process supernode: the real <see cref="N2nConnection"/>
    /// registers the edge (REGISTER_SUPER → REGISTER_SUPER_ACK), brings up the L2 Ethernet data plane bridged to L3 via
    /// ARP + the VirtualHost, and round-trips IP packets both directions (ARP-resolving the gateway, then echoing). The
    /// supernode is a throwaway test harness (this is a client library).
    /// </summary>
    public class N2nConnectionTests
    {
        static readonly string Community = "labnet";
        static readonly IPAddress OverlayAddress = IPAddress.Parse("10.7.0.2");
        static readonly IPAddress Gateway = IPAddress.Parse("10.7.0.1");

        // A minimal IPv4 packet from the overlay address to the gateway with a recognisable tail for the echo assertion.
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

        static N2nConfig BuildConfig(N2nTransformKind transform = N2nTransformKind.Null, byte[]? aesKey = null,
            bool headerEncryption = false) => new N2nConfig
        {
            Community = Community,
            OverlayAddress = OverlayAddress,
            PrefixLength = 24,
            Transform = transform,
            AesKey = aesKey,
            HeaderEncryption = headerEncryption,
            Mtu = N2nDriverConstants.DefaultMtu,
        };

        // The host is an IP literal so DnsHostResolver parses it without a DNS lookup (the in-process loopback ignores
        // the resolved endpoint anyway — it self-pumps).
        static N2nConnection BuildConnection(LoopbackUdpLink link, N2nConfig config)
        {
            var factory = new InProcessN2nTransportFactory(link.Client);
            return new N2nConnection("127.0.0.1", 7654, config, factory,
                reconnectOptions: new N2nReconnectOptions { Enabled = false });
        }

        [Fact]
        public async Task Connect_RegistersWithSupernode_AndReachesConnectedState()
        {
            var link = new LoopbackUdpLink();
            using var supernode = new SimulatedN2nSupernode(link.Server, Community, Gateway);
            await using var connection = BuildConnection(link, BuildConfig());

            using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(10));
            await connection.ConnectAsync(cts.Token);

            Assert.Equal(VpnConnectionState.Connected, connection.State);
            Assert.True(supernode.RegisterSuperCount >= 1, "the supernode must have received a REGISTER_SUPER");
            Assert.Equal(OverlayAddress, connection.AssignedAddress);
            Assert.Equal(OverlayAddress, connection.Config.AssignedAddress);
        }

        [Fact]
        public async Task Connect_RoundTripsIp_OverL2Fabric_WithNullTransform()
        {
            var link = new LoopbackUdpLink();
            using var supernode = new SimulatedN2nSupernode(link.Server, Community, Gateway);
            await using var connection = BuildConnection(link, BuildConfig());

            var inbound = Channel.CreateUnbounded<byte[]>();
            connection.PacketChannel.InboundIpPacket += m => inbound.Writer.TryWrite(m.ToArray());

            using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(10));
            await connection.ConnectAsync(cts.Token);

            // Client → supernode (ARP-resolve the gateway, then echo) → client: an IP packet survives the L2 PACKET path both ways.
            byte[] packet = BuildIpv4Packet(OverlayAddress, Gateway, 0xAB);
            await connection.PacketChannel.WriteIpPacketAsync(packet, cts.Token);
            byte[] echoed = await inbound.Reader.ReadAsync(cts.Token);
            Assert.Equal(packet, echoed);
            Assert.True(supernode.PacketCount >= 2, "the supernode must have relayed the ARP request and the IP packet");
        }

        [Fact]
        public async Task Connect_RoundTripsIp_OverL2Fabric_WithAesTransform()
        {
            byte[] aesKey = new byte[32];
            for (int i = 0; i < aesKey.Length; i++) aesKey[i] = (byte)(i + 1);

            var link = new LoopbackUdpLink();
            using var supernode = new SimulatedN2nSupernode(link.Server, Community, Gateway, new N2nAesTransform(aesKey));
            await using var connection = BuildConnection(link, BuildConfig(N2nTransformKind.Aes, aesKey));

            var inbound = Channel.CreateUnbounded<byte[]>();
            connection.PacketChannel.InboundIpPacket += m => inbound.Writer.TryWrite(m.ToArray());

            using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(10));
            await connection.ConnectAsync(cts.Token);

            // The AES-CBC transform (random preamble + null IV) protects every PACKET payload both ways. n2n's AES zero-
            // pads the frame to an AES block boundary and does NOT strip the pad on decrypt (the IP total-length field
            // bounds the real packet), so the echoed bytes are the original packet possibly followed by zero padding.
            byte[] packet = BuildIpv4Packet(OverlayAddress, Gateway, 0xCD);
            await connection.PacketChannel.WriteIpPacketAsync(packet, cts.Token);
            byte[] echoed = await inbound.Reader.ReadAsync(cts.Token);
            Assert.True(echoed.Length >= packet.Length);
            Assert.Equal(packet, echoed.AsSpan(0, packet.Length).ToArray());     // the real packet is the unpadded prefix
            for (int i = packet.Length; i < echoed.Length; i++) Assert.Equal(0, echoed[i]);   // the rest is zero pad
        }

        [Fact]
        public async Task Connect_RegistersWithSupernode_WithHeaderEncryption()
        {
            var link = new LoopbackUdpLink();
            using var supernode = new SimulatedN2nSupernode(link.Server, Community, Gateway, headerEncryption: true);
            await using var connection = BuildConnection(link, BuildConfig(headerEncryption: true));

            using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(10));
            await connection.ConnectAsync(cts.Token);

            Assert.Equal(VpnConnectionState.Connected, connection.State);
            Assert.True(supernode.RegisterSuperCount >= 1, "the -H REGISTER_SUPER must decrypt + register on the supernode");
        }

        [Fact]
        public async Task Connect_RoundTripsIp_OverL2Fabric_WithHeaderEncryption()
        {
            var link = new LoopbackUdpLink();
            using var supernode = new SimulatedN2nSupernode(link.Server, Community, Gateway, headerEncryption: true);
            await using var connection = BuildConnection(link, BuildConfig(headerEncryption: true));

            var inbound = Channel.CreateUnbounded<byte[]>();
            connection.PacketChannel.InboundIpPacket += m => inbound.Writer.TryWrite(m.ToArray());

            using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(10));
            await connection.ConnectAsync(cts.Token);

            // The whole control path AND the data PACKET header are SPECK-encrypted (-H); the IP packet still round-trips.
            byte[] packet = BuildIpv4Packet(OverlayAddress, Gateway, 0xEF);
            await connection.PacketChannel.WriteIpPacketAsync(packet, cts.Token);
            byte[] echoed = await inbound.Reader.ReadAsync(cts.Token);
            Assert.Equal(packet, echoed);
            Assert.True(supernode.PacketCount >= 2, "the supernode must have decrypted + relayed the ARP request and the IP packet");
        }

        [Fact]
        public async Task Connect_TimesOut_WhenSupernodeNeverAcks()
        {
            var link = new LoopbackUdpLink();
            // No supernode wired on link.Server: REGISTER_SUPER goes unanswered.
            var factory = new InProcessN2nTransportFactory(link.Client);
            await using var connection = new N2nConnection("127.0.0.1", 7654, BuildConfig(), factory,
                reconnectOptions: new N2nReconnectOptions { Enabled = false },
                handshakeTimeout: TimeSpan.FromMilliseconds(300));

            using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(10));
            await Assert.ThrowsAsync<VpnConnectionException>(() => connection.ConnectAsync(cts.Token));
            // The initial connect threw before any success, so reconnect never arms — the state stays at Connecting
            // (matching the base ReconnectingVpnConnection contract: it only goes Disconnected via teardown or a final
            // reconnect failure).
            Assert.Equal(VpnConnectionState.Connecting, connection.State);
        }
    }
}
