using System.Net;
using System.Threading.Channels;
using TqkLibrary.VpnClient.Abstractions.Drivers;
using TqkLibrary.VpnClient.Drivers.ZeroTier.Config;
using TqkLibrary.VpnClient.Drivers.ZeroTier.Enums;
using TqkLibrary.VpnClient.ZeroTier.Identity;
using TqkLibrary.VpnClient.ZeroTier.Identity.Models;
using TqkLibrary.VpnClient.ZeroTier.Vl2.Models;
using Xunit;

namespace TqkLibrary.VpnClient.Drivers.ZeroTier.Tests
{
    /// <summary>
    /// Drives the whole ZeroTier driver offline against an in-process node/controller: the real
    /// <see cref="ZeroTierConnection"/> runs the VL1 HELLO ⇄ OK handshake, joins the VL2 network
    /// (NETWORK_CONFIG_REQUEST → assigned IP + COM), brings up the L2 Ethernet data plane bridged to L3 via ARP + the
    /// VirtualHost, and round-trips IP packets both directions (ARP-resolving the gateway, then echoing). The
    /// node/controller is a throwaway test harness (this is a client library).
    /// <para>
    /// The identities are throwaway lab identities captured from real <c>zerotier-idtool</c> output (their addresses are
    /// already memory-hard-derived, so the test does not pay the 2 MB hashcash cost). The Curve25519 halves are the
    /// first 32 bytes of each key; X25519 is symmetric, so the client and the simulated node derive the same VL1 session
    /// key.
    /// </para>
    /// </summary>
    public class ZeroTierConnectionTests
    {
        // Real throwaway lab identities (addr:0:pub128hex[:priv128hex]) — same pair as the VL1 HELLO interop KAT.
        const string ClientSecret =
            "0ef6d8cebd:0:490d7a076365facb4bb070cca733d251055fbd089a5dc372b67c07295b84a108dbb9c861d301d92bbdda8ecf89dbd4a204b044946f8f1af5883106c4c66d6017" +
            ":1cf9b219d9693b2eed3d24a43e0033a5a5fa52c830efcac164ad0c592f27bbfdae6c19ffd91a37c600adec412dd1b5c145ab519c288a6ca5d046469f78b909d3";
        const string NodePublic =
            "7494911ed3:0:02df0fa2fca3ef4e618c063d325217d5484b4b3de85302c3731481098841525b08e3ff6b728ce7f4f73496489159680827d4f96bd2fcc048bff57d07fe320d28";

        static readonly NetworkId Network = NetworkId.Parse("7494911ed3000001"); // controller = the node's address
        static readonly IPAddress AssignedIp = IPAddress.Parse("10.144.0.2");
        static readonly IPAddress Gateway = IPAddress.Parse("10.144.0.1");

        static (ZeroTierIdentity client, ZeroTierIdentity node) Identities()
        {
            var codec = new ZeroTierIdentityCodec();
            return (codec.ParseString(ClientSecret), codec.ParseString(NodePublic));
        }

        static ZeroTierConfig BuildConfig(ZeroTierIdentity client, ZeroTierIdentity node, IPAddress? overlay = null) => new ZeroTierConfig
        {
            Identity = client,
            PeerIdentity = node,
            NetworkId = Network,
            OverlayAddress = overlay,                 // null => adopt the controller-assigned address
            PrefixLength = 24,
            NetworkConfigTimeout = TimeSpan.FromSeconds(5),
        };

        static ZeroTierConnection BuildConnection(LoopbackUdpLink link, ZeroTierConfig config)
        {
            var factory = new InProcessZeroTierTransportFactory(link.Client);
            return new ZeroTierConnection("127.0.0.1", 9993, config, factory,
                reconnectOptions: new ZeroTierReconnectOptions { Enabled = false },
                handshakeTimeout: TimeSpan.FromSeconds(5));
        }

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

        [Fact]
        public async Task Connect_RunsHelloHandshake_JoinsNetwork_AndAdoptsAssignedAddress()
        {
            var (client, node) = Identities();
            var link = new LoopbackUdpLink();
            using var sim = new SimulatedZeroTierNode(link.Server, node, client, Network, AssignedIp, Gateway);
            await using var connection = BuildConnection(link, BuildConfig(client, node));

            using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(20));
            await connection.ConnectAsync(cts.Token);

            Assert.Equal(ZeroTierConnectionState.Connected, connection.State);
            Assert.True(sim.HelloCount >= 1, "the node must have received a HELLO");
            Assert.True(sim.NetworkConfigRequestCount >= 1, "the controller must have received a NETWORK_CONFIG_REQUEST");
            Assert.Equal(AssignedIp, connection.AssignedAddress);                 // controller-assigned address adopted
            Assert.Equal(AssignedIp, connection.Config.AssignedAddress);
        }

        [Fact]
        public async Task Connect_WithPinnedOverlayAddress_StillReachesConnected()
        {
            var (client, node) = Identities();
            var pinned = IPAddress.Parse("10.144.0.9");
            var link = new LoopbackUdpLink();
            using var sim = new SimulatedZeroTierNode(link.Server, node, client, Network, AssignedIp, Gateway);
            await using var connection = BuildConnection(link, BuildConfig(client, node, overlay: pinned));

            using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(20));
            await connection.ConnectAsync(cts.Token);

            Assert.Equal(ZeroTierConnectionState.Connected, connection.State);
            Assert.Equal(pinned, connection.AssignedAddress);                     // the pinned address wins
        }

        [Fact]
        public async Task Connect_RoundTripsIp_OverL2Fabric()
        {
            var (client, node) = Identities();
            var link = new LoopbackUdpLink();
            using var sim = new SimulatedZeroTierNode(link.Server, node, client, Network, AssignedIp, Gateway);
            await using var connection = BuildConnection(link, BuildConfig(client, node));

            var inbound = Channel.CreateUnbounded<byte[]>();
            connection.PacketChannel.InboundIpPacket += m => inbound.Writer.TryWrite(m.ToArray());

            using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(20));
            await connection.ConnectAsync(cts.Token);

            // Client → node (ARP-resolve the gateway, then echo) → client: an IP packet survives the VL2 EXT_FRAME path both ways.
            byte[] packet = BuildIpv4Packet(connection.AssignedAddress, Gateway, 0xAB);
            await connection.PacketChannel.WriteIpPacketAsync(packet, cts.Token);
            byte[] echoed = await inbound.Reader.ReadAsync(cts.Token);
            Assert.Equal(packet, echoed);
            Assert.True(sim.ExtFrameCount >= 2, "the node must have relayed the ARP request and the IP packet as EXT_FRAMEs");
        }

        [Fact]
        public async Task Connect_TimesOut_WhenNodeNeverReplies()
        {
            var (client, node) = Identities();
            var link = new LoopbackUdpLink();
            // No node wired on link.Server: the HELLO goes unanswered.
            var factory = new InProcessZeroTierTransportFactory(link.Client);
            await using var connection = new ZeroTierConnection("127.0.0.1", 9993, BuildConfig(client, node), factory,
                reconnectOptions: new ZeroTierReconnectOptions { Enabled = false },
                handshakeTimeout: TimeSpan.FromMilliseconds(400));

            using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(20));
            await Assert.ThrowsAsync<VpnConnectionException>(() => connection.ConnectAsync(cts.Token));
            Assert.Equal(ZeroTierConnectionState.Connecting, connection.State);
        }
    }
}
