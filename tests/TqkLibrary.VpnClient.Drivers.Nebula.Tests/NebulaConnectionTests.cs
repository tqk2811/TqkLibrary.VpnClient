using System.Net;
using System.Text;
using System.Threading.Channels;
using TqkLibrary.VpnClient.Abstractions.Drivers;
using TqkLibrary.VpnClient.Drivers.Nebula.Config;
using TqkLibrary.VpnClient.Drivers.Core.Enums;
using TqkLibrary.VpnClient.Nebula.Certificate.Models;
using Xunit;

namespace TqkLibrary.VpnClient.Drivers.Nebula.Tests
{
    /// <summary>
    /// Drives the whole Nebula driver offline against an in-process responder: the real <see cref="NebulaConnection"/>
    /// runs the Noise IX handshake, verifies the responder certificate against the CA, binds the type-1 message data
    /// plane behind a stable packet channel, and round-trips IP packets both directions; the make-before-break
    /// re-handshake is exercised too. The responder is a throwaway test harness (this is a client library).
    /// </summary>
    public class NebulaConnectionTests
    {
        static (NebulaConfig config, SimulatedNebulaResponder responder) BuildPair(LoopbackUdpLink link)
        {
            var pki = new NebulaTestPki();
            (NebulaCertificate clientCert, byte[] clientPriv) = pki.SignHost("client", IPAddress.Parse("192.168.100.5"), 24);
            (NebulaCertificate serverCert, byte[] serverPriv) = pki.SignHost("lighthouse", IPAddress.Parse("192.168.100.1"), 24);

            var config = new NebulaConfig
            {
                CaCertificate = pki.CaCertificate,
                ClientCertificate = clientCert,
                ClientX25519PrivateKey = clientPriv,
                PeerEndpoint = new IPEndPoint(IPAddress.Loopback, 4242),
                Mtu = NebulaDriverConstants.DefaultMtu,
            };
            var responder = new SimulatedNebulaResponder(link.Server, serverCert, serverPriv);
            return (config, responder);
        }

        [Fact]
        public async Task Connect_RunsHandshake_VerifiesCert_RoundTripsBothDirections()
        {
            var link = new LoopbackUdpLink();
            var (config, responder) = BuildPair(link);
            using var _ = responder;

            using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(30));
            var connection = new NebulaConnection("127.0.0.1", 4242, config,
                new InProcessNebulaTransportFactory(link.Client));

            var inbound = Channel.CreateUnbounded<byte[]>();
            connection.PacketChannel.InboundIpPacket += m => inbound.Writer.TryWrite(m.ToArray());

            await connection.ConnectAsync(cts.Token);

            Assert.Equal(VpnConnectionState.Connected, connection.State);
            Assert.Equal(IPAddress.Parse("192.168.100.5"), connection.AssignedAddress); // overlay from the cert
            Assert.Equal(NebulaDriverConstants.DefaultMtu, connection.Config.Mtu);
            Assert.Equal(0, connection.PacketChannel.MaxHeaderLength); // Nebula carries bare IP

            // Client → responder (echoed) → client: an IP packet survives the type-1 message data plane both ways.
            byte[] packet = Encoding.ASCII.GetBytes("a tunnelled IP packet over the Nebula data plane");
            await connection.PacketChannel.WriteIpPacketAsync(packet, cts.Token);
            byte[] echoed = await inbound.Reader.ReadAsync(cts.Token);
            Assert.Equal(packet, echoed);

            // Responder → client (unsolicited): proves the inbound demux + deliver path.
            byte[] sentinel = Encoding.ASCII.GetBytes("a packet the peer originated");
            responder.SendToClient(sentinel);
            byte[] fromPeer = await inbound.Reader.ReadAsync(cts.Token);
            Assert.Equal(sentinel, fromPeer);

            await connection.DisposeAsync();
        }

        [Fact]
        public async Task Connect_UsesConnectHostPort_WhenNoStaticEndpoint()
        {
            var link = new LoopbackUdpLink();
            var pki = new NebulaTestPki();
            (NebulaCertificate clientCert, byte[] clientPriv) = pki.SignHost("client", IPAddress.Parse("192.168.100.7"), 24);
            (NebulaCertificate serverCert, byte[] serverPriv) = pki.SignHost("lighthouse", IPAddress.Parse("192.168.100.1"), 24);
            using var responder = new SimulatedNebulaResponder(link.Server, serverCert, serverPriv);

            var config = new NebulaConfig
            {
                CaCertificate = pki.CaCertificate,
                ClientCertificate = clientCert,
                ClientX25519PrivateKey = clientPriv,
                PeerEndpoint = null, // ⇒ resolve from the connect host:port
            };

            using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(30));
            var connection = new NebulaConnection("127.0.0.1", 4242, config,
                new InProcessNebulaTransportFactory(link.Client));
            await connection.ConnectAsync(cts.Token);
            Assert.Equal(VpnConnectionState.Connected, connection.State);
            await connection.DisposeAsync();
        }

        [Fact]
        public async Task Connect_WrongCa_RejectsResponderCert_HandshakeTimesOut()
        {
            // The responder is signed by a DIFFERENT CA than the client trusts ⇒ cert verification fails ⇒ the stage-2
            // is dropped ⇒ the handshake never completes ⇒ connect throws (no tunnel against an untrusted peer).
            var link = new LoopbackUdpLink();
            var clientPki = new NebulaTestPki();
            var roguePki = new NebulaTestPki();
            (NebulaCertificate clientCert, byte[] clientPriv) = clientPki.SignHost("client", IPAddress.Parse("192.168.100.5"), 24);
            (NebulaCertificate rogueCert, byte[] roguePriv) = roguePki.SignHost("rogue", IPAddress.Parse("192.168.100.1"), 24);
            using var responder = new SimulatedNebulaResponder(link.Server, rogueCert, roguePriv);

            var config = new NebulaConfig
            {
                CaCertificate = clientPki.CaCertificate, // trusts only clientPki's CA
                ClientCertificate = clientCert,
                ClientX25519PrivateKey = clientPriv,
                PeerEndpoint = new IPEndPoint(IPAddress.Loopback, 4242),
            };

            using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(10));
            var connection = new NebulaConnection("127.0.0.1", 4242, config,
                new InProcessNebulaTransportFactory(link.Client),
                reconnectOptions: new NebulaReconnectOptions { Enabled = false },
                handshakeTimeoutMs: 1500);
            await Assert.ThrowsAsync<VpnConnectionException>(() => connection.ConnectAsync(cts.Token));
            await connection.DisposeAsync();
        }

        [Fact]
        public async Task Rehandshake_SwapsSession_TunnelKeepsCarryingData()
        {
            // A short re-handshake interval forces a make-before-break rekey while the tunnel is up; data must still
            // round-trip after the channel is swapped to the new session.
            var link = new LoopbackUdpLink();
            var (config, responder) = BuildPair(link);
            using var _ = responder;

            using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(30));
            var connection = new NebulaConnection("127.0.0.1", 4242, config,
                new InProcessNebulaTransportFactory(link.Client),
                rehandshakeIntervalMs: 300);

            var inbound = Channel.CreateUnbounded<byte[]>();
            connection.PacketChannel.InboundIpPacket += m => inbound.Writer.TryWrite(m.ToArray());

            await connection.ConnectAsync(cts.Token);

            // Give the timer loop time to run at least one make-before-break re-handshake.
            await Task.Delay(900, cts.Token);

            byte[] packet = Encoding.ASCII.GetBytes("data after a re-handshake");
            await connection.PacketChannel.WriteIpPacketAsync(packet, cts.Token);
            byte[] echoed = await inbound.Reader.ReadAsync(cts.Token);
            Assert.Equal(packet, echoed);
            Assert.Equal(VpnConnectionState.Connected, connection.State);

            await connection.DisposeAsync();
        }
    }
}
