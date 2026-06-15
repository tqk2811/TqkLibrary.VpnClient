using System.Collections.Generic;
using System.Net;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Threading;
using System.Threading.Channels;
using System.Threading.Tasks;
using TqkLibrary.VpnClient.OpenVpn;
using TqkLibrary.VpnClient.OpenVpn.DataChannel;
using Xunit;

namespace TqkLibrary.VpnClient.Drivers.OpenVpn.Tests
{
    /// <summary>
    /// Drives the whole OpenVPN driver offline against an in-process responder: the real <see cref="OpenVpnConnection"/>
    /// runs reset → TLS → key-method-2 → PUSH_REQUEST, the server pushes a tunnel address + peer-id + cipher, and the
    /// negotiated AEAD data channel then round-trips an IP packet through the tun channel — proving the opcode demux
    /// (control vs P_DATA on one transport) and the data-plane wiring. A keepalive ping the server sends is dropped, not
    /// delivered to the IP layer. The responder is a throwaway test harness (this is a client library — no server product).
    /// </summary>
    public class OpenVpnConnectionHandshakeTests
    {
        [Fact]
        public async Task Connect_RunsFullHandshake_BindsTunAddress_RoundTrips_AndDropsPing()
        {
            var link = new LoopbackLink();
            using var serverCert = OpenVpnTestPki.CreateSelfSignedServerCert();
            using var server = new SimulatedOpenVpnServer(link.Server, serverCert);

            using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(30));
            // host "127.0.0.1" resolves verbatim (no DNS); the in-process factory ignores the address and returns the loopback.
            var connection = new OpenVpnConnection("127.0.0.1", 1194, new InProcessTransportFactory(link.Client),
                optionsString: "V4,cipher AES-256-GCM",
                serverCertificateValidation: (_, _, _, _) => true,
                // A long retransmit interval so the lossless in-memory path never fires a spurious resend mid-handshake.
                reliabilityOptions: new OpenVpnReliabilityOptions { Interval = TimeSpan.FromSeconds(30) });

            var inbound = Channel.CreateUnbounded<byte[]>();
            connection.PacketChannel.InboundIpPacket += m => inbound.Writer.TryWrite(m.ToArray());

            await connection.ConnectAsync(cts.Token);

            // PUSH_REPLY bound the tunnel address (ifconfig) + /24 (topology subnet).
            Assert.Equal(IPAddress.Parse("10.8.0.2"), connection.AssignedAddress);
            Assert.Equal(24, connection.Config.PrefixLength);

            // Client → server (echoed) → client: a real IP packet survives the AEAD data channel + opcode demux.
            byte[] packet = Encoding.ASCII.GetBytes("a tunnelled IP packet over the OpenVPN data channel");
            await connection.PacketChannel.WriteIpPacketAsync(packet, cts.Token);
            byte[] echoed = await inbound.Reader.ReadAsync(cts.Token);
            Assert.Equal(packet, echoed);

            // The server emits a keepalive ping then a normal packet; the ping must be dropped, only the packet delivered.
            server.SendDataToClient(OpenVpnPing.Magic.ToArray());
            byte[] sentinel = Encoding.ASCII.GetBytes("the packet after the ping");
            server.SendDataToClient(sentinel);
            byte[] afterPing = await inbound.Reader.ReadAsync(cts.Token);
            Assert.Equal(sentinel, afterPing); // the ping never surfaced, so the next readable packet is the sentinel

            await connection.DisposeAsync();
        }

        [Fact]
        public async Task Connect_NcpSelectsChaCha20Poly1305_RoundTripsIp()
        {
            var link = new LoopbackLink();
            using var serverCert = OpenVpnTestPki.CreateSelfSignedServerCert();
            using var server = new ChaChaSimulatedOpenVpnServer(link.Server, serverCert);

            using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(30));
            var connection = new OpenVpnConnection("127.0.0.1", 1194, new InProcessTransportFactory(link.Client),
                optionsString: "V4,cipher AES-256-GCM",
                serverCertificateValidation: (_, _, _, _) => true,
                reliabilityOptions: new OpenVpnReliabilityOptions { Interval = TimeSpan.FromSeconds(30) });

            var inbound = Channel.CreateUnbounded<byte[]>();
            connection.PacketChannel.InboundIpPacket += m => inbound.Writer.TryWrite(m.ToArray());

            await connection.ConnectAsync(cts.Token);
            Assert.Equal(IPAddress.Parse("10.8.0.2"), connection.AssignedAddress);

            // The server picked CHACHA20-POLY1305 in PUSH_REPLY; the client must drive its data channel with ChaCha or the tag fails.
            byte[] packet = Encoding.ASCII.GetBytes("a tunnelled IP packet over ChaCha20-Poly1305");
            await connection.PacketChannel.WriteIpPacketAsync(packet, cts.Token);
            byte[] echoed = await inbound.Reader.ReadAsync(cts.Token);
            Assert.Equal(packet, echoed);

            await connection.DisposeAsync();
        }

        [Fact]
        public async Task Connect_AdvertisesAdvancedPeerInfo_MtuAndUserVars()
        {
            var link = new LoopbackLink();
            using var serverCert = OpenVpnTestPki.CreateSelfSignedServerCert();
            using var server = new SimulatedOpenVpnServer(link.Server, serverCert);

            using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(30));
            var connection = new OpenVpnConnection("127.0.0.1", 1194, new InProcessTransportFactory(link.Client),
                optionsString: "V4,cipher AES-256-GCM",
                serverCertificateValidation: (_, _, _, _) => true,
                tunMtu: 1380,
                // No IV_MTU set here, so the connection fills it from the tun MTU; a user variable rides along.
                peerInfoOptions: new OpenVpnPeerInfoOptions { Extra = new[] { new KeyValuePair<string, string>("UV_ID", "client-7") } },
                reliabilityOptions: new OpenVpnReliabilityOptions { Interval = TimeSpan.FromSeconds(30) });

            await connection.ConnectAsync(cts.Token);

            Assert.NotNull(server.ReceivedPeerInfo);
            Assert.Contains("IV_CIPHERS=AES-256-GCM:AES-128-GCM:CHACHA20-POLY1305", server.ReceivedPeerInfo!);
            Assert.Contains("IV_MTU=1380", server.ReceivedPeerInfo!); // the tun MTU filled IV_MTU
            Assert.Contains("UV_ID=client-7", server.ReceivedPeerInfo!);
            Assert.Contains("IV_PLAT=", server.ReceivedPeerInfo!);

            await connection.DisposeAsync();
        }

        /// <summary>tun responder: every decrypted P_DATA payload is a bare IP packet, echoed straight back.</summary>
        sealed class SimulatedOpenVpnServer : SimulatedOpenVpnServerBase
        {
            public SimulatedOpenVpnServer(IOpenVpnTransport transport, X509Certificate2 certificate) : base(transport, certificate) { }
            protected override void OnData(byte[] plaintext) => SendData(plaintext);
        }

        /// <summary>tun responder that "selects" CHACHA20-POLY1305 via NCP (peer-info → PUSH cipher), echoing IP packets.</summary>
        sealed class ChaChaSimulatedOpenVpnServer : SimulatedOpenVpnServerBase
        {
            public ChaChaSimulatedOpenVpnServer(IOpenVpnTransport transport, X509Certificate2 certificate) : base(transport, certificate) { }
            protected override OpenVpnDataCipher DataCipher => OpenVpnDataCipher.ChaCha20Poly1305;
            protected override void OnData(byte[] plaintext) => SendData(plaintext);
        }
    }
}
