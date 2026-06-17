using System.Net;
using System.Security.Cryptography.X509Certificates;
using System.Threading;
using System.Threading.Tasks;
using TqkLibrary.VpnClient.OpenVpn;
using TqkLibrary.VpnClient.OpenVpn.DataChannel;
using Xunit;

namespace TqkLibrary.VpnClient.Drivers.OpenVpn.Tests
{
    /// <summary>
    /// Offline coverage for the V.2 OCC tasks: explicit-exit-notify on teardown (the server catches the
    /// <c>EXIT_NOTIFY</c> control message) and NCP-less cipher selection — the client falls back to its configured
    /// <c>cipher</c> when the server pushes none, or mines the server's echoed <c>IV_CIPHERS</c> list. Drives the real
    /// <see cref="OpenVpnConnection"/> against the in-process responder; the responder is throwaway test scaffolding.
    /// </summary>
    public class OpenVpnOccAndFallbackTests
    {
        [Fact]
        public async Task DisconnectAsync_SendsExplicitExitNotify()
        {
            var link = new LoopbackLink();
            using var serverCert = OpenVpnTestPki.CreateSelfSignedServerCert();
            using var server = new ExitNotifyServer(link.Server, serverCert);

            using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(30));
            var connection = new OpenVpnConnection("127.0.0.1", 1194, new InProcessTransportFactory(link.Client),
                optionsString: "V4,cipher AES-256-GCM",
                serverCertificateValidation: (_, _, _, _) => true,
                reliabilityOptions: new OpenVpnReliabilityOptions { Interval = TimeSpan.FromSeconds(30) });

            await connection.ConnectAsync(cts.Token);

            // Teardown sends EXIT_NOTIFY over the control channel before disposing the transport.
            await connection.DisconnectAsync(cts.Token);

            string received = await server.ExitNotifyReceived.WaitAsync(TimeSpan.FromSeconds(10), cts.Token);
            Assert.Equal("EXIT_NOTIFY", received);

            await connection.DisposeAsync();
        }

        [Fact]
        public async Task NcpLessServer_FallsBackToConfiguredCipher_RoundTripsIp()
        {
            var link = new LoopbackLink();
            using var serverCert = OpenVpnTestPki.CreateSelfSignedServerCert();
            // The server pushes NO cipher and echoes NO IV_CIPHERS — a pure NCP-less server pinned to AES-128-GCM.
            using var server = new NoNcpServer(link.Server, serverCert);

            using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(30));
            var connection = new OpenVpnConnection("127.0.0.1", 1194, new InProcessTransportFactory(link.Client),
                optionsString: "V4,cipher AES-128-GCM",
                serverCertificateValidation: (_, _, _, _) => true,
                fallbackCipher: "AES-128-GCM", // the profile's `cipher` directive — used because the server doesn't speak NCP
                reliabilityOptions: new OpenVpnReliabilityOptions { Interval = TimeSpan.FromSeconds(30) });

            var inbound = System.Threading.Channels.Channel.CreateUnbounded<byte[]>();
            connection.PacketChannel.InboundIpPacket += m => inbound.Writer.TryWrite(m.ToArray());

            await connection.ConnectAsync(cts.Token);
            Assert.Equal(IPAddress.Parse("10.8.0.2"), connection.AssignedAddress);

            // Client and server must agree on AES-128-GCM via the fallback or the GCM tag fails on round-trip.
            byte[] packet = System.Text.Encoding.ASCII.GetBytes("packet over the NCP-less fallback cipher");
            await connection.PacketChannel.WriteIpPacketAsync(packet, cts.Token);
            byte[] echoed = await inbound.Reader.ReadAsync(cts.Token);
            Assert.Equal(packet, echoed);

            await connection.DisposeAsync();
        }

        [Fact]
        public async Task NcpLessServer_PicksFromServerPushedIvCiphers_RoundTripsIp()
        {
            var link = new LoopbackLink();
            using var serverCert = OpenVpnTestPki.CreateSelfSignedServerCert();
            // The server pushes no `cipher` in PUSH_REPLY but echoes IV_CIPHERS in its key-method-2 reply options.
            using var server = new IvCiphersEchoServer(link.Server, serverCert);

            using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(30));
            var connection = new OpenVpnConnection("127.0.0.1", 1194, new InProcessTransportFactory(link.Client),
                optionsString: "V4,cipher AES-256-GCM",
                serverCertificateValidation: (_, _, _, _) => true,
                // No fallback configured: the client must mine the server's IV_CIPHERS to find AES-128-GCM.
                reliabilityOptions: new OpenVpnReliabilityOptions { Interval = TimeSpan.FromSeconds(30) });

            var inbound = System.Threading.Channels.Channel.CreateUnbounded<byte[]>();
            connection.PacketChannel.InboundIpPacket += m => inbound.Writer.TryWrite(m.ToArray());

            await connection.ConnectAsync(cts.Token);

            byte[] packet = System.Text.Encoding.ASCII.GetBytes("packet over the server-echoed IV_CIPHERS cipher");
            await connection.PacketChannel.WriteIpPacketAsync(packet, cts.Token);
            byte[] echoed = await inbound.Reader.ReadAsync(cts.Token);
            Assert.Equal(packet, echoed);

            await connection.DisposeAsync();
        }

        /// <summary>tun responder that echoes data — used to observe the EXIT_NOTIFY teardown message.</summary>
        sealed class ExitNotifyServer : SimulatedOpenVpnServerBase
        {
            public ExitNotifyServer(IOpenVpnTransport transport, X509Certificate2 certificate) : base(transport, certificate) { }
            protected override void OnData(byte[] plaintext) => SendData(plaintext);
        }

        /// <summary>NCP-less responder pinned to AES-128-GCM: PUSH_REPLY carries no cipher, options echo no IV_CIPHERS.</summary>
        sealed class NoNcpServer : SimulatedOpenVpnServerBase
        {
            public NoNcpServer(IOpenVpnTransport transport, X509Certificate2 certificate) : base(transport, certificate) { }
            protected override OpenVpnDataCipher DataCipher => OpenVpnDataCipher.Aes128Gcm;
            protected override string PushReply => $"PUSH_REPLY,ifconfig 10.8.0.2 255.255.255.0,topology subnet,peer-id {PeerId}";
            protected override string ServerKeyMethodOptions => "V4,dev-type tun"; // no IV_CIPHERS line
            protected override void OnData(byte[] plaintext) => SendData(plaintext);
        }

        /// <summary>NCP-less responder that echoes IV_CIPHERS in its key-method-2 options; the data cipher is AES-128-GCM.</summary>
        sealed class IvCiphersEchoServer : SimulatedOpenVpnServerBase
        {
            public IvCiphersEchoServer(IOpenVpnTransport transport, X509Certificate2 certificate) : base(transport, certificate) { }
            protected override OpenVpnDataCipher DataCipher => OpenVpnDataCipher.Aes128Gcm;
            protected override string PushReply => $"PUSH_REPLY,ifconfig 10.8.0.2 255.255.255.0,topology subnet,peer-id {PeerId}";
            protected override string ServerKeyMethodOptions => "V4,dev-type tun\nIV_CIPHERS=AES-128-GCM:CHACHA20-POLY1305";
            protected override void OnData(byte[] plaintext) => SendData(plaintext);
        }
    }
}
