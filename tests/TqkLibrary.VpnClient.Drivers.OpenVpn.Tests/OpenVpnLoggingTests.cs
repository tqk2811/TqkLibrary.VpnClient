using System;
using System.Net;
using System.Threading;
using System.Threading.Channels;
using System.Threading.Tasks;
using TqkLibrary.VpnClient.Abstractions.Diagnostics;
using TqkLibrary.VpnClient.Drivers.OpenVpn.Enums;
using TqkLibrary.VpnClient.OpenVpn;
using Xunit;

namespace TqkLibrary.VpnClient.Drivers.OpenVpn.Tests
{
    /// <summary>
    /// Q.2 diagnostics: a captured <see cref="Microsoft.Extensions.Logging.ILoggerFactory"/> threaded into the real
    /// <see cref="OpenVpnConnection"/> must receive the expected cross-cutting events (handshake progress + completion +
    /// state changes) while the connect/data path behaves exactly as it does without a logger (the no-op default).
    /// </summary>
    public class OpenVpnLoggingTests
    {
        sealed class SimulatedOpenVpnServer : SimulatedOpenVpnServerBase
        {
            public SimulatedOpenVpnServer(IOpenVpnTransport transport, System.Security.Cryptography.X509Certificates.X509Certificate2 certificate)
                : base(transport, certificate) { }
            protected override void OnData(byte[] plaintext) => SendData(plaintext);
        }

        [Fact]
        public async Task Connect_EmitsHandshakeAndStateEvents()
        {
            var link = new LoopbackLink();
            using var serverCert = OpenVpnTestPki.CreateSelfSignedServerCert();
            using var server = new SimulatedOpenVpnServer(link.Server, serverCert);

            using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(30));
            var logger = new CapturingLoggerFactory();
            var connection = new OpenVpnConnection("127.0.0.1", 1194, new InProcessTransportFactory(link.Client),
                optionsString: "V4,cipher AES-256-GCM",
                serverCertificateValidation: (_, _, _, _) => true,
                reliabilityOptions: new OpenVpnReliabilityOptions { Interval = TimeSpan.FromSeconds(30) },
                loggerFactory: logger);

            var inbound = Channel.CreateUnbounded<byte[]>();
            connection.PacketChannel.InboundIpPacket += m => inbound.Writer.TryWrite(m.ToArray());

            await connection.ConnectAsync(cts.Token);

            // The handshake/lifecycle events the connect path is expected to log, plus an unchanged data path.
            Assert.Equal(OpenVpnConnectionState.Connected, connection.State);
            Assert.Equal(IPAddress.Parse("10.8.0.2"), connection.AssignedAddress);
            Assert.True(logger.Captured(VpnEventIds.Handshake), "expected Handshake events (reset/key-method-2/PUSH)");
            Assert.True(logger.Captured(VpnEventIds.HandshakeCompleted), "expected a HandshakeCompleted event");
            Assert.True(logger.Captured(VpnEventIds.StateChanged), "expected a StateChanged event");
            Assert.Contains(OpenVpnConnectionState.Connected.ToString(),
                string.Join("|", logger.MessagesFor(VpnEventIds.StateChanged)));

            await connection.DisposeAsync();
        }
    }
}
