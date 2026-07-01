using System;
using System.Net;
using System.Threading;
using System.Threading.Channels;
using System.Threading.Tasks;
using TqkLibrary.VpnClient.Abstractions.Diagnostics;
using TqkLibrary.VpnClient.Drivers.Core.Enums;
using TqkLibrary.VpnClient.SoftEther.Models;
using Xunit;

namespace TqkLibrary.VpnClient.Drivers.SoftEther.Tests
{
    /// <summary>
    /// Q.2 diagnostics: a captured <see cref="Microsoft.Extensions.Logging.ILoggerFactory"/> threaded into the real
    /// <see cref="SoftEtherConnection"/> must receive the expected cross-cutting events (control handshake + DHCP lease
    /// progress and completion, plus state changes) while the connect/data path behaves exactly as it does without a
    /// logger.
    /// </summary>
    public class SoftEtherLoggingTests
    {
        static SoftEtherLoginRequest Login() => new SoftEtherLoginRequest
        {
            HubName = "DEFAULT",
            UserName = "alice",
            Password = "P@ssw0rd",
            Session = new SoftEtherSessionParams { MaxConnection = 1 },
        };

        [Fact]
        public async Task Connect_EmitsHandshakeAndStateEvents()
        {
            var (client, server) = DuplexPipe.CreatePair();
            var sim = new SimulatedSoftEtherServer(server);
            using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(30));
            var serverTask = Task.Run(() => sim.RunAsync(cts.Token));

            var logger = new CapturingLoggerFactory();
            var connection = new SoftEtherConnection("vpn.example.com", 443, Login(),
                new InProcessSoftEtherTransportFactory(() => client),
                reconnectOptions: new SoftEtherReconnectOptions { Enabled = false }, loggerFactory: logger);

            var inbound = Channel.CreateUnbounded<byte[]>();
            connection.PacketChannel.InboundIpPacket += m => inbound.Writer.TryWrite(m.ToArray());

            await connection.ConnectAsync(cts.Token);

            // The handshake/DHCP/lifecycle events the connect path is expected to log.
            Assert.Equal(VpnConnectionState.Connected, connection.State);
            Assert.True(logger.Captured(VpnEventIds.Handshake), "expected Handshake events (control + DHCP)");
            Assert.True(logger.Captured(VpnEventIds.HandshakeCompleted), "expected a HandshakeCompleted event");
            Assert.True(logger.Captured(VpnEventIds.StateChanged), "expected a StateChanged event");
            Assert.Contains(VpnConnectionState.Connected.ToString(),
                string.Join("|", logger.MessagesFor(VpnEventIds.StateChanged)));

            await connection.DisposeAsync();
            cts.Cancel();
            try { await serverTask; } catch { }
        }
    }
}
