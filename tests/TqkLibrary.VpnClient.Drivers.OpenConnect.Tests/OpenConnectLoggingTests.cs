using System;
using System.Net;
using System.Text;
using System.Threading;
using System.Threading.Channels;
using System.Threading.Tasks;
using TqkLibrary.VpnClient.Abstractions.Diagnostics;
using TqkLibrary.VpnClient.Abstractions.Drivers;
using TqkLibrary.VpnClient.Drivers.Core.Enums;
using Xunit;

namespace TqkLibrary.VpnClient.Drivers.OpenConnect.Tests
{
    /// <summary>
    /// Q.2 diagnostics: a captured <see cref="Microsoft.Extensions.Logging.ILoggerFactory"/> threaded into the real
    /// <see cref="OpenConnectConnection"/> must receive the expected cross-cutting events (config-auth + CONNECT
    /// handshake progress and completion, state changes, and — on a bad password — a handshake-failed event) while the
    /// data plane still round-trips exactly as it does without a logger.
    /// </summary>
    public class OpenConnectLoggingTests
    {
        const string User = "alice";
        const string Pass = "s3cret";

        static (LoopbackByteStreamPair link, SimulatedOpenConnectServer server, CancellationTokenSource serverCts) StartServer()
        {
            var link = new LoopbackByteStreamPair();
            var server = new SimulatedOpenConnectServer(link.Server, User, Pass, 30, 20);
            var serverCts = new CancellationTokenSource();
            _ = Task.Run(() => server.RunAsync(serverCts.Token));
            return (link, server, serverCts);
        }

        [Fact]
        public async Task Connect_EmitsHandshakeAndStateEvents_AndStillRoundTrips()
        {
            var (link, server, serverCts) = StartServer();
            var logger = new CapturingLoggerFactory();
            using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(30));

            var connection = new OpenConnectConnection("127.0.0.1", 443,
                new InProcessOpenConnectTransportFactory(link.Client), User, Pass, loggerFactory: logger);

            var inbound = Channel.CreateUnbounded<byte[]>();
            connection.PacketChannel.InboundIpPacket += m => inbound.Writer.TryWrite(m.ToArray());

            await connection.ConnectAsync(cts.Token);

            Assert.True(logger.Captured(VpnEventIds.Handshake), "expected Handshake events (config-auth + CONNECT)");
            Assert.True(logger.Captured(VpnEventIds.HandshakeCompleted), "expected a HandshakeCompleted event");
            Assert.True(logger.Captured(VpnEventIds.StateChanged), "expected a StateChanged event");
            Assert.Contains(VpnConnectionState.Connected.ToString(),
                string.Join("|", logger.MessagesFor(VpnEventIds.StateChanged)));

            // ADDITIVE: behaviour is unchanged — the CSTP data plane still round-trips.
            byte[] packet = Encoding.ASCII.GetBytes("logged but unchanged");
            await connection.PacketChannel.WriteIpPacketAsync(packet, cts.Token);
            Assert.Equal(packet, await inbound.Reader.ReadAsync(cts.Token));

            await connection.DisposeAsync();
            serverCts.Cancel();
        }

        [Fact]
        public async Task WrongPassword_LogsHandshakeFailed()
        {
            var (link, _, serverCts) = StartServer();
            var logger = new CapturingLoggerFactory();
            using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(30));

            var connection = new OpenConnectConnection("127.0.0.1", 443,
                new InProcessOpenConnectTransportFactory(link.Client), User, "wrong-password",
                reconnectOptions: new OpenConnectReconnectOptions { Enabled = false }, loggerFactory: logger);

            await Assert.ThrowsAsync<VpnAuthenticationException>(() => connection.ConnectAsync(cts.Token));
            Assert.True(logger.Captured(VpnEventIds.HandshakeFailed), "expected a HandshakeFailed event on the rejected auth");

            await connection.DisposeAsync();
            serverCts.Cancel();
        }
    }
}
