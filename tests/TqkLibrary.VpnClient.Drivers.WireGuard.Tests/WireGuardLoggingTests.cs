using System;
using System.Net;
using System.Text;
using System.Threading;
using System.Threading.Channels;
using System.Threading.Tasks;
using Microsoft.Extensions.Logging.Abstractions;
using TqkLibrary.VpnClient.Abstractions.Diagnostics;
using TqkLibrary.VpnClient.Abstractions.Diagnostics.Enums;
using TqkLibrary.VpnClient.Abstractions.Diagnostics.Extensions;
using TqkLibrary.VpnClient.Drivers.Core.Enums;
using TqkLibrary.VpnClient.WireGuard;
using TqkLibrary.VpnClient.WireGuard.Config;
using TqkLibrary.VpnClient.WireGuard.Handshake.Models;
using Xunit;

namespace TqkLibrary.VpnClient.Drivers.WireGuard.Tests
{
    /// <summary>
    /// Q.2 diagnostics: a captured <see cref="Microsoft.Extensions.Logging.ILoggerFactory"/> threaded into the real
    /// <see cref="WireGuardConnection"/> must receive the expected cross-cutting events (handshake progress + completion,
    /// state changes, and a dropped inbound packet) — and the data plane must still round-trip exactly as it does
    /// without a logger (the logging seam is additive, never changes behaviour). The default (no factory) is the
    /// allocation-free <see cref="NullLogger"/>.
    /// </summary>
    public class WireGuardLoggingTests
    {
        static (WireGuardConfig config, WireGuardKeyPair clientStatic, WireGuardKeyPair serverStatic) BuildPair()
        {
            WireGuardKeyPair clientStatic = WireGuardTestKeys.NewStatic();
            WireGuardKeyPair serverStatic = WireGuardTestKeys.NewStatic();
            var config = new WireGuardConfig
            {
                PrivateKey = clientStatic.PrivateKey,
                PeerPublicKey = serverStatic.PublicKey,
                Address = IPAddress.Parse("10.7.0.2"),
                PrefixLength = 32,
                Mtu = WireGuardConstants.DefaultMtu,
            };
            return (config, clientStatic, serverStatic);
        }

        [Fact]
        public async Task Connect_EmitsHandshakeAndStateEvents_AndStillRoundTrips()
        {
            var link = new LoopbackUdpLink();
            var (config, clientStatic, serverStatic) = BuildPair();
            using var responder = new SimulatedWireGuardResponder(link.Server, serverStatic, clientStatic.PublicKey);

            var logger = new CapturingLoggerFactory();
            using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(30));
            var connection = new WireGuardConnection("127.0.0.1", 51820, config,
                new InProcessWireGuardTransportFactory(link.Client), loggerFactory: logger);

            var inbound = Channel.CreateUnbounded<byte[]>();
            connection.PacketChannel.InboundIpPacket += m => inbound.Writer.TryWrite(m.ToArray());

            await connection.ConnectAsync(cts.Token);

            // The handshake/lifecycle events the connect path is expected to log.
            Assert.True(logger.Captured(VpnEventIds.Handshake), "expected at least one Handshake event");
            Assert.True(logger.Captured(VpnEventIds.HandshakeCompleted), "expected a HandshakeCompleted event");
            Assert.True(logger.Captured(VpnEventIds.StateChanged), "expected a StateChanged event");
            Assert.Contains(VpnConnectionState.Connected.ToString(),
                string.Join("|", logger.MessagesFor(VpnEventIds.StateChanged)));

            // ADDITIVE: behaviour is unchanged — the data plane still round-trips end-to-end.
            byte[] packet = Encoding.ASCII.GetBytes("logged but unchanged");
            await connection.PacketChannel.WriteIpPacketAsync(packet, cts.Token);
            Assert.Equal(packet, await inbound.Reader.ReadAsync(cts.Token));

            await connection.DisposeAsync();
        }

        [Fact]
        public async Task ForeignInboundDatagram_IsLoggedAsDrop()
        {
            var link = new LoopbackUdpLink();
            var (config, clientStatic, serverStatic) = BuildPair();
            using var responder = new SimulatedWireGuardResponder(link.Server, serverStatic, clientStatic.PublicKey);

            var logger = new CapturingLoggerFactory();
            using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(30));
            var connection = new WireGuardConnection("127.0.0.1", 51820, config,
                new InProcessWireGuardTransportFactory(link.Client), loggerFactory: logger);
            await connection.ConnectAsync(cts.Token);

            // Inject a malformed type-2 response straight into the client's demux: it has no matching pending handshake
            // (the live handshake already completed) → the driver must record a PacketDropped event.
            byte[] bogusResponse = new byte[92];
            bogusResponse[0] = WireGuardConstants.MessageTypeResponse;
            await link.Server.SendAsync(bogusResponse, cts.Token);

            await WaitUntilAsync(() => logger.Captured(VpnEventIds.PacketDropped), cts.Token);
            Assert.True(logger.Captured(VpnEventIds.PacketDropped));

            await connection.DisposeAsync();
        }

        [Fact]
        public async Task WrongPeerKey_LogsHandshakeFailed()
        {
            var link = new LoopbackUdpLink();
            var (config, clientStatic, _) = BuildPair();
            WireGuardKeyPair otherServer = WireGuardTestKeys.NewStatic();
            using var responder = new SimulatedWireGuardResponder(link.Server, otherServer, clientStatic.PublicKey);

            var logger = new CapturingLoggerFactory();
            var connection = new WireGuardConnection("127.0.0.1", 51820, config,
                new InProcessWireGuardTransportFactory(link.Client),
                reconnectOptions: new WireGuardReconnectOptions { Enabled = false },
                timers: new WireGuardTimers(rekeyAttemptTimeSeconds: 1),
                loggerFactory: logger);

            using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(30));
            await Assert.ThrowsAsync<Abstractions.Drivers.VpnConnectionException>(() => connection.ConnectAsync(cts.Token));

            // A genuine AEAD-mismatch response is dropped (AuthFailed/DecryptFailed); the timeout logs HandshakeFailed.
            Assert.True(logger.Captured(VpnEventIds.HandshakeFailed), "expected a HandshakeFailed event on the timed-out handshake");
            await connection.DisposeAsync();
        }

        [Fact]
        public void NullLoggerExtensions_AreNoOpAndSafe()
        {
            // The default path (no ILoggerFactory) uses NullLogger; the extension helpers must be safe no-ops on it.
            var logger = NullLogger.Instance;
            logger.LogStateChanged("wireguard", "Connected");
            logger.LogHandshake("wireguard", "step");
            logger.LogHandshakeCompleted("wireguard");
            logger.LogHandshakeFailed("wireguard", "reason");
            logger.LogRekey("wireguard", "phase");
            logger.LogKeepalive("wireguard", "kind");
            logger.LogLinkLost("wireguard", "reason");
            logger.LogReconnectAttempt("wireguard", 1);
            logger.LogReconnected("wireguard");
            logger.LogPacketDropped("wireguard", VpnDropReason.DecryptFailed, "detail");
        }

        static async Task WaitUntilAsync(Func<bool> condition, CancellationToken ct)
        {
            while (!condition())
            {
                ct.ThrowIfCancellationRequested();
                await Task.Delay(20, ct);
            }
        }
    }
}
