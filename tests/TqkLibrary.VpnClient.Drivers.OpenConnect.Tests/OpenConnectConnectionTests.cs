using System;
using System.Net;
using System.Text;
using System.Threading;
using System.Threading.Channels;
using System.Threading.Tasks;
using TqkLibrary.VpnClient.Abstractions.Drivers;
using TqkLibrary.VpnClient.Abstractions.Drivers.Enums;
using TqkLibrary.VpnClient.Abstractions.Drivers.Interfaces;
using TqkLibrary.VpnClient.Abstractions.Drivers.Models;
using TqkLibrary.VpnClient.Drivers.OpenConnect.Enums;
using Xunit;

namespace TqkLibrary.VpnClient.Drivers.OpenConnect.Tests
{
    /// <summary>
    /// Drives the whole OpenConnect driver offline against an in-process ocserv responder: the real
    /// <see cref="OpenConnectConnection"/> runs the HTTPS config-auth handshake, promotes the stream with HTTP CONNECT,
    /// binds the CSTP-over-TLS data channel behind a stable <see cref="IPacketChannel"/>, and round-trips IP packets
    /// both directions; DPD (both probe and reply), peer-close teardown and the driver façade are exercised too. The
    /// responder is a throwaway test harness (this is a client library — there is no server product).
    /// </summary>
    public class OpenConnectConnectionTests
    {
        const string User = "alice";
        const string Pass = "s3cret";

        static (LoopbackByteStreamPair link, SimulatedOpenConnectServer server, CancellationTokenSource serverCts) StartServer(
            int dpdSeconds = 30, int keepaliveSeconds = 20)
        {
            var link = new LoopbackByteStreamPair();
            var server = new SimulatedOpenConnectServer(link.Server, User, Pass, dpdSeconds, keepaliveSeconds);
            var serverCts = new CancellationTokenSource();
            _ = Task.Run(() => server.RunAsync(serverCts.Token));
            return (link, server, serverCts);
        }

        [Fact]
        public async Task Connect_RunsAuthAndConnect_BindsPushedAddress_AndRoundTripsBothDirections()
        {
            var (link, server, serverCts) = StartServer();
            using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(30));

            var connection = new OpenConnectConnection("127.0.0.1", 443,
                new InProcessOpenConnectTransportFactory(link.Client), User, Pass);

            var inbound = Channel.CreateUnbounded<byte[]>();
            connection.PacketChannel.InboundIpPacket += m => inbound.Writer.TryWrite(m.ToArray());

            await connection.ConnectAsync(cts.Token);

            // In-band config from X-CSTP-* (config-push), bare IP — no PPP.
            Assert.Equal(OpenConnectConnectionState.Connected, connection.State);
            Assert.Equal(IPAddress.Parse("10.10.0.5"), connection.AssignedAddress);
            Assert.Equal(1400, connection.Config.Mtu);
            Assert.Equal(0, connection.PacketChannel.MaxHeaderLength);
            Assert.Equal(24, connection.Config.PrefixLength);                 // 255.255.255.0
            Assert.Contains(IPAddress.Parse("10.10.0.1"), connection.Config.DnsServers);
            Assert.Contains("10.10.0.0/16", connection.Config.Routes);

            // Client → server (echoed) → client: an IP packet survives the CSTP data channel both ways.
            byte[] packet = Encoding.ASCII.GetBytes("a tunnelled IP packet over the CSTP-over-TLS data channel");
            await connection.PacketChannel.WriteIpPacketAsync(packet, cts.Token);
            byte[] echoed = await inbound.Reader.ReadAsync(cts.Token);
            Assert.Equal(packet, echoed);
            Assert.Equal(1, server.DataPacketsReceived);

            // Server → client (unsolicited): proves the inbound CSTP demux + deliver path.
            byte[] sentinel = Encoding.ASCII.GetBytes("a packet the gateway originated");
            await server.SendDataAsync(sentinel, cts.Token);
            byte[] fromPeer = await inbound.Reader.ReadAsync(cts.Token);
            Assert.Equal(sentinel, fromPeer);

            await connection.DisposeAsync();
            serverCts.Cancel();
        }

        [Fact]
        public async Task Connect_WrongPassword_FailsAuth()
        {
            var (link, _, serverCts) = StartServer();
            using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(30));

            var connection = new OpenConnectConnection("127.0.0.1", 443,
                new InProcessOpenConnectTransportFactory(link.Client), User, "wrong-password",
                reconnectOptions: new OpenConnectReconnectOptions { Enabled = false });

            await Assert.ThrowsAsync<VpnAuthenticationException>(() => connection.ConnectAsync(cts.Token));
            await connection.DisposeAsync();
            serverCts.Cancel();
        }

        [Fact]
        public async Task Dpd_ServerProbe_IsAnsweredWithResponse()
        {
            var (link, server, serverCts) = StartServer();
            using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(30));

            var connection = new OpenConnectConnection("127.0.0.1", 443,
                new InProcessOpenConnectTransportFactory(link.Client), User, Pass);
            await connection.ConnectAsync(cts.Token);

            // The server sends a DPD-REQUEST; the client's CstpChannel must answer with a DPD-RESPONSE.
            await server.SendDpdRequestAsync(cts.Token);
            await WaitUntilAsync(() => server.DpdResponsesReceived > 0, cts.Token);
            Assert.True(server.DpdResponsesReceived > 0);

            await connection.DisposeAsync();
            serverCts.Cancel();
        }

        [Fact]
        public async Task Dpd_ClientProbe_FiresAfterSilence()
        {
            // Short DPD interval; a controllable clock pushes past it so the client's timer sends a DPD-REQUEST.
            var (link, server, serverCts) = StartServer(dpdSeconds: 2, keepaliveSeconds: 0);
            var clock = new MutableClock();
            using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(30));

            var connection = new OpenConnectConnection("127.0.0.1", 443,
                new InProcessOpenConnectTransportFactory(link.Client), User, Pass, clock: clock.Now);
            await connection.ConnectAsync(cts.Token);

            // Past the DPD interval of silence → the client's timer loop sends a DPD-REQUEST to the server. The server's
            // DPD-RESPONSE in turn keeps the client alive, so the tunnel must still be up.
            clock.Advance(3000);
            await WaitUntilAsync(() => server.DpdRequestsReceived > 0, cts.Token);
            Assert.True(server.DpdRequestsReceived > 0);
            Assert.Equal(OpenConnectConnectionState.Connected, connection.State);

            await connection.DisposeAsync();
            serverCts.Cancel();
        }

        [Fact]
        public async Task PeerDisconnect_TearsDownWhenReconnectDisabled()
        {
            var (link, server, serverCts) = StartServer();
            using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(30));

            var connection = new OpenConnectConnection("127.0.0.1", 443,
                new InProcessOpenConnectTransportFactory(link.Client), User, Pass,
                reconnectOptions: new OpenConnectReconnectOptions { Enabled = false });
            await connection.ConnectAsync(cts.Token);
            Assert.Equal(OpenConnectConnectionState.Connected, connection.State);

            await server.SendDisconnectAsync(cts.Token);
            await WaitUntilAsync(() => connection.State == OpenConnectConnectionState.Disconnected, cts.Token);
            Assert.Equal(OpenConnectConnectionState.Disconnected, connection.State);

            await connection.DisposeAsync();
            serverCts.Cancel();
        }

        [Fact]
        public async Task Driver_Connect_ExposesSessionAndCapabilities()
        {
            var (link, _, serverCts) = StartServer();
            using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(30));

            var driver = new OpenConnectDriver(transportFactory: new InProcessOpenConnectTransportFactory(link.Client));
            Assert.Equal("openconnect", driver.Name);
            Assert.Equal(VpnLinkLayer.L3Ip, driver.Capabilities.LinkLayer);
            Assert.Equal(VpnSecurityKind.Tls, driver.Capabilities.SecurityKinds);
            Assert.Equal(VpnTransportKind.Tls, driver.Capabilities.TransportKinds);
            Assert.Equal(AddressAssignment.ConfigPush, driver.Capabilities.AddressAssignment);
            Assert.False(driver.Capabilities.UsesPpp);

            IVpnConnection vpn = await driver.ConnectAsync(
                new VpnEndpoint("127.0.0.1", 443),
                new VpnCredentials { Username = User, Password = Pass }, cts.Token);

            IVpnSession session = Assert.Single(vpn.Sessions);
            Assert.Equal(IPAddress.Parse("10.10.0.5"), session.Config.AssignedAddress);

            var inbound = Channel.CreateUnbounded<byte[]>();
            session.PacketChannel.InboundIpPacket += m => inbound.Writer.TryWrite(m.ToArray());
            byte[] packet = Encoding.ASCII.GetBytes("through the IVpnConnection facade");
            await session.PacketChannel.WriteIpPacketAsync(packet, cts.Token);
            Assert.Equal(packet, await inbound.Reader.ReadAsync(cts.Token));

            await Assert.ThrowsAsync<NotSupportedException>(() => vpn.OpenSessionAsync(cts.Token));
            await vpn.DisposeAsync();
            serverCts.Cancel();
        }

        // ---- helpers ----

        static async Task WaitUntilAsync(Func<bool> condition, CancellationToken ct)
        {
            while (!condition())
            {
                ct.ThrowIfCancellationRequested();
                await Task.Delay(50, ct);
            }
        }

        /// <summary>A monotonic millisecond clock the test advances by hand (the timer still fires on real wall-clock).</summary>
        sealed class MutableClock
        {
            long _value;
            public long Now() => Interlocked.Read(ref _value);
            public void Advance(long ms) => Interlocked.Add(ref _value, ms);
        }
    }
}
