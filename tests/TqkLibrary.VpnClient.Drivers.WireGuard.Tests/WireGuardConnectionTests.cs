using System;
using System.Net;
using System.Text;
using System.Threading;
using System.Threading.Channels;
using System.Threading.Tasks;
using TqkLibrary.VpnClient.Abstractions.Drivers.Enums;
using TqkLibrary.VpnClient.Abstractions.Drivers.Interfaces;
using TqkLibrary.VpnClient.Abstractions.Drivers.Models;
using TqkLibrary.VpnClient.Drivers.Core.Enums;
using TqkLibrary.VpnClient.WireGuard;
using TqkLibrary.VpnClient.WireGuard.Config;
using TqkLibrary.VpnClient.WireGuard.Handshake.Models;
using Xunit;

namespace TqkLibrary.VpnClient.Drivers.WireGuard.Tests
{
    /// <summary>
    /// Drives the whole WireGuard driver offline against an in-process responder: the real <see cref="WireGuardConnection"/>
    /// runs the Noise_IKpsk2 handshake, binds the type-4 data channel behind a stable <see cref="IPacketChannel"/>, and
    /// round-trips IP packets both directions; rekey, keepalive and the cookie/mac2 path are exercised too. The
    /// responder is a throwaway test harness (this is a client library — there is no server product).
    /// </summary>
    public class WireGuardConnectionTests
    {
        static (WireGuardConfig config, WireGuardKeyPair clientStatic, WireGuardKeyPair serverStatic) BuildPair(
            byte[]? psk = null, int persistentKeepalive = 0)
        {
            WireGuardKeyPair clientStatic = WireGuardTestKeys.NewStatic();
            WireGuardKeyPair serverStatic = WireGuardTestKeys.NewStatic();
            var config = new WireGuardConfig
            {
                PrivateKey = clientStatic.PrivateKey,
                PeerPublicKey = serverStatic.PublicKey,
                PresharedKey = psk,
                Address = IPAddress.Parse("10.7.0.2"),
                PrefixLength = 32,
                PersistentKeepaliveSeconds = persistentKeepalive,
                Mtu = WireGuardConstants.DefaultMtu,
            };
            return (config, clientStatic, serverStatic);
        }

        [Fact]
        public async Task Connect_RunsHandshake_BindsStaticAddress_AndRoundTripsBothDirections()
        {
            var link = new LoopbackUdpLink();
            var (config, clientStatic, serverStatic) = BuildPair();
            using var responder = new SimulatedWireGuardResponder(link.Server, serverStatic, clientStatic.PublicKey);

            using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(30));
            var connection = new WireGuardConnection("127.0.0.1", 51820, config,
                new InProcessWireGuardTransportFactory(link.Client));

            var inbound = Channel.CreateUnbounded<byte[]>();
            connection.PacketChannel.InboundIpPacket += m => inbound.Writer.TryWrite(m.ToArray());

            await connection.ConnectAsync(cts.Token);

            // Static config (out-of-band address) — not negotiated.
            Assert.Equal(VpnConnectionState.Connected, connection.State);
            Assert.Equal(IPAddress.Parse("10.7.0.2"), connection.AssignedAddress);
            Assert.Equal(WireGuardConstants.DefaultMtu, connection.Config.Mtu);
            Assert.Equal(0, connection.PacketChannel.MaxHeaderLength); // WireGuard carries bare IP

            // Client → responder (echoed) → client: an IP packet survives the type-4 data channel both ways.
            byte[] packet = Encoding.ASCII.GetBytes("a tunnelled IP packet over the WireGuard data channel");
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
        public async Task Connect_WithPresharedKey_RoundTrips()
        {
            byte[] psk = new byte[32];
            for (int i = 0; i < psk.Length; i++) psk[i] = (byte)(0xA0 + i);

            var link = new LoopbackUdpLink();
            var (config, clientStatic, serverStatic) = BuildPair(psk);
            using var responder = new SimulatedWireGuardResponder(link.Server, serverStatic, clientStatic.PublicKey, psk);

            using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(30));
            var connection = new WireGuardConnection("127.0.0.1", 51820, config,
                new InProcessWireGuardTransportFactory(link.Client));

            var inbound = Channel.CreateUnbounded<byte[]>();
            connection.PacketChannel.InboundIpPacket += m => inbound.Writer.TryWrite(m.ToArray());

            await connection.ConnectAsync(cts.Token);

            byte[] packet = Encoding.ASCII.GetBytes("PSK-protected WireGuard payload");
            await connection.PacketChannel.WriteIpPacketAsync(packet, cts.Token);
            byte[] echoed = await inbound.Reader.ReadAsync(cts.Token);
            Assert.Equal(packet, echoed);

            await connection.DisposeAsync();
        }

        [Fact]
        public async Task Connect_WrongPeerKey_FailsHandshake()
        {
            var link = new LoopbackUdpLink();
            var (config, clientStatic, _) = BuildPair();
            WireGuardKeyPair otherServer = WireGuardTestKeys.NewStatic();
            // The responder uses a DIFFERENT static key than the one the client's config trusts → the response AEAD fails.
            using var responder = new SimulatedWireGuardResponder(link.Server, otherServer, clientStatic.PublicKey);

            // A short attempt window so the failed handshake gives up quickly; reconnect disabled so ConnectAsync throws.
            var connection = new WireGuardConnection("127.0.0.1", 51820, config,
                new InProcessWireGuardTransportFactory(link.Client),
                reconnectOptions: new WireGuardReconnectOptions { Enabled = false },
                timers: new WireGuardTimers(rekeyAttemptTimeSeconds: 1));

            using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(30));
            await Assert.ThrowsAsync<Abstractions.Drivers.VpnConnectionException>(() => connection.ConnectAsync(cts.Token));
            await connection.DisposeAsync();
        }

        [Fact]
        public async Task Connect_CookieReplyPath_ResendWithMac2_Completes()
        {
            var link = new LoopbackUdpLink();
            var (config, clientStatic, serverStatic) = BuildPair();
            // The responder answers the FIRST initiation with a cookie-reply; the client must resend with a valid mac2.
            using var responder = new SimulatedWireGuardResponder(link.Server, serverStatic, clientStatic.PublicKey,
                cookieOnFirstInitiation: true);

            using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(30));
            // A 1-second rekey-timeout so the resend (which now carries mac2) fires quickly within the attempt window.
            var connection = new WireGuardConnection("127.0.0.1", 51820, config,
                new InProcessWireGuardTransportFactory(link.Client),
                timers: new WireGuardTimers(rekeyTimeoutSeconds: 1, rekeyAttemptTimeSeconds: 30));

            var inbound = Channel.CreateUnbounded<byte[]>();
            connection.PacketChannel.InboundIpPacket += m => inbound.Writer.TryWrite(m.ToArray());

            await connection.ConnectAsync(cts.Token);
            Assert.Equal(VpnConnectionState.Connected, connection.State);

            byte[] packet = Encoding.ASCII.GetBytes("after the cookie-reply round-trip");
            await connection.PacketChannel.WriteIpPacketAsync(packet, cts.Token);
            byte[] echoed = await inbound.Reader.ReadAsync(cts.Token);
            Assert.Equal(packet, echoed);

            await connection.DisposeAsync();
        }

        [Fact]
        public async Task Rekey_MakeBeforeBreak_SwapsChannel_AndKeepsCarryingData()
        {
            var link = new LoopbackUdpLink();
            var (config, clientStatic, serverStatic) = BuildPair();
            using var responder = new SimulatedWireGuardResponder(link.Server, serverStatic, clientStatic.PublicKey);

            // A controllable clock: the timer fires on real time but reads this value, so advancing it crosses thresholds.
            var clock = new MutableClock();
            using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(30));
            var connection = new WireGuardConnection("127.0.0.1", 51820, config,
                new InProcessWireGuardTransportFactory(link.Client),
                // Rekey after 1s of session age; the test pushes the clock past it.
                timers: new WireGuardTimers(rekeyAfterTimeSeconds: 1, rekeyTimeoutSeconds: 1, rekeyAttemptTimeSeconds: 30),
                clock: clock.Now);

            var inbound = Channel.CreateUnbounded<byte[]>();
            connection.PacketChannel.InboundIpPacket += m => inbound.Writer.TryWrite(m.ToArray());

            await connection.ConnectAsync(cts.Token);
            Assert.Equal(0, responder.DataPacketsOpened); // no data yet, only handshake

            // Round-trip before the rekey.
            byte[] before = Encoding.ASCII.GetBytes("before rekey");
            await connection.PacketChannel.WriteIpPacketAsync(before, cts.Token);
            Assert.Equal(before, await inbound.Reader.ReadAsync(cts.Token));

            // Advance the clock past REKEY_AFTER_TIME; within a couple of real timer ticks the make-before-break rekey runs.
            clock.Advance(2000);

            // The channel is swapped to the new session's keys; data must still flow end-to-end after the swap.
            byte[] after = await PumpUntilEchoesAsync(connection, inbound, "after rekey", cts.Token);
            Assert.Equal(Encoding.ASCII.GetBytes("after rekey"), after);

            await connection.DisposeAsync();
        }

        [Fact]
        public async Task PersistentKeepalive_SendsEmptyTransportPackets()
        {
            var link = new LoopbackUdpLink();
            var (config, clientStatic, serverStatic) = BuildPair(persistentKeepalive: 1);
            using var responder = new SimulatedWireGuardResponder(link.Server, serverStatic, clientStatic.PublicKey);

            var clock = new MutableClock();
            using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(30));
            var connection = new WireGuardConnection("127.0.0.1", 51820, config,
                new InProcessWireGuardTransportFactory(link.Client),
                timers: new WireGuardTimers(persistentKeepaliveSeconds: 1),
                clock: clock.Now);

            await connection.ConnectAsync(cts.Token);
            int baseline = responder.DataPacketsOpened;

            // Past the persistent-keepalive interval of silence → the timer loop seals an empty type-4 keepalive.
            clock.Advance(1500);
            await WaitUntilAsync(() => responder.DataPacketsOpened > baseline, cts.Token);
            Assert.True(responder.DataPacketsOpened > baseline);

            await connection.DisposeAsync();
        }

        [Fact]
        public async Task Driver_Connect_ExposesSessionAndCapabilities()
        {
            var link = new LoopbackUdpLink();
            var (config, clientStatic, serverStatic) = BuildPair();
            using var responder = new SimulatedWireGuardResponder(link.Server, serverStatic, clientStatic.PublicKey);

            var driver = new WireGuardDriver(config, transportFactory: new InProcessWireGuardTransportFactory(link.Client));
            Assert.Equal("wireguard", driver.Name);
            Assert.Equal(VpnLinkLayer.L3Ip, driver.Capabilities.LinkLayer);
            Assert.Equal(VpnSecurityKind.Noise, driver.Capabilities.SecurityKinds);
            Assert.Equal(AddressAssignment.OutOfBand, driver.Capabilities.AddressAssignment);
            Assert.Equal(VpnTransportKind.Udp, driver.Capabilities.TransportKinds);

            using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(30));
            IVpnConnection vpn = await driver.ConnectAsync(new VpnEndpoint("127.0.0.1", 51820), new VpnCredentials(), cts.Token);

            IVpnSession session = Assert.Single(vpn.Sessions);
            Assert.Equal(IPAddress.Parse("10.7.0.2"), session.Config.AssignedAddress);

            var inbound = Channel.CreateUnbounded<byte[]>();
            session.PacketChannel.InboundIpPacket += m => inbound.Writer.TryWrite(m.ToArray());
            byte[] packet = Encoding.ASCII.GetBytes("through the IVpnConnection facade");
            await session.PacketChannel.WriteIpPacketAsync(packet, cts.Token);
            Assert.Equal(packet, await inbound.Reader.ReadAsync(cts.Token));

            await Assert.ThrowsAsync<NotSupportedException>(() => vpn.OpenSessionAsync(cts.Token));
            await vpn.DisposeAsync();
        }

        // ---- helpers ----

        static async Task<byte[]> PumpUntilEchoesAsync(WireGuardConnection connection, Channel<byte[]> inbound, string text, CancellationToken ct)
        {
            byte[] payload = Encoding.ASCII.GetBytes(text);
            // After a rekey the channel was swapped; retry the write a few times until an echo comes back over the new keys.
            for (int attempt = 0; attempt < 40; attempt++)
            {
                await connection.PacketChannel.WriteIpPacketAsync(payload, ct);
                using var perTry = CancellationTokenSource.CreateLinkedTokenSource(ct);
                perTry.CancelAfter(250);
                try { return await inbound.Reader.ReadAsync(perTry.Token); }
                catch (OperationCanceledException) when (!ct.IsCancellationRequested) { /* swap not finished yet — retry */ }
            }
            throw new TimeoutException("No echo after the rekey swap.");
        }

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
