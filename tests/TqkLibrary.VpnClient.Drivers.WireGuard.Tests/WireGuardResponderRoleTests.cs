using System;
using System.Net;
using System.Text;
using System.Threading;
using System.Threading.Channels;
using System.Threading.Tasks;
using TqkLibrary.VpnClient.Drivers.WireGuard.Enums;
using TqkLibrary.VpnClient.WireGuard;
using TqkLibrary.VpnClient.WireGuard.Config;
using TqkLibrary.VpnClient.WireGuard.Handshake.Models;
using Xunit;

namespace TqkLibrary.VpnClient.Drivers.WireGuard.Tests
{
    /// <summary>
    /// Proves the <b>responder role</b> (peer-to-peer / <c>acceptInbound</c>): two real <see cref="WireGuardConnection"/>
    /// instances — no server, no test responder — hand-shake <i>each other</i> over an in-process UDP loopback. Each is
    /// configured with the other as its single peer and brought up with <c>acceptInbound: true</c>, so whichever side's
    /// initiation reaches the other first is answered with a type-2 response and both tunnels come up. Then a bare IP
    /// packet round-trips both directions through the type-4 data plane, end-to-end between the two .NET nodes. This is
    /// the data-plane proof behind Tailscale full-tunnel: ts2021 control feeds each node the other's WireGuard pubkey +
    /// endpoint, and the WireGuard responder role lets the two complete the handshake without a server.
    /// </summary>
    public class WireGuardResponderRoleTests
    {
        [Fact]
        public async Task TwoDotNetNodes_HandshakeEachOther_AndRoundTripBothDirections()
        {
            // Two independent static identities; each node trusts the other as its single full-tunnel peer.
            WireGuardKeyPair nodeA = WireGuardTestKeys.NewStatic();
            WireGuardKeyPair nodeB = WireGuardTestKeys.NewStatic();

            var configA = new WireGuardConfig
            {
                PrivateKey = nodeA.PrivateKey,
                PeerPublicKey = nodeB.PublicKey,
                Address = IPAddress.Parse("100.64.0.1"),
                PrefixLength = 32,
                Mtu = WireGuardConstants.DefaultMtu,
            };
            var configB = new WireGuardConfig
            {
                PrivateKey = nodeB.PrivateKey,
                PeerPublicKey = nodeA.PublicKey,
                Address = IPAddress.Parse("100.64.0.2"),
                PrefixLength = 32,
                Mtu = WireGuardConstants.DefaultMtu,
            };

            // One bidirectional loopback wires node A's socket to node B's socket and vice versa.
            var link = new LoopbackUdpLink();
            using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(30));

            var connA = new WireGuardConnection("127.0.0.1", 51820, configA,
                new InProcessWireGuardTransportFactory(link.Client), acceptInbound: true);
            var connB = new WireGuardConnection("127.0.0.1", 51820, configB,
                new InProcessWireGuardTransportFactory(link.Server), acceptInbound: true);

            var inboundA = Channel.CreateUnbounded<byte[]>();
            var inboundB = Channel.CreateUnbounded<byte[]>();
            connA.PacketChannel.InboundIpPacket += m => inboundA.Writer.TryWrite(m.ToArray());
            connB.PacketChannel.InboundIpPacket += m => inboundB.Writer.TryWrite(m.ToArray());

            // Both connect concurrently: each sends an initiation; whoever's reaches the other first is answered.
            await Task.WhenAll(connA.ConnectAsync(cts.Token), connB.ConnectAsync(cts.Token));

            Assert.Equal(WireGuardConnectionState.Connected, connA.State);
            Assert.Equal(WireGuardConnectionState.Connected, connB.State);

            // A → B: a bare IP packet survives the type-4 data plane and is delivered at B.
            byte[] aToB = Encoding.ASCII.GetBytes("packet from node A to node B over the responder-role tunnel");
            await connA.PacketChannel.WriteIpPacketAsync(aToB, cts.Token);
            Assert.Equal(aToB, await inboundB.Reader.ReadAsync(cts.Token));

            // B → A: the reverse direction works too (both halves of the crossed transport keys are correct).
            byte[] bToA = Encoding.ASCII.GetBytes("reply from node B back to node A");
            await connB.PacketChannel.WriteIpPacketAsync(bToA, cts.Token);
            Assert.Equal(bToA, await inboundA.Reader.ReadAsync(cts.Token));

            await connA.DisposeAsync();
            await connB.DisposeAsync();
        }

        [Fact]
        public async Task Responder_AnswersInbound_WhenItNeverInitiatesFirst()
        {
            // The same two-node setup, but we prove the *responder* half in isolation: node R answers an inbound type-1
            // from node I. Both run acceptInbound; convergence is the same as above, and data flows both ways.
            WireGuardKeyPair nodeI = WireGuardTestKeys.NewStatic();
            WireGuardKeyPair nodeR = WireGuardTestKeys.NewStatic();

            var configI = new WireGuardConfig
            {
                PrivateKey = nodeI.PrivateKey,
                PeerPublicKey = nodeR.PublicKey,
                Address = IPAddress.Parse("100.64.0.10"),
                PrefixLength = 32,
                Mtu = WireGuardConstants.DefaultMtu,
            };
            var configR = new WireGuardConfig
            {
                PrivateKey = nodeR.PrivateKey,
                PeerPublicKey = nodeI.PublicKey,
                Address = IPAddress.Parse("100.64.0.11"),
                PrefixLength = 32,
                Mtu = WireGuardConstants.DefaultMtu,
            };

            var link = new LoopbackUdpLink();
            using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(30));

            var connI = new WireGuardConnection("127.0.0.1", 51820, configI,
                new InProcessWireGuardTransportFactory(link.Client), acceptInbound: true);
            var connR = new WireGuardConnection("127.0.0.1", 51820, configR,
                new InProcessWireGuardTransportFactory(link.Server), acceptInbound: true);

            var inboundR = Channel.CreateUnbounded<byte[]>();
            connR.PacketChannel.InboundIpPacket += m => inboundR.Writer.TryWrite(m.ToArray());

            await Task.WhenAll(connI.ConnectAsync(cts.Token), connR.ConnectAsync(cts.Token));
            Assert.Equal(WireGuardConnectionState.Connected, connR.State);

            byte[] packet = Encoding.ASCII.GetBytes("initiator->responder data after the responder answered type-1");
            await connI.PacketChannel.WriteIpPacketAsync(packet, cts.Token);
            Assert.Equal(packet, await inboundR.Reader.ReadAsync(cts.Token));

            await connI.DisposeAsync();
            await connR.DisposeAsync();
        }

        [Fact]
        public async Task InitiatorOnly_ByDefault_DoesNotAnswerInbound()
        {
            // Without acceptInbound, a connection never answers an inbound type-1 (the proven initiator-only client). Two
            // default connections each only initiate and neither answers, so the handshake cannot complete: the attempt
            // times out. (This is the behaviour we must NOT regress; the responder role is strictly opt-in.)
            WireGuardKeyPair nodeA = WireGuardTestKeys.NewStatic();
            WireGuardKeyPair nodeB = WireGuardTestKeys.NewStatic();

            var configA = new WireGuardConfig
            {
                PrivateKey = nodeA.PrivateKey,
                PeerPublicKey = nodeB.PublicKey,
                Address = IPAddress.Parse("100.64.0.20"),
                PrefixLength = 32,
            };

            var link = new LoopbackUdpLink();
            // The "peer" is a second default (initiator-only) connection that also never answers.
            var configB = new WireGuardConfig
            {
                PrivateKey = nodeB.PrivateKey,
                PeerPublicKey = nodeA.PublicKey,
                Address = IPAddress.Parse("100.64.0.21"),
                PrefixLength = 32,
            };

            var connA = new WireGuardConnection("127.0.0.1", 51820, configA,
                new InProcessWireGuardTransportFactory(link.Client),
                reconnectOptions: new WireGuardReconnectOptions { Enabled = false },
                timers: new WireGuardTimers(rekeyAttemptTimeSeconds: 1)); // acceptInbound defaults to false
            var connB = new WireGuardConnection("127.0.0.1", 51820, configB,
                new InProcessWireGuardTransportFactory(link.Server),
                reconnectOptions: new WireGuardReconnectOptions { Enabled = false },
                timers: new WireGuardTimers(rekeyAttemptTimeSeconds: 1));

            using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(30));
            // B runs in the background only to consume A's initiations (it also fails — both are initiator-only).
            Task bTask = Assert.ThrowsAsync<Abstractions.Drivers.VpnConnectionException>(() => connB.ConnectAsync(cts.Token));
            await Assert.ThrowsAsync<Abstractions.Drivers.VpnConnectionException>(() => connA.ConnectAsync(cts.Token));
            await bTask;

            await connA.DisposeAsync();
            await connB.DisposeAsync();
        }
    }
}
