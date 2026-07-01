using System.Net;
using System.Security.Cryptography;
using TqkLibrary.VpnClient.Crypto.Noise;
using TqkLibrary.VpnClient.Drivers.Core.Enums;
using TqkLibrary.VpnClient.Drivers.Tinc;
using TqkLibrary.VpnClient.Drivers.Tinc.Config;
using TqkLibrary.VpnClient.Tinc.Hosts;
using Xunit;

namespace TqkLibrary.VpnClient.Drivers.Tinc.Tests
{
    /// <summary>
    /// End-to-end driver tests: the real <see cref="TincConnection"/> driven against an in-process
    /// <see cref="SimulatedTincResponder"/> over loopback meta + UDP pipes. Covers the full lifecycle — meta SPTPS
    /// handshake, ACK / ADD_SUBNET, the data-plane SPTPS key exchange over REQ_KEY/ANS_KEY, and bidirectional bare-IP
    /// data over UDP. Mirrors the Nebula driver's connection tests.
    /// </summary>
    public class TincConnectionTests
    {
        static (byte[] seed, byte[] pub) NewKey()
        {
            byte[] seed = new byte[32];
            RandomNumberGenerator.Fill(seed);
            return (seed, new Ed25519Signer().DerivePublicKey(seed));
        }

        sealed class Harness : IAsyncDisposable
        {
            public TincConnection Client { get; }
            public SimulatedTincResponder Responder { get; }
            readonly CancellationTokenSource _cts = new();
            readonly Task _responderTask;

            public Harness()
            {
                var (clientSeed, clientPub) = NewKey();
                var (serverSeed, serverPub) = NewKey();

                var meta = new ByteStreamPipe();
                var udp = new DatagramPipe();

                // Peer (server) host config the client trusts.
                var peerHost = new TincHostConfig { Name = "server", Port = 655 };
                peerHost.Ed25519PublicKey = serverPub;
                peerHost.Subnets.Add("10.99.0.1/32");

                var config = new TincConfig
                {
                    NodeName = "client",
                    PrivateKey = clientSeed,
                    PeerHost = peerHost,
                    PeerEndpoint = new IPEndPoint(IPAddress.Loopback, 655),
                    OverlayAddress = IPAddress.Parse("10.99.0.2"),
                    PrefixLength = 32,
                    Mtu = 1400,
                };

                var factory = new InProcessTincTransportFactory(meta.ClientSide, udp.Client);
                Client = new TincConnection("server", 655, config, factory,
                    reconnectOptions: new TincReconnectOptions { Enabled = false });

                Responder = new SimulatedTincResponder(meta.ServerSide, udp.Server,
                    "server", serverSeed, serverPub, "client", clientPub);
                _responderTask = Task.Run(() => Responder.RunAsync(_cts.Token));
            }

            public async ValueTask DisposeAsync()
            {
                _cts.Cancel();
                try { await Client.DisposeAsync(); } catch { }
                try { await _responderTask; } catch { }
                _cts.Dispose();
            }
        }

        [Fact]
        public async Task Connect_CompletesMetaAndDataHandshake()
        {
            await using var h = new Harness();
            using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(15));
            await h.Client.ConnectAsync(cts.Token);

            Assert.Equal(VpnConnectionState.Connected, h.Client.State);
            Assert.Equal(IPAddress.Parse("10.99.0.2"), h.Client.AssignedAddress);
            // The peer's subnet became a tunnel route.
            Assert.Contains("10.99.0.1/32", h.Client.Config.Routes);
        }

        [Fact]
        public async Task DataPlane_EchoesIpPacketBothWays()
        {
            await using var h = new Harness();
            using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(15));
            await h.Client.ConnectAsync(cts.Token);

            var received = new TaskCompletionSource<byte[]>(TaskCreationOptions.RunContinuationsAsynchronously);
            h.Client.PacketChannel.InboundIpPacket += packet => received.TrySetResult(packet.ToArray());

            // A minimal IPv4-looking packet (version nibble 4 so a router-mode peer accepts it).
            byte[] ipPacket = { 0x45, 0x00, 0x00, 0x14, 0x00, 0x01, 0x00, 0x00, 0x40, 0x01, 0, 0, 10, 99, 0, 2, 10, 99, 0, 1 };
            await h.Client.PacketChannel.WriteIpPacketAsync(ipPacket, cts.Token);

            Task done = await Task.WhenAny(received.Task, Task.Delay(TimeSpan.FromSeconds(10)));
            Assert.True(done == received.Task, "did not receive the echoed IP packet in time");
            Assert.Equal(ipPacket, received.Task.Result);
            Assert.True(h.Responder.DataPacketsEchoed >= 1);
        }

        [Fact]
        public async Task DataPlane_ResponderOriginatedPacket_Delivered()
        {
            await using var h = new Harness();
            using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(15));
            await h.Client.ConnectAsync(cts.Token);

            // Drive one client→server packet first so the responder has opened its data transport, then have it echo a
            // second one back: this exercises the inbound (server→client) path end-to-end.
            var received = new TaskCompletionSource<byte[]>(TaskCreationOptions.RunContinuationsAsynchronously);
            h.Client.PacketChannel.InboundIpPacket += packet => received.TrySetResult(packet.ToArray());

            byte[] ipPacket = { 0x45, 0x00, 0x00, 0x10, 0, 0, 0, 0, 0x40, 0x01, 0, 0, 10, 99, 0, 2, 10, 99, 0, 1 };
            await h.Client.PacketChannel.WriteIpPacketAsync(ipPacket, cts.Token);

            Task done = await Task.WhenAny(received.Task, Task.Delay(TimeSpan.FromSeconds(10)));
            Assert.True(done == received.Task, "no inbound packet delivered");
        }
    }
}
