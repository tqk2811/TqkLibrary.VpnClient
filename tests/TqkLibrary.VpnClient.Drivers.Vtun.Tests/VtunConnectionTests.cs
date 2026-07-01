using System.Net;
using TqkLibrary.VpnClient.Abstractions.Drivers;
using TqkLibrary.VpnClient.Drivers.Core.Models;
using TqkLibrary.VpnClient.Drivers.Vtun.Config;
using TqkLibrary.VpnClient.Drivers.Core.Enums;
using TqkLibrary.VpnClient.Vtun.Wire.Enums;
using Xunit;

namespace TqkLibrary.VpnClient.Drivers.Vtun.Tests
{
    /// <summary>
    /// End-to-end tests driving a real <see cref="VtunConnection"/> against an in-process <see cref="SimulatedVtunServer"/>:
    /// the full challenge-response handshake, a data-frame round-trip (a written IP packet returns as an inbound one),
    /// and the rejection paths (wrong password ⇒ auth failure; an unsupported server flag set ⇒ connection error).
    /// </summary>
    public class VtunConnectionTests
    {
        static VtunConfig Config(string host = "test", string password = "pass") => new()
        {
            HostName = host,
            Password = password,
            TunnelAddress = IPAddress.Parse("10.11.0.2"),
            PeerAddress = IPAddress.Parse("10.11.0.1"),
            PrefixLength = 24,
            Mtu = 1450,
        };

        static (VtunConnection client, SimulatedVtunServer server, Task serverTask, CancellationTokenSource cts) Wire(
            VtunConfig config, string serverPassword, VtunHostFlags flags = VtunHostFlags.Tcp | VtunHostFlags.Tun,
            int cipherId = 0)
        {
            var pipe = new ByteStreamPipe();
            var server = new SimulatedVtunServer(pipe.ServerSide, serverPassword, flags, cipherId);
            var cts = new CancellationTokenSource();
            Task serverTask = Task.Run(() => server.RunAsync(cts.Token));
            var factory = new InProcessVtunTransportFactory(pipe.ClientSide);
            var reconnect = new VtunReconnectOptions { Enabled = false };
            var client = new VtunConnection("localhost", 5000, config, factory, reconnectOptions: reconnect);
            return (client, server, serverTask, cts);
        }

        [Fact]
        public async Task Connect_CompletesHandshake_AndAuthenticates()
        {
            var (client, server, serverTask, cts) = Wire(Config(), "pass");
            try
            {
                using var connectCts = new CancellationTokenSource(TimeSpan.FromSeconds(10));
                await client.ConnectAsync(connectCts.Token);

                Assert.Equal(VpnConnectionState.Connected, client.State);
                Assert.True(server.Authenticated);
                Assert.Equal(VtunHostFlags.Tcp | VtunHostFlags.Tun, client.ServerFlags);
                Assert.Equal(IPAddress.Parse("10.11.0.2"), client.AssignedAddress);
            }
            finally { cts.Cancel(); await client.DisposeAsync(); await serverTask; }
        }

        [Fact]
        public async Task DataFrame_RoundTrips_ThroughTheTunnel()
        {
            var (client, server, serverTask, cts) = Wire(Config(), "pass");
            try
            {
                using var connectCts = new CancellationTokenSource(TimeSpan.FromSeconds(10));
                await client.ConnectAsync(connectCts.Token);

                var received = new TaskCompletionSource<byte[]>(TaskCreationOptions.RunContinuationsAsynchronously);
                client.PacketChannel.InboundIpPacket += p => received.TrySetResult(p.ToArray());

                // A small fake IPv4 packet — vtun tun mode carries it verbatim; the server reflects it back.
                byte[] packet = { 0x45, 0x00, 0x00, 0x14, 0x00, 0x01, 0x00, 0x00, 0x40, 0x01, 0x00, 0x00,
                                  10, 11, 0, 2, 10, 11, 0, 1 };
                await client.PacketChannel.WriteIpPacketAsync(packet);

                Task done = await Task.WhenAny(received.Task, Task.Delay(TimeSpan.FromSeconds(5)));
                Assert.True(done == received.Task, "no inbound packet returned through the tunnel");
                byte[] inbound = await received.Task;
                Assert.Equal(packet, inbound);
            }
            finally { cts.Cancel(); await client.DisposeAsync(); await serverTask; }
        }

        [Fact]
        public async Task EncryptedDataFrame_RoundTrips_ThroughBlowfishEcbTunnel()
        {
            // Server announces 'encrypt' with cipher id 1 (Blowfish-128-ECB). The client must encrypt outbound data
            // frames and decrypt inbound ones; the packet must still return intact (the wire bytes are ciphertext).
            var flags = VtunHostFlags.Tcp | VtunHostFlags.Tun | VtunHostFlags.Encrypt;
            var (client, server, serverTask, cts) = Wire(Config(), "pass", flags, cipherId: 1);
            try
            {
                using var connectCts = new CancellationTokenSource(TimeSpan.FromSeconds(10));
                await client.ConnectAsync(connectCts.Token);
                Assert.Equal(VpnConnectionState.Connected, client.State);
                Assert.True((client.ServerFlags & VtunHostFlags.Encrypt) != 0);

                var received = new TaskCompletionSource<byte[]>(TaskCreationOptions.RunContinuationsAsynchronously);
                client.PacketChannel.InboundIpPacket += p => received.TrySetResult(p.ToArray());

                byte[] packet = { 0x45, 0x00, 0x00, 0x14, 0x00, 0x01, 0x00, 0x00, 0x40, 0x01, 0x00, 0x00,
                                  10, 11, 0, 2, 10, 11, 0, 1 };
                await client.PacketChannel.WriteIpPacketAsync(packet);

                Task done = await Task.WhenAny(received.Task, Task.Delay(TimeSpan.FromSeconds(5)));
                Assert.True(done == received.Task, "no inbound packet returned through the encrypted tunnel");
                Assert.Equal(packet, await received.Task); // decrypted back to the original IP packet
            }
            finally { cts.Cancel(); await client.DisposeAsync(); await serverTask; }
        }

        [Fact]
        public async Task Connect_UnsupportedCipher_ThrowsConnection()
        {
            // Server announces 'encrypt' with cipher id 16 (AES-256-OFB), which this driver does not implement → error.
            var flags = VtunHostFlags.Tcp | VtunHostFlags.Tun | VtunHostFlags.Encrypt;
            var (client, server, serverTask, cts) = Wire(Config(), "pass", flags, cipherId: 16);
            try
            {
                using var connectCts = new CancellationTokenSource(TimeSpan.FromSeconds(10));
                await Assert.ThrowsAsync<VpnConnectionException>(() => client.ConnectAsync(connectCts.Token));
                Assert.True(server.Authenticated); // auth succeeded; the cipher is what was rejected
            }
            finally { cts.Cancel(); await client.DisposeAsync(); await serverTask; }
        }

        [Fact]
        public async Task Connect_WrongPassword_ThrowsAuthentication()
        {
            // The client uses "wrongpass"; the server keyed with "pass" → its decrypt of the response ≠ challenge → ERR.
            var (client, server, serverTask, cts) = Wire(Config(password: "wrongpass"), "pass");
            try
            {
                using var connectCts = new CancellationTokenSource(TimeSpan.FromSeconds(10));
                await Assert.ThrowsAsync<VpnAuthenticationException>(() => client.ConnectAsync(connectCts.Token));
                Assert.False(server.Authenticated);
            }
            finally { cts.Cancel(); await client.DisposeAsync(); await serverTask; }
        }

        [Fact]
        public async Task Connect_UnsupportedFlags_ThrowsConnection()
        {
            // The server announces a pipe link, which this driver rejects after a successful auth (only tun/ether are supported).
            var (client, server, serverTask, cts) = Wire(Config(), "pass", VtunHostFlags.Tcp | VtunHostFlags.Pipe);
            try
            {
                using var connectCts = new CancellationTokenSource(TimeSpan.FromSeconds(10));
                await Assert.ThrowsAsync<VpnConnectionException>(() => client.ConnectAsync(connectCts.Token));
                Assert.True(server.Authenticated); // auth succeeded; the link type is what was rejected
            }
            finally { cts.Cancel(); await client.DisposeAsync(); await serverTask; }
        }

        [Fact]
        public async Task Connect_TapMode_BridgesEthernetToL3()
        {
            // Server announces 'type ether' (tap). The driver must bring up the L2 channel + ARP + VirtualHost bridge and
            // reach Connected; the bound facade exposes a bare-IP L3 channel (the Ethernet header is invisible to the stack).
            var (client, server, serverTask, cts) = Wire(Config(), "pass", VtunHostFlags.Tcp | VtunHostFlags.Ether);
            try
            {
                using var connectCts = new CancellationTokenSource(TimeSpan.FromSeconds(10));
                await client.ConnectAsync(connectCts.Token);
                Assert.Equal(VpnConnectionState.Connected, client.State);
                Assert.Equal(VtunHostFlags.Tcp | VtunHostFlags.Ether, client.ServerFlags);
                // The facade presents an L3 (bare-IP) channel regardless of the L2 carrier.
                Assert.Equal(Abstractions.Channels.Enums.LinkMedium.Ip, client.PacketChannel.Medium);
            }
            finally { cts.Cancel(); await client.DisposeAsync(); await serverTask; }
        }

        [Fact]
        public void Driver_Capabilities_AreTunTcpOutOfBand()
        {
            var driver = new VtunDriver(Config());
            Assert.Equal("vtun", driver.Name);
            Assert.Equal(Abstractions.Drivers.Enums.VpnLinkLayer.L3Ip, driver.Capabilities.LinkLayer);
            Assert.Equal(Abstractions.Drivers.Enums.AddressAssignment.OutOfBand, driver.Capabilities.AddressAssignment);
            Assert.True((driver.Capabilities.TransportKinds & Abstractions.Drivers.Enums.VpnTransportKind.Tcp) != 0);
        }
    }
}
