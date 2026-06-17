using System;
using System.Net;
using System.Threading;
using System.Threading.Channels;
using System.Threading.Tasks;
using TqkLibrary.VpnClient.Abstractions.Drivers;
using TqkLibrary.VpnClient.Abstractions.Drivers.Enums;
using TqkLibrary.VpnClient.Abstractions.Drivers.Interfaces;
using TqkLibrary.VpnClient.Abstractions.Drivers.Models;
using TqkLibrary.VpnClient.Drivers.SoftEther.Enums;
using TqkLibrary.VpnClient.SoftEther.Models;
using Xunit;

namespace TqkLibrary.VpnClient.Drivers.SoftEther.Tests
{
    /// <summary>
    /// Drives the whole SoftEther driver offline against an in-process SecureNAT server: the real
    /// <see cref="SoftEtherConnection"/> runs the watermark/hello/login control handshake over an in-memory TLS-shaped
    /// byte stream, then leases an IP over DHCP on the L2 segment, resolves the gateway via ARP, and round-trips IP
    /// packets through the Ethernet-over-TLS data channel. The server is a throwaway test harness (this is a client
    /// library — there is no server product).
    /// </summary>
    public class SoftEtherConnectionTests
    {
        static SoftEtherLoginRequest Login() => new SoftEtherLoginRequest
        {
            HubName = "DEFAULT",
            UserName = "alice",
            Password = "P@ssw0rd",
            Session = new SoftEtherSessionParams { MaxConnection = 1 },
        };

        // A minimal, well-formed IPv4 packet (20-byte header) to dst, so VirtualHost reads the destination at offset 16
        // and ARP-resolves it. The payload is a recognisable tail the echo test can assert.
        static byte[] BuildIpv4(IPAddress dst, byte[] tail)
        {
            byte[] packet = new byte[20 + tail.Length];
            packet[0] = 0x45;                 // version 4, IHL 5
            int total = packet.Length;
            packet[2] = (byte)(total >> 8); packet[3] = (byte)total;
            packet[8] = 64;                   // TTL
            packet[9] = 253;                  // protocol (experimental) — irrelevant for the echo
            IPAddress.Parse("192.168.30.10").GetAddressBytes().CopyTo(packet, 12);   // src
            dst.GetAddressBytes().CopyTo(packet, 16);                                // dst
            tail.CopyTo(packet, 20);
            return packet;
        }

        [Fact]
        public async Task Connect_RunsHandshake_LeasesDhcpAddress_AndRoundTripsIp()
        {
            var (client, server) = DuplexPipe.CreatePair();
            var sim = new SimulatedSoftEtherServer(server);
            using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(30));
            var serverTask = Task.Run(() => sim.RunAsync(cts.Token));

            var connection = new SoftEtherConnection("vpn.example.com", 443, Login(),
                new InProcessSoftEtherTransportFactory(() => client),
                reconnectOptions: new SoftEtherReconnectOptions { Enabled = false });

            var inbound = Channel.CreateUnbounded<byte[]>();
            connection.PacketChannel.InboundIpPacket += m => inbound.Writer.TryWrite(m.ToArray());

            await connection.ConnectAsync(cts.Token);

            // The DHCP lease drove the tunnel config (address, prefix from the /24 mask, gateway route, DNS).
            Assert.Equal(SoftEtherConnectionState.Connected, connection.State);
            Assert.Equal(sim.LeasedAddress, connection.AssignedAddress);
            Assert.Equal(24, connection.Config.PrefixLength);
            Assert.Contains(IPAddress.Parse("192.168.30.1"), connection.Config.DnsServers);
            Assert.True(sim.DhcpReplies >= 2);   // an OFFER + an ACK

            // L2 channel bridged to L3: the stack sees no Ethernet header (it was subtracted from the MTU).
            Assert.Equal(0, connection.PacketChannel.MaxHeaderLength);

            // Client → server (echoed) → client: an IP packet survives the Ethernet-over-TLS data channel both ways.
            byte[] packet = BuildIpv4(IPAddress.Parse("8.8.8.8"), System.Text.Encoding.ASCII.GetBytes("tunnelled over SoftEther"));
            await connection.PacketChannel.WriteIpPacketAsync(packet, cts.Token);
            byte[] echoed = await inbound.Reader.ReadAsync(cts.Token);
            Assert.Equal(packet, echoed);

            await connection.DisposeAsync();
        }

        [Fact]
        public async Task Connect_ServerRejectsLogin_ThrowsWithErrorCode()
        {
            var (client, server) = DuplexPipe.CreatePair();
            var sim = new SimulatedSoftEtherServer(server, rejectLogin: true, rejectErrorCode: 7);
            using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(30));
            var serverTask = Task.Run(() => sim.RunAsync(cts.Token));

            var connection = new SoftEtherConnection("vpn.example.com", 443, Login(),
                new InProcessSoftEtherTransportFactory(() => client),
                reconnectOptions: new SoftEtherReconnectOptions { Enabled = false });

            var ex = await Assert.ThrowsAsync<TqkLibrary.VpnClient.SoftEther.SoftEtherProtocolException>(
                () => connection.ConnectAsync(cts.Token));
            Assert.Equal(7u, ex.ErrorCode);

            await connection.DisposeAsync();
        }

        [Fact]
        public async Task Driver_Connect_ExposesSessionAndCapabilities()
        {
            var (client, server) = DuplexPipe.CreatePair();
            var sim = new SimulatedSoftEtherServer(server);
            using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(30));
            var serverTask = Task.Run(() => sim.RunAsync(cts.Token));

            var driver = new SoftEtherDriver("DEFAULT",
                reconnectOptions: new SoftEtherReconnectOptions { Enabled = false },
                transportFactory: new InProcessSoftEtherTransportFactory(() => client));

            Assert.Equal("softether", driver.Name);
            Assert.Equal(VpnLinkLayer.L2Ethernet, driver.Capabilities.LinkLayer);
            Assert.Equal(VpnSecurityKind.Tls, driver.Capabilities.SecurityKinds);
            Assert.Equal(AddressAssignment.Dhcp, driver.Capabilities.AddressAssignment);
            Assert.Equal(MultiHostModel.L2BroadcastDomain, driver.Capabilities.MultiHostModel);
            Assert.True(driver.Capabilities.SupportsMultiHost);   // a whole L2 broadcast domain (EthernetAdapter, L2.8)

            IVpnConnection vpn = await driver.ConnectAsync(
                new VpnEndpoint("vpn.example.com", 443),
                new VpnCredentials { Username = "alice", Password = "P@ssw0rd" }, cts.Token);

            IVpnSession session = Assert.Single(vpn.Sessions);
            Assert.Equal(sim.LeasedAddress, session.Config.AssignedAddress);

            var inbound = Channel.CreateUnbounded<byte[]>();
            session.PacketChannel.InboundIpPacket += m => inbound.Writer.TryWrite(m.ToArray());
            byte[] packet = BuildIpv4(IPAddress.Parse("1.1.1.1"), System.Text.Encoding.ASCII.GetBytes("through the IVpnConnection facade"));
            await session.PacketChannel.WriteIpPacketAsync(packet, cts.Token);
            Assert.Equal(packet, await inbound.Reader.ReadAsync(cts.Token));

            await Assert.ThrowsAsync<NotSupportedException>(() => vpn.OpenSessionAsync(cts.Token));
            await vpn.DisposeAsync();
        }

        [Fact]
        public async Task Driver_Connect_WithoutUsername_FailsAuthentication()
        {
            var driver = new SoftEtherDriver("DEFAULT");
            using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(10));
            await Assert.ThrowsAsync<VpnAuthenticationException>(() => driver.ConnectAsync(
                new VpnEndpoint("vpn.example.com", 443), new VpnCredentials { Password = "x" }, cts.Token));
        }

        [Fact]
        public async Task ServerClosesSession_WithReconnectDisabled_GoesDisconnected()
        {
            var (client, server) = DuplexPipe.CreatePair();
            var sim = new SimulatedSoftEtherServer(server);
            using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(30));
            var serverTask = Task.Run(() => sim.RunAsync(cts.Token));

            var connection = new SoftEtherConnection("vpn.example.com", 443, Login(),
                new InProcessSoftEtherTransportFactory(() => client),
                reconnectOptions: new SoftEtherReconnectOptions { Enabled = false });

            var states = Channel.CreateUnbounded<SoftEtherConnectionState>();
            connection.StateChanged += s => states.Writer.TryWrite(s);

            await connection.ConnectAsync(cts.Token);
            Assert.Equal(SoftEtherConnectionState.Connected, connection.State);

            // Closing the server end makes the client's receive loop see EOF → link lost → Disconnected (reconnect off).
            await server.DisposeAsync();
            SoftEtherConnectionState state;
            do { state = await states.Reader.ReadAsync(cts.Token); }
            while (state != SoftEtherConnectionState.Disconnected);

            Assert.Equal(SoftEtherConnectionState.Disconnected, connection.State);
            await connection.DisposeAsync();
        }
    }
}
