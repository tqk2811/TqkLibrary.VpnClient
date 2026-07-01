using System;
using System.Net;
using System.Threading;
using System.Threading.Channels;
using System.Threading.Tasks;
using TqkLibrary.VpnClient.Abstractions.Drivers;
using TqkLibrary.VpnClient.Abstractions.Drivers.Enums;
using TqkLibrary.VpnClient.Abstractions.Drivers.Interfaces;
using TqkLibrary.VpnClient.Abstractions.Drivers.Models;
using TqkLibrary.VpnClient.Drivers.Core.Enums;
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

        static SoftEtherLoginRequest Login(bool useEncrypt, bool useCompress) => new SoftEtherLoginRequest
        {
            HubName = "DEFAULT",
            UserName = "alice",
            Password = "P@ssw0rd",
            Session = new SoftEtherSessionParams { MaxConnection = 1, UseEncrypt = useEncrypt, UseCompress = useCompress },
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
            Assert.Equal(VpnConnectionState.Connected, connection.State);
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

        [Theory]
        [InlineData(true, false)]    // use_encrypt only (RC4 over TLS)
        [InlineData(false, true)]    // use_compress only (DEFLATE per frame)
        [InlineData(true, true)]     // both: compress then encrypt
        public async Task Connect_WithEncryptAndCompress_RoundTripsIp(bool useEncrypt, bool useCompress)
        {
            var (client, server) = DuplexPipe.CreatePair();
            var sim = new SimulatedSoftEtherServer(server, useEncrypt: useEncrypt, useCompress: useCompress);
            using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(30));
            var serverTask = Task.Run(() => sim.RunAsync(cts.Token));

            var connection = new SoftEtherConnection("vpn.example.com", 443, Login(useEncrypt, useCompress),
                new InProcessSoftEtherTransportFactory(() => client),
                reconnectOptions: new SoftEtherReconnectOptions { Enabled = false });

            var inbound = Channel.CreateUnbounded<byte[]>();
            connection.PacketChannel.InboundIpPacket += m => inbound.Writer.TryWrite(m.ToArray());

            await connection.ConnectAsync(cts.Token);

            // The whole handshake + DHCP lease + ARP ran through the use_compress/use_encrypt data session.
            Assert.Equal(VpnConnectionState.Connected, connection.State);
            Assert.Equal(sim.LeasedAddress, connection.AssignedAddress);

            // A compressible IP packet survives compress+encrypt both ways (echoed by the server).
            byte[] packet = BuildIpv4(IPAddress.Parse("8.8.8.8"),
                System.Text.Encoding.ASCII.GetBytes(new string('z', 400)));   // long run → actually compresses
            await connection.PacketChannel.WriteIpPacketAsync(packet, cts.Token);
            byte[] echoed = await inbound.Reader.ReadAsync(cts.Token);
            Assert.Equal(packet, echoed);

            await connection.DisposeAsync();
        }

        // A minimal IPv6 packet whose next-header is UDP (17), so the bridge/NDISC does not mistake it for an NDISC message.
        static byte[] BuildIpv6(IPAddress src, IPAddress dst, byte[] tail)
        {
            byte[] packet = new byte[40 + tail.Length];
            packet[0] = 0x60;                                 // version 6
            packet[4] = (byte)(tail.Length >> 8); packet[5] = (byte)tail.Length;
            packet[6] = 17;                                   // next header = UDP
            packet[7] = 64;                                   // hop limit
            src.GetAddressBytes().CopyTo(packet, 8);          // RFC 8200: src @ 8
            dst.GetAddressBytes().CopyTo(packet, 24);         // dst @ 24
            tail.CopyTo(packet, 40);
            return packet;
        }

        [Fact]
        public async Task Connect_WithIpv6Enabled_ConfiguresV6BySlaac_AndRoundTripsV4AndV6()
        {
            var (client, server) = DuplexPipe.CreatePair();
            var sim = new SimulatedSoftEtherServer(server, enableIpv6: true);
            using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(30));
            var serverTask = Task.Run(() => sim.RunAsync(cts.Token));

            var connection = new SoftEtherConnection("vpn.example.com", 443, Login(),
                new InProcessSoftEtherTransportFactory(() => client),
                reconnectOptions: new SoftEtherReconnectOptions { Enabled = false },
                enableIpv6: true);

            var inbound = Channel.CreateUnbounded<byte[]>();
            connection.PacketChannel.InboundIpPacket += m => inbound.Writer.TryWrite(m.ToArray());

            await connection.ConnectAsync(cts.Token);

            // IPv4 still leased over DHCP exactly as before.
            Assert.Equal(VpnConnectionState.Connected, connection.State);
            Assert.Equal(sim.LeasedAddress, connection.AssignedAddress);
            Assert.Equal(24, connection.Config.PrefixLength);

            // IPv6 configured by SLAAC: the autonomous /64 prefix from the RA + EUI-64 of the connection's MAC, /64.
            Assert.True(connection.IsIpv6Enabled);
            Assert.NotNull(connection.AssignedAddressV6);
            Assert.True(sim.RouterAdvertisements >= 1);   // the bridge solicited an RA
            Assert.Equal(System.Net.Sockets.AddressFamily.InterNetworkV6, connection.AssignedAddressV6!.AddressFamily);
            byte[] v6 = connection.AssignedAddressV6.GetAddressBytes();
            Assert.Equal(SimulatedSoftEtherServer.Ipv6Prefix.GetAddressBytes()[..8], v6[..8]);   // shares the advertised /64
            Assert.Equal(64, connection.Config.PrefixLengthV6);
            Assert.Contains(IPAddress.Parse("2001:4860:4860::8888"), connection.Config.DnsServers);   // DHCPv6 DNS
            Assert.Contains("::/0 fe80::1", connection.Config.Routes);                                  // v6 default route via the RA router

            // IPv4 packet still round-trips (echoed by the server) over the dual-stack bridge.
            byte[] v4Packet = BuildIpv4(IPAddress.Parse("8.8.8.8"), System.Text.Encoding.ASCII.GetBytes("v4 over dual-stack"));
            await connection.PacketChannel.WriteIpPacketAsync(v4Packet, cts.Token);
            Assert.Equal(v4Packet, await ReadDataPacketAsync(inbound, cts.Token));

            // IPv6 packet round-trips: egress resolves the next-hop MAC by REAL NDISC (NS → server NA), then echoed.
            byte[] v6Packet = BuildIpv6(connection.AssignedAddressV6,
                IPAddress.Parse("2606:4700:4700::1111"), System.Text.Encoding.ASCII.GetBytes("v6 over SoftEther"));
            await connection.PacketChannel.WriteIpPacketAsync(v6Packet, cts.Token);
            Assert.Equal(v6Packet, await ReadDataPacketAsync(inbound, cts.Token, ipv6Data: true));

            await connection.DisposeAsync();
        }

        [Fact]
        public async Task Connect_WithIpv6Enabled_ButIpv4OnlyServer_StillConnectsOnIpv4_NoV6Address()
        {
            var (client, server) = DuplexPipe.CreatePair();
            var sim = new SimulatedSoftEtherServer(server, enableIpv6: false);   // server advertises no IPv6 (IPv4-only SecureNAT)
            using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(30));
            var serverTask = Task.Run(() => sim.RunAsync(cts.Token));

            // Client opts into IPv6 but the SecureNAT is IPv4-only: best-effort v6 → IPv4 still connects.
            var connection = new SoftEtherConnection("vpn.example.com", 443, Login(),
                new InProcessSoftEtherTransportFactory(() => client),
                reconnectOptions: new SoftEtherReconnectOptions { Enabled = false },
                enableIpv6: true,
                ipv6Options: new TqkLibrary.VpnClient.Ethernet.Ipv6AddressConfiguratorOptions(
                    routerAdvertisementTimeout: TimeSpan.FromMilliseconds(150), routerSolicitationAttempts: 2));

            var inbound = Channel.CreateUnbounded<byte[]>();
            connection.PacketChannel.InboundIpPacket += m => inbound.Writer.TryWrite(m.ToArray());

            await connection.ConnectAsync(cts.Token);

            Assert.Equal(VpnConnectionState.Connected, connection.State);
            Assert.Equal(sim.LeasedAddress, connection.AssignedAddress);
            Assert.Null(connection.AssignedAddressV6);   // no RA → no SLAAC/DHCPv6 → IPv4-only config

            // IPv4 traffic still works.
            byte[] v4Packet = BuildIpv4(IPAddress.Parse("8.8.4.4"), System.Text.Encoding.ASCII.GetBytes("v4-only fallback"));
            await connection.PacketChannel.WriteIpPacketAsync(v4Packet, cts.Token);
            Assert.Equal(v4Packet, await ReadDataPacketAsync(inbound, cts.Token));

            await connection.DisposeAsync();
        }

        // Reads the next non-control IP packet from the inbound channel (skips NDISC/DHCP control frames the bridge raises).
        static async Task<byte[]> ReadDataPacketAsync(Channel<byte[]> inbound, CancellationToken cancellationToken, bool ipv6Data = false)
        {
            while (true)
            {
                byte[] p = await inbound.Reader.ReadAsync(cancellationToken);
                if (p.Length < 1) continue;
                byte version = (byte)(p[0] >> 4);
                // ICMPv6 (NDISC) rides IPv6 with next-header 58; skip those control frames.
                if (version == 6 && p.Length >= 7 && p[6] == 58) continue;
                if (ipv6Data && version != 6) continue;
                if (!ipv6Data && version != 4) continue;
                return p;
            }
        }

        [Fact]
        public async Task MultiHost_WithIpv6Enabled_PrimaryStationConfiguresV4AndV6()
        {
            var (client, server) = DuplexPipe.CreatePair();
            var sim = new SimulatedSoftEtherServer(server, enableIpv6: true);
            using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(30));
            var serverTask = Task.Run(() => sim.RunAsync(cts.Token));

            var connection = new SoftEtherConnection("vpn.example.com", 443, Login(),
                new InProcessSoftEtherTransportFactory(() => client),
                reconnectOptions: new SoftEtherReconnectOptions { Enabled = false },
                multiHost: true,
                enableIpv6: true);

            await connection.ConnectAsync(cts.Token);

            // The primary station leased IPv4 over the shared switch AND configured IPv6 by SLAAC over the same uplink.
            Assert.True(connection.IsMultiHost);
            Assert.True(connection.IsIpv6Enabled);
            Assert.Equal(sim.LeasedAddress, connection.AssignedAddress);
            Assert.NotNull(connection.AssignedAddressV6);
            Assert.Equal(SimulatedSoftEtherServer.Ipv6Prefix.GetAddressBytes()[..8],
                connection.AssignedAddressV6!.GetAddressBytes()[..8]);   // SLAAC address under the advertised /64
            Assert.Equal(1, connection.MultiHostSession!.StationCount);

            await connection.DisposeAsync();
        }

        [Fact]
        public async Task MultiHost_AttachesUplinkPort_PrimaryStationLeases_AndOpenSessionAddsAnotherStation()
        {
            var (client, server) = DuplexPipe.CreatePair();
            var sim = new SimulatedSoftEtherServer(server);
            using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(30));
            var serverTask = Task.Run(() => sim.RunAsync(cts.Token));

            var connection = new SoftEtherConnection("vpn.example.com", 443, Login(),
                new InProcessSoftEtherTransportFactory(() => client),
                reconnectOptions: new SoftEtherReconnectOptions { Enabled = false },
                multiHost: true);

            await connection.ConnectAsync(cts.Token);

            // The data channel is an uplink port on the broadcast domain; the primary station leased over the shared switch.
            Assert.True(connection.IsMultiHost);
            Assert.NotNull(connection.MultiHostSession);
            Assert.Equal(sim.LeasedAddress, connection.AssignedAddress);
            Assert.Equal(1, connection.MultiHostSession!.StationCount);
            Assert.Equal(2, connection.MultiHostSession.Adapter.Switch.PortCount);   // uplink + primary station

            // Round-trip an IP packet through the primary station's facade (ARP over the uplink → server → echo).
            var inbound = Channel.CreateUnbounded<byte[]>();
            connection.PacketChannel.InboundIpPacket += m => inbound.Writer.TryWrite(m.ToArray());
            byte[] packet = BuildIpv4(IPAddress.Parse("8.8.4.4"), System.Text.Encoding.ASCII.GetBytes("multi-host station 1"));
            await connection.PacketChannel.WriteIpPacketAsync(packet, cts.Token);
            Assert.Equal(packet, await inbound.Reader.ReadAsync(cts.Token));

            // A second station leases its own IP over the shared switch (the uplink bridges its DHCP to the server).
            var vpnConnection = new SoftEtherVpnConnection(connection,
                new SoftEtherVpnSession(connection.PacketChannel, connection.Config));
            IVpnSession station2 = await vpnConnection.OpenSessionAsync(cts.Token);
            Assert.Equal(sim.LeasedAddress, station2.Config.AssignedAddress);
            Assert.Equal(2, connection.MultiHostSession.StationCount);
            Assert.Equal(2, vpnConnection.Sessions.Count);
            Assert.NotSame(connection.PacketChannel, station2.PacketChannel);

            await vpnConnection.DisposeAsync();
        }

        [Fact]
        public async Task MultiHost_OpenSessionOnSingleHost_Throws()
        {
            var (client, server) = DuplexPipe.CreatePair();
            var sim = new SimulatedSoftEtherServer(server);
            using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(30));
            var serverTask = Task.Run(() => sim.RunAsync(cts.Token));

            var connection = new SoftEtherConnection("vpn.example.com", 443, Login(),
                new InProcessSoftEtherTransportFactory(() => client),
                reconnectOptions: new SoftEtherReconnectOptions { Enabled = false });   // single-host (default)
            await connection.ConnectAsync(cts.Token);

            Assert.False(connection.IsMultiHost);
            var vpnConnection = new SoftEtherVpnConnection(connection,
                new SoftEtherVpnSession(connection.PacketChannel, connection.Config));
            await Assert.ThrowsAsync<NotSupportedException>(() => vpnConnection.OpenSessionAsync(cts.Token));

            await vpnConnection.DisposeAsync();
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

            var states = Channel.CreateUnbounded<VpnConnectionState>();
            connection.StateChanged += s => states.Writer.TryWrite(s);

            await connection.ConnectAsync(cts.Token);
            Assert.Equal(VpnConnectionState.Connected, connection.State);

            // Closing the server end makes the client's receive loop see EOF → link lost → Disconnected (reconnect off).
            await server.DisposeAsync();
            VpnConnectionState state;
            do { state = await states.Reader.ReadAsync(cts.Token); }
            while (state != VpnConnectionState.Disconnected);

            Assert.Equal(VpnConnectionState.Disconnected, connection.State);
            await connection.DisposeAsync();
        }
    }
}
