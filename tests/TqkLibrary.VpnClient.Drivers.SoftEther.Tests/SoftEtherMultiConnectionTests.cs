using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Threading;
using System.Threading.Channels;
using System.Threading.Tasks;
using TqkLibrary.VpnClient.Drivers.SoftEther.Enums;
using TqkLibrary.VpnClient.SoftEther.Models;
using Xunit;

namespace TqkLibrary.VpnClient.Drivers.SoftEther.Tests
{
    /// <summary>
    /// Drives the real <see cref="SoftEtherConnection"/> over a multi-connection session (V.4) against an in-process
    /// SecureNAT server: after login the driver opens up to <c>max_connection</c> extra TLS connections via
    /// <c>additional_connect</c> (reattaching by session key), aggregates them into one data path, and round-robins the
    /// Ethernet-over-TLS data session across all of them. The tests prove N connections attach, that two-way IP traffic
    /// survives reassembly with no loss across many packets, and that half-duplex keeps the direction split. Offline —
    /// the server is throwaway test scaffolding.
    /// </summary>
    public class SoftEtherMultiConnectionTests
    {
        static SoftEtherLoginRequest Login(uint maxConnection) => new SoftEtherLoginRequest
        {
            HubName = "DEFAULT",
            UserName = "alice",
            Password = "P@ssw0rd",
            Session = new SoftEtherSessionParams { MaxConnection = maxConnection },
        };

        static byte[] BuildIpv4(IPAddress dst, byte[] tail)
        {
            byte[] packet = new byte[20 + tail.Length];
            packet[0] = 0x45;
            int total = packet.Length;
            packet[2] = (byte)(total >> 8); packet[3] = (byte)total;
            packet[8] = 64;
            packet[9] = 253;
            IPAddress.Parse("192.168.30.10").GetAddressBytes().CopyTo(packet, 12);
            dst.GetAddressBytes().CopyTo(packet, 16);
            tail.CopyTo(packet, 20);
            return packet;
        }

        [Fact]
        public async Task MultiConnection_OpensAdditionalConnects_AndRoundTripsAllPacketsWithoutLoss()
        {
            using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(30));
            var server = new SoftEtherMultiConnectionServer(grantedMaxConnection: 4);
            var factory = new MultiConnectionTransportFactory(server, cts.Token);

            var connection = new SoftEtherConnection("vpn.example.com", 443, Login(4), factory,
                reconnectOptions: new SoftEtherReconnectOptions { Enabled = false });

            var inbound = Channel.CreateUnbounded<byte[]>();
            connection.PacketChannel.InboundIpPacket += m => inbound.Writer.TryWrite(m.ToArray());

            await connection.ConnectAsync(cts.Token);

            Assert.Equal(SoftEtherConnectionState.Connected, connection.State);
            Assert.Equal(4, connection.ConnectionCount);                 // primary + 3 additional_connect
            Assert.Equal(4, server.AttachedConnections);
            Assert.Equal(server.LeasedAddress, connection.AssignedAddress);

            // Round-trip many packets: with round-robin egress and merged ingress, every one must come back (no loss,
            // each packet self-contained so reassembly is the union of all connections).
            const int count = 40;
            var expected = new List<byte[]>();
            for (int i = 0; i < count; i++)
            {
                byte[] packet = BuildIpv4(IPAddress.Parse("8.8.8.8"),
                    System.Text.Encoding.ASCII.GetBytes($"multi-conn packet {i}"));
                expected.Add(packet);
                await connection.PacketChannel.WriteIpPacketAsync(packet, cts.Token);
            }

            var received = new List<byte[]>();
            for (int i = 0; i < count; i++)
                received.Add(await inbound.Reader.ReadAsync(cts.Token));

            // Every distinct packet returned exactly once (set equality — order across connections is best-effort).
            Assert.Equal(count, received.Count);
            foreach (byte[] packet in expected)
                Assert.Contains(received, r => r.SequenceEqual(packet));

            await connection.DisposeAsync();
        }

        [Fact]
        public async Task MultiConnection_ClampsToServerGrantedCount()
        {
            using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(30));
            // Client asks for 8 but the server (hub policy) only grants 2.
            var server = new SoftEtherMultiConnectionServer(grantedMaxConnection: 2);
            var factory = new MultiConnectionTransportFactory(server, cts.Token);

            var connection = new SoftEtherConnection("vpn.example.com", 443, Login(8), factory,
                reconnectOptions: new SoftEtherReconnectOptions { Enabled = false });
            await connection.ConnectAsync(cts.Token);

            Assert.Equal(2, connection.ConnectionCount);
            Assert.Equal(2, server.AttachedConnections);

            var inbound = Channel.CreateUnbounded<byte[]>();
            connection.PacketChannel.InboundIpPacket += m => inbound.Writer.TryWrite(m.ToArray());
            byte[] packet = BuildIpv4(IPAddress.Parse("1.1.1.1"), System.Text.Encoding.ASCII.GetBytes("clamped"));
            await connection.PacketChannel.WriteIpPacketAsync(packet, cts.Token);
            Assert.Equal(packet, await inbound.Reader.ReadAsync(cts.Token));

            await connection.DisposeAsync();
        }

        [Fact]
        public async Task SingleConnection_StillWorks_WhenMaxConnectionIsOne()
        {
            using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(30));
            var server = new SoftEtherMultiConnectionServer(grantedMaxConnection: 1);
            var factory = new MultiConnectionTransportFactory(server, cts.Token);

            var connection = new SoftEtherConnection("vpn.example.com", 443, Login(1), factory,
                reconnectOptions: new SoftEtherReconnectOptions { Enabled = false });
            await connection.ConnectAsync(cts.Token);

            Assert.Equal(1, connection.ConnectionCount);
            Assert.Equal(1, server.AttachedConnections);

            var inbound = Channel.CreateUnbounded<byte[]>();
            connection.PacketChannel.InboundIpPacket += m => inbound.Writer.TryWrite(m.ToArray());
            byte[] packet = BuildIpv4(IPAddress.Parse("9.9.9.9"), System.Text.Encoding.ASCII.GetBytes("single"));
            await connection.PacketChannel.WriteIpPacketAsync(packet, cts.Token);
            Assert.Equal(packet, await inbound.Reader.ReadAsync(cts.Token));

            await connection.DisposeAsync();
        }

        [Fact]
        public async Task HalfConnection_SplitsDirections_AndStillRoundTrips()
        {
            using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(30));
            // 4 connections, half-duplex: client sends on 2, receives on 2.
            var server = new SoftEtherMultiConnectionServer(grantedMaxConnection: 4, halfConnection: true);
            var factory = new MultiConnectionTransportFactory(server, cts.Token);

            var connection = new SoftEtherConnection("vpn.example.com", 443, Login(4), factory,
                reconnectOptions: new SoftEtherReconnectOptions { Enabled = false });

            var inbound = Channel.CreateUnbounded<byte[]>();
            connection.PacketChannel.InboundIpPacket += m => inbound.Writer.TryWrite(m.ToArray());

            await connection.ConnectAsync(cts.Token);

            Assert.Equal(4, connection.ConnectionCount);
            Assert.Equal(4, server.AttachedConnections);
            Assert.Equal(server.LeasedAddress, connection.AssignedAddress);

            // Two-way traffic survives even though each connection is one-directional.
            const int count = 20;
            var expected = new List<byte[]>();
            for (int i = 0; i < count; i++)
            {
                byte[] packet = BuildIpv4(IPAddress.Parse("8.8.4.4"),
                    System.Text.Encoding.ASCII.GetBytes($"half-duplex packet {i}"));
                expected.Add(packet);
                await connection.PacketChannel.WriteIpPacketAsync(packet, cts.Token);
            }
            var received = new List<byte[]>();
            for (int i = 0; i < count; i++)
                received.Add(await inbound.Reader.ReadAsync(cts.Token));

            Assert.Equal(count, received.Count);
            foreach (byte[] packet in expected)
                Assert.Contains(received, r => r.SequenceEqual(packet));

            await connection.DisposeAsync();
        }
    }
}
