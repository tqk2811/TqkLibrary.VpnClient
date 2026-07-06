using System;
using System.Net;
using System.Net.Sockets;
using System.Threading;
using System.Threading.Tasks;
using TqkLibrary.VpnClient.Abstractions.Channels.Interfaces;
using TqkLibrary.VpnClient.Abstractions.Drivers.Enums;
using TqkLibrary.VpnClient.Abstractions.Drivers.Interfaces;
using TqkLibrary.VpnClient.Abstractions.Drivers.Models;
using TqkLibrary.VpnClient.Abstractions.Net;
using TqkLibrary.VpnClient.Abstractions.Transport.Interfaces;
using TqkLibrary.VpnClient.Drivers.Fou.Enums;
using TqkLibrary.VpnClient.IpEncap.Gre;
using Xunit;

namespace TqkLibrary.VpnClient.Drivers.Fou.Tests
{
    /// <summary>
    /// Offline coverage for the FOU / GUE (Generic X-over-UDP) driver runtime: the GUE variant-0 header codec
    /// (<see cref="GueHeader"/>), and the reused IpEncap data-plane channels (GRE / IPIP passthrough) over a UDP datagram
    /// pipe, framed bare (FOU) or behind a GUE header (GUE). No admin/server, no <c>Integration</c> trait — the real-socket
    /// case uses 127.0.0.1 ephemeral ports, the others an in-memory loopback link. Covers: GUE header round-trip + skip
    /// extensions + reject bad version / control message / truncated; inner-protocol dispatch (IPIP v4/v6 passthrough, GRE
    /// via IpEncap codec) for both FOU and GUE modes; a real UDP loopback round-trip; driver capabilities (no elevation /
    /// no raw socket) and default options.
    /// </summary>
    public class FouTests
    {
        const string ServerHost = "203.0.113.7"; // TEST-NET-3 literal so the resolver returns it verbatim (no DNS)

        // ---- 1) GUE variant-0 header codec ----

        [Theory]
        [InlineData(IpProtocol.IpInIp)]
        [InlineData(IpProtocol.Ipv6)]
        [InlineData(IpProtocol.Gre)]
        [InlineData(IpProtocol.Esp)]
        public void GueHeader_Encode_ThenDecode_RoundTripsProtocolAndPayload(byte protocol)
        {
            byte[] payload = { 0xDE, 0xAD, 0xBE, 0xEF, 0x01, 0x02 };
            byte[] datagram = GueHeader.Encode(protocol, payload);

            // A minimal variant-0 header is exactly 4 bytes: Ver=0/C=0/Hlen=0, Proto, Flags=0.
            Assert.Equal(GueHeader.BaseLength + payload.Length, datagram.Length);
            Assert.Equal(0, datagram[0]);
            Assert.Equal(protocol, datagram[1]);
            Assert.Equal(0, datagram[2]);
            Assert.Equal(0, datagram[3]);

            Assert.True(GueHeader.TryDecode(datagram, out byte decodedProto, out int payloadOffset));
            Assert.Equal(protocol, decodedProto);
            Assert.Equal(GueHeader.BaseLength, payloadOffset);
            Assert.Equal(payload, datagram.AsSpan(payloadOffset).ToArray());
        }

        [Theory]
        [InlineData(0)]
        [InlineData(1)]
        [InlineData(2)]
        [InlineData(3)]
        public void GueHeader_Decode_SkipsExtensionFieldsByHlen(int hlenWords)
        {
            // Hlen counts 32-bit words of extension fields between the 4-byte base header and the payload.
            byte[] payload = { 0x11, 0x22, 0x33 };
            int extBytes = hlenWords * 4;
            byte[] datagram = new byte[GueHeader.BaseLength + extBytes + payload.Length];
            datagram[0] = (byte)(hlenWords & 0x1F); // Ver=0, C=0, Hlen=hlenWords
            datagram[1] = IpProtocol.Gre;
            for (int i = 0; i < extBytes; i++) datagram[GueHeader.BaseLength + i] = 0xAB; // junk extension bytes
            payload.CopyTo(datagram.AsSpan(GueHeader.BaseLength + extBytes));

            Assert.True(GueHeader.TryDecode(datagram, out byte proto, out int payloadOffset));
            Assert.Equal(IpProtocol.Gre, proto);
            Assert.Equal(GueHeader.BaseLength + extBytes, payloadOffset);
            Assert.Equal(payload, datagram.AsSpan(payloadOffset).ToArray());
        }

        [Fact]
        public void GueHeader_Decode_RejectsNonZeroVersion()
        {
            byte[] datagram = { 0x40, IpProtocol.Gre, 0x00, 0x00, 0x01 }; // Ver=1 (top two bits)
            Assert.False(GueHeader.TryDecode(datagram, out _, out _));
        }

        [Fact]
        public void GueHeader_Decode_RejectsControlMessage()
        {
            byte[] datagram = { 0x20, IpProtocol.Gre, 0x00, 0x00, 0x01 }; // C bit set → control, not data
            Assert.False(GueHeader.TryDecode(datagram, out _, out _));
        }

        [Theory]
        [InlineData(0)]
        [InlineData(1)]
        [InlineData(2)]
        [InlineData(3)]
        public void GueHeader_Decode_RejectsTooShort(int length)
        {
            Assert.False(GueHeader.TryDecode(new byte[length], out _, out _));
        }

        [Fact]
        public void GueHeader_Decode_RejectsTruncatedExtensions()
        {
            // Hlen=2 declares 8 extension bytes, but only 2 are present after the base header.
            byte[] datagram = { 0x02, IpProtocol.Gre, 0x00, 0x00, 0xAB, 0xCD };
            Assert.False(GueHeader.TryDecode(datagram, out _, out _));
        }

        // ---- 2) inner-protocol dispatch, end-to-end over the in-memory loopback link (both directions of framing) ----

        [Theory]
        [InlineData(FouEncapMode.Fou, IpProtocol.IpInIp, false)]
        [InlineData(FouEncapMode.Fou, IpProtocol.Ipv6, true)]
        [InlineData(FouEncapMode.Fou, IpProtocol.Gre, false)]
        [InlineData(FouEncapMode.Fou, IpProtocol.Gre, true)]
        [InlineData(FouEncapMode.Gue, IpProtocol.IpInIp, false)]
        [InlineData(FouEncapMode.Gue, IpProtocol.Ipv6, true)]
        [InlineData(FouEncapMode.Gue, IpProtocol.Gre, false)]
        [InlineData(FouEncapMode.Gue, IpProtocol.Gre, true)]
        public async Task Tunnel_RoundTrips_InnerPacket_ForEachModeAndInnerProtocol(FouEncapMode mode, byte innerProtocol, bool innerIsIpv6)
        {
            var link = new LoopbackDatagramLink();
            using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(10));
            var options = new FouOptions { Mode = mode, InnerProtocol = innerProtocol, Mtu = 1400 };

            var driverA = new FouDriver(options, transportFactory: new FakeFouTransportFactory(link.A));
            var driverB = new FouDriver(options, transportFactory: new FakeFouTransportFactory(link.B));
            await using IVpnConnection connA = await driverA.ConnectAsync(new VpnEndpoint(ServerHost, 0), new VpnCredentials(), cts.Token);
            await using IVpnConnection connB = await driverB.ConnectAsync(new VpnEndpoint(ServerHost, 0), new VpnCredentials(), cts.Token);
            IPacketChannel chA = connA.Sessions[0].PacketChannel;
            IPacketChannel chB = connB.Sessions[0].PacketChannel;

            var received = new TaskCompletionSource<byte[]>(TaskCreationOptions.RunContinuationsAsynchronously);
            chB.InboundIpPacket += p => received.TrySetResult(p.ToArray());

            byte[] inner = innerIsIpv6 ? BuildIpv6Packet(0xCD) : BuildIpv4Packet(0xAB);
            await chA.WriteIpPacketAsync(inner, cts.Token);

            Assert.Equal(inner, await WaitAsync(received.Task, cts.Token));
        }

        // ---- 3) GUE receiver drops a datagram whose Proto does not match the configured inner protocol ----

        [Fact]
        public async Task Gue_Receiver_DropsWrongInnerProtocol_ThenDeliversValid()
        {
            var link = new LoopbackDatagramLink();
            using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(10));
            var options = new FouOptions { Mode = FouEncapMode.Gue, InnerProtocol = IpProtocol.Gre, Mtu = 1400 };

            var driver = new FouDriver(options, transportFactory: new FakeFouTransportFactory(link.B));
            await using IVpnConnection conn = await driver.ConnectAsync(new VpnEndpoint(ServerHost, 0), new VpnCredentials(), cts.Token);
            IPacketChannel channel = conn.Sessions[0].PacketChannel;

            var received = new TaskCompletionSource<byte[]>(TaskCreationOptions.RunContinuationsAsynchronously);
            channel.InboundIpPacket += p => received.TrySetResult(p.ToArray());

            // First a GUE datagram for the wrong inner protocol (ESP-50 vs configured GRE-47) → must be dropped.
            await link.A.SendAsync(GueHeader.Encode(IpProtocol.Esp, new byte[] { 1, 2, 3, 4 }), cts.Token);
            // Then a valid GUE(47) + GRE(IPv4) datagram → must surface the inner IPv4 packet, proving the loop continued.
            byte[] inner = BuildIpv4Packet(0x5A);
            byte[] gre = GreCodec.Encode(new GrePacket { ProtocolType = GreCodec.ProtocolTypeIpv4, Payload = inner });
            await link.A.SendAsync(GueHeader.Encode(IpProtocol.Gre, gre), cts.Token);

            Assert.Equal(inner, await WaitAsync(received.Task, cts.Token));
        }

        // ---- 4) real UDP loopback: FOU (IPIP passthrough) client <-> a raw UDP echo peer on 127.0.0.1 ----

        [Fact]
        public async Task Udp_Loopback_Fou_RoundTrips_InnerIpv4OverRealSocket()
        {
            using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(15));

            using var peer = new Socket(AddressFamily.InterNetwork, SocketType.Dgram, ProtocolType.Udp);
            peer.Bind(new IPEndPoint(IPAddress.Loopback, 0));
            int peerPort = ((IPEndPoint)peer.LocalEndPoint!).Port;
            var peerLoop = Task.Run(() => RunEchoPeerAsync(peer, cts.Token));

            // FOU + IPIP = header-less passthrough: the UDP payload IS the inner IP packet, so a plain reflecting peer echoes it.
            IDatagramTransport transport = new FouUdpTransportFactory(IPAddress.Loopback)
                .Create(new IPEndPoint(IPAddress.Loopback, peerPort));
            await transport.ConnectAsync(cts.Token);
            await using var channel = new IpEncap.RawIpPassthroughChannel(transport);

            var received = new TaskCompletionSource<byte[]>(TaskCreationOptions.RunContinuationsAsynchronously);
            channel.InboundIpPacket += p => received.TrySetResult(p.ToArray());
            channel.Start();

            byte[] inner = BuildIpv4Packet(0x11);
            await channel.WriteIpPacketAsync(inner, cts.Token);

            Assert.Equal(inner, await WaitAsync(received.Task, cts.Token));

            cts.Cancel();
            try { await peerLoop; } catch { }
        }

        // A raw UDP peer that reflects every datagram back to the sender's source endpoint (FOU-IPIP has no header).
        static async Task RunEchoPeerAsync(Socket peer, CancellationToken cancellationToken)
        {
            byte[] buffer = new byte[2048];
            var any = new IPEndPoint(IPAddress.Loopback, 0);
            using (cancellationToken.Register(() => { try { peer.Dispose(); } catch { } }))
            {
                while (!cancellationToken.IsCancellationRequested)
                {
                    SocketReceiveFromResult r = await peer.ReceiveFromAsync(new ArraySegment<byte>(buffer), SocketFlags.None, any).ConfigureAwait(false);
                    if (r.ReceivedBytes <= 0) continue;
                    await peer.SendToAsync(new ArraySegment<byte>(buffer, 0, r.ReceivedBytes), SocketFlags.None, r.RemoteEndPoint).ConfigureAwait(false);
                }
            }
        }

        // ---- 5) driver capabilities + name per mode ----

        [Theory]
        [InlineData(FouEncapMode.Fou, "fou")]
        [InlineData(FouEncapMode.Gue, "gue")]
        public void Driver_ExposesFouCapabilities(FouEncapMode mode, string expectedName)
        {
            var driver = new FouDriver(new FouOptions { Mode = mode });

            Assert.Equal(expectedName, driver.Name);
            Assert.False(driver.Capabilities.UsesPpp);
            Assert.False(driver.Capabilities.RequiresElevation);
            Assert.False(driver.Capabilities.RequiresRawIpSocket);
            Assert.Equal(VpnLinkLayer.L3Ip, driver.Capabilities.LinkLayer);
            Assert.True((driver.Capabilities.TransportKinds & VpnTransportKind.Udp) != 0);
            Assert.Equal(VpnSecurityKind.None, driver.Capabilities.SecurityKinds);
            Assert.Equal(VpnAuthMethod.None, driver.Capabilities.AuthMethods);
            Assert.Equal(AddressAssignment.OutOfBand, driver.Capabilities.AddressAssignment);
        }

        // ---- 6) default options ----

        [Fact]
        public void Options_Defaults_AreFouGrePort6080()
        {
            var options = new FouOptions();
            Assert.Equal(FouEncapMode.Fou, options.Mode);
            Assert.Equal(IpProtocol.Gre, options.InnerProtocol);
            Assert.Equal(6080, options.Port);
            Assert.Equal(1400, options.Mtu);
        }

        [Fact]
        public void Connection_NullTransportFactory_Throws()
        {
            Assert.Throws<ArgumentNullException>(() => new FouConnection(ServerHost, null!));
        }

        // ---- helpers ----

        // A minimal but version-correct IPv4 packet (first nibble 4) so the GRE channel picks ProtocolTypeIpv4.
        static byte[] BuildIpv4Packet(byte marker)
        {
            byte[] p = new byte[20];
            p[0] = 0x45; // version 4, IHL 5
            p[9] = 0xFE; // some protocol
            p[19] = marker;
            return p;
        }

        // A minimal IPv6 packet (first nibble 6) so the GRE channel picks ProtocolTypeIpv6.
        static byte[] BuildIpv6Packet(byte marker)
        {
            byte[] p = new byte[40];
            p[0] = 0x60; // version 6
            p[39] = marker;
            return p;
        }

        static async Task<T> WaitAsync<T>(Task<T> task, CancellationToken cancellationToken)
        {
            var cancelled = new TaskCompletionSource<bool>(TaskCreationOptions.RunContinuationsAsynchronously);
            using (cancellationToken.Register(() => cancelled.TrySetResult(true)))
            {
                if (await Task.WhenAny(task, cancelled.Task).ConfigureAwait(false) != task)
                    cancellationToken.ThrowIfCancellationRequested();
                return await task.ConfigureAwait(false);
            }
        }

        /// <summary>A fake <see cref="IFouTransportFactory"/> handing out one preconfigured loopback datagram end as the UDP pipe.</summary>
        sealed class FakeFouTransportFactory : IFouTransportFactory
        {
            readonly IDatagramTransport _transport;
            public FakeFouTransportFactory(IDatagramTransport transport) => _transport = transport;
            public IDatagramTransport Create(IPEndPoint remote) => _transport;
        }
    }
}
