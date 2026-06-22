using System;
using System.Net;
using System.Threading;
using System.Threading.Tasks;
using TqkLibrary.VpnClient.Abstractions.Channels.Interfaces;
using TqkLibrary.VpnClient.Abstractions.Drivers.Enums;
using TqkLibrary.VpnClient.Abstractions.Drivers.Interfaces;
using TqkLibrary.VpnClient.Abstractions.Drivers.Models;
using TqkLibrary.VpnClient.Abstractions.Transport.Interfaces;
using TqkLibrary.VpnClient.Drivers.IpEncap.Enums;
using TqkLibrary.VpnClient.IpEncap.Gre;
using Xunit;

namespace TqkLibrary.VpnClient.Drivers.IpEncap.Tests
{
    /// <summary>
    /// Offline end-to-end coverage for the plain IP-encapsulation driver runtime
    /// (<see cref="IpEncapConnection"/> / <see cref="IpEncapDriver"/>), driven against a loopback datagram link standing
    /// in for the raw-IP proto-47/4/41 transport. No real raw sockets, no <c>Integration</c> trait.
    /// <para>What this covers (exercises the real driver's <c>EstablishAsync</c> and the stable
    /// <see cref="ReconnectingVpnConnection{TState}.PacketChannel"/> facade):</para>
    /// <list type="bullet">
    ///   <item>GRE (proto-47): an inner IPv4 packet written to the channel reaches the peer GRE-wrapped (decodes via
    ///         <see cref="GreCodec"/> back to the same inner packet), and a peer→client GRE frame surfaces on the
    ///         channel's <c>InboundIpPacket</c>.</item>
    ///   <item>IPIP (proto-4): the inner IPv4 packet rides the wire verbatim (header-less) both ways.</item>
    ///   <item>SIT (proto-41): an inner IPv6 packet rides verbatim (header-less) both ways.</item>
    ///   <item>The driver's capabilities and its null-factory guard.</item>
    /// </list>
    /// </summary>
    public class IpEncapConnectionTests
    {
        const string ServerHost = "203.0.113.7"; // TEST-NET-3 literal so the resolver returns it verbatim (no DNS)

        [Fact]
        public void Driver_ExposesIpEncapCapabilities()
        {
            var driver = new IpEncapDriver(new FakeRawIpTransportFactory(new LoopbackDatagramLink().A));

            Assert.Equal("ipencap", driver.Name);
            Assert.False(driver.Capabilities.UsesPpp);
            Assert.True(driver.Capabilities.RequiresElevation);
            Assert.True(driver.Capabilities.RequiresRawIpSocket);
            Assert.Equal(VpnLinkLayer.L3Ip, driver.Capabilities.LinkLayer);
            Assert.True((driver.Capabilities.TransportKinds & VpnTransportKind.RawIp) != 0);
            Assert.Equal(VpnSecurityKind.None, driver.Capabilities.SecurityKinds);
            Assert.Equal(VpnAuthMethod.None, driver.Capabilities.AuthMethods);
            Assert.Equal(AddressAssignment.OutOfBand, driver.Capabilities.AddressAssignment);
        }

        [Fact]
        public void Driver_NullRawIpFactory_Throws()
        {
            Assert.Throws<ArgumentNullException>(() => new IpEncapDriver(null!));
        }

        [Fact]
        public void Connection_NullRawIpFactory_Throws()
        {
            Assert.Throws<ArgumentNullException>(() => new IpEncapConnection(ServerHost, null!));
        }

        [Fact]
        public async Task Gre_RoundTrips_InnerIpv4PacketBothWays()
        {
            var link = new LoopbackDatagramLink();
            using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(10));

            var driver = new IpEncapDriver(new FakeRawIpTransportFactory(link.A),
                new IpEncapOptions { Kind = IpEncapKind.Gre, Mtu = 1400 });
            await using IVpnConnection connection = await driver.ConnectAsync(
                new VpnEndpoint(ServerHost, 0), new VpnCredentials(), cts.Token);
            IPacketChannel channel = connection.Sessions[0].PacketChannel;

            // client → peer: the inner IPv4 packet must reach the peer GRE-wrapped and decode back to the same bytes.
            byte[] innerOut = BuildIpv4Packet(0x11);
            await channel.WriteIpPacketAsync(innerOut, cts.Token);

            byte[] datagram = await ReceiveDatagramAsync(link.B, cts.Token);
            Assert.True(GreCodec.TryDecode(datagram, out GrePacket? wrapped) && wrapped is not null);
            Assert.Equal(GreCodec.ProtocolTypeIpv4, wrapped!.ProtocolType);
            Assert.Equal(innerOut, wrapped.Payload.ToArray());

            // peer → client: a GRE frame carrying an inner IPv4 packet must surface on InboundIpPacket verbatim.
            var inbound = new TaskCompletionSource<byte[]>(TaskCreationOptions.RunContinuationsAsynchronously);
            channel.InboundIpPacket += p => inbound.TrySetResult(p.ToArray());

            byte[] innerIn = BuildIpv4Packet(0x22);
            byte[] greIn = GreCodec.Encode(new GrePacket { ProtocolType = GreCodec.ProtocolTypeIpv4, Payload = innerIn });
            await link.B.SendAsync(greIn, cts.Token);

            byte[] surfaced = await WaitAsync(inbound.Task, cts.Token);
            Assert.Equal(innerIn, surfaced);
        }

        [Fact]
        public async Task IpIp_RoundTrips_InnerIpv4PacketVerbatimBothWays()
        {
            var link = new LoopbackDatagramLink();
            using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(10));

            var driver = new IpEncapDriver(new FakeRawIpTransportFactory(link.A),
                new IpEncapOptions { Kind = IpEncapKind.IpIp, Mtu = 1480 });
            await using IVpnConnection connection = await driver.ConnectAsync(
                new VpnEndpoint(ServerHost, 0), new VpnCredentials(), cts.Token);
            IPacketChannel channel = connection.Sessions[0].PacketChannel;

            // client → peer: header-less, so the wire datagram IS the inner IP packet verbatim.
            byte[] innerOut = BuildIpv4Packet(0x33);
            await channel.WriteIpPacketAsync(innerOut, cts.Token);
            byte[] datagram = await ReceiveDatagramAsync(link.B, cts.Token);
            Assert.Equal(innerOut, datagram);

            // peer → client: a raw inner IP packet surfaces verbatim on InboundIpPacket.
            var inbound = new TaskCompletionSource<byte[]>(TaskCreationOptions.RunContinuationsAsynchronously);
            channel.InboundIpPacket += p => inbound.TrySetResult(p.ToArray());

            byte[] innerIn = BuildIpv4Packet(0x44);
            await link.B.SendAsync(innerIn, cts.Token);
            byte[] surfaced = await WaitAsync(inbound.Task, cts.Token);
            Assert.Equal(innerIn, surfaced);
        }

        [Fact]
        public async Task Sit_RoundTrips_InnerIpv6PacketVerbatimBothWays()
        {
            var link = new LoopbackDatagramLink();
            using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(10));

            var driver = new IpEncapDriver(new FakeRawIpTransportFactory(link.A),
                new IpEncapOptions { Kind = IpEncapKind.Sit, Mtu = 1480 });
            await using IVpnConnection connection = await driver.ConnectAsync(
                new VpnEndpoint(ServerHost, 0), new VpnCredentials(), cts.Token);
            IPacketChannel channel = connection.Sessions[0].PacketChannel;

            byte[] innerOut = BuildIpv6Packet(0x55);
            await channel.WriteIpPacketAsync(innerOut, cts.Token);
            byte[] datagram = await ReceiveDatagramAsync(link.B, cts.Token);
            Assert.Equal(innerOut, datagram);

            var inbound = new TaskCompletionSource<byte[]>(TaskCreationOptions.RunContinuationsAsynchronously);
            channel.InboundIpPacket += p => inbound.TrySetResult(p.ToArray());

            byte[] innerIn = BuildIpv6Packet(0x66);
            await link.B.SendAsync(innerIn, cts.Token);
            byte[] surfaced = await WaitAsync(inbound.Task, cts.Token);
            Assert.Equal(innerIn, surfaced);
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

        static async Task<byte[]> ReceiveDatagramAsync(LoopbackDatagramLink.End end, CancellationToken cancellationToken)
        {
            byte[] buffer = new byte[2048];
            int n = await end.ReceiveAsync(buffer, cancellationToken).ConfigureAwait(false);
            return buffer.AsMemory(0, n).ToArray();
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

        /// <summary>A fake <see cref="IRawIpTransportFactory"/> handing out one preconfigured loopback datagram end as the raw-IP pipe.</summary>
        sealed class FakeRawIpTransportFactory : IRawIpTransportFactory
        {
            readonly IDatagramTransport _transport;
            public FakeRawIpTransportFactory(IDatagramTransport transport) => _transport = transport;
            public bool IsAvailable => true;
            public IDatagramTransport Create(IPAddress remote, int ipProtocol, IPAddress? localBind = null) => _transport;
        }
    }
}
