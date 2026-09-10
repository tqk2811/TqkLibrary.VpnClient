using System.Net;
using TqkLibrary.VpnClient.Abstractions.Channels.Enums;
using TqkLibrary.VpnClient.Abstractions.Channels.Interfaces;
using TqkLibrary.VpnClient.Ethernet;
using Xunit;

namespace TqkLibrary.VpnClient.Ethernet.Tests
{
    public class VirtualHostTests
    {
        static readonly MacAddress MacA = MacAddress.Parse("02:00:00:00:00:0a");
        static readonly MacAddress MacB = MacAddress.Parse("02:00:00:00:00:0b");

        // ---- Egress (stack -> wire) ----

        [Fact]
        public async Task Egress_Ipv4_WrapsWithResolvedDestAndOwnSource()
        {
            var port = new CaptureEthernetChannel();
            var resolver = new MapNeighborResolver();
            IPAddress dst = IPAddress.Parse("10.0.0.2");
            resolver.Add(dst, MacB);
            await using var host = new VirtualHost(MacA, port, resolver);

            byte[] ip = Ipv4Packet(dst, 1, 2, 3, 4);
            await host.WriteIpPacketAsync(ip);

            byte[] frame = Assert.Single(port.Written);
            Assert.Equal(MacB, EthernetFrame.Destination(frame));               // resolved next-hop
            Assert.Equal(MacA, EthernetFrame.Source(frame));                    // own MAC
            Assert.Equal(EthernetFrame.EtherTypeIpv4, EthernetFrame.EtherType(frame));
            Assert.Equal(ip, EthernetFrame.Payload(frame).ToArray());           // IP packet carried verbatim
        }

        [Fact]
        public async Task Egress_Ipv6_UsesIpv6EtherType()
        {
            var port = new CaptureEthernetChannel();
            var resolver = new MapNeighborResolver();
            IPAddress dst = IPAddress.Parse("fd00::2");
            resolver.Add(dst, MacB);
            await using var host = new VirtualHost(MacA, port, resolver);

            byte[] ip = Ipv6Packet(dst, 9, 9);
            await host.WriteIpPacketAsync(ip);

            byte[] frame = Assert.Single(port.Written);
            Assert.Equal(MacB, EthernetFrame.Destination(frame));
            Assert.Equal(EthernetFrame.EtherTypeIpv6, EthernetFrame.EtherType(frame));
            Assert.Equal(ip, EthernetFrame.Payload(frame).ToArray());
        }

        [Fact]
        public async Task Egress_OffLink_ResolvesTheGatewayNotTheDestination()
        {
            var port = new CaptureEthernetChannel();
            var resolver = new MapNeighborResolver();
            IPAddress gateway = IPAddress.Parse("10.245.254.254");
            resolver.Add(gateway, MacB);                                        // only the router answers, as on a real segment
            await using var host = new VirtualHost(MacA, port, resolver);
            host.Routes.SetIpv4(IPAddress.Parse("10.245.96.168"), 16, gateway);

            IPAddress far = IPAddress.Parse("23.15.142.182");
            await host.WriteIpPacketAsync(Ipv4Packet(far, 7));

            byte[] frame = Assert.Single(port.Written);
            Assert.Equal(MacB, EthernetFrame.Destination(frame));               // framed to the router
            Assert.Equal(far, new IPAddress(EthernetFrame.Payload(frame).Slice(16, 4).ToArray()));   // still addressed to the far host
            Assert.DoesNotContain(far, resolver.Asked);                         // never wasted an ARP on the destination
            Assert.Contains(gateway, resolver.Asked);
        }

        [Fact]
        public async Task Egress_OnLink_StillResolvesTheDestination()
        {
            var port = new CaptureEthernetChannel();
            var resolver = new MapNeighborResolver();
            IPAddress neighbour = IPAddress.Parse("10.245.1.2");
            resolver.Add(neighbour, MacB);
            await using var host = new VirtualHost(MacA, port, resolver);
            host.Routes.SetIpv4(IPAddress.Parse("10.245.96.168"), 16, IPAddress.Parse("10.245.254.254"));

            await host.WriteIpPacketAsync(Ipv4Packet(neighbour, 7));

            byte[] frame = Assert.Single(port.Written);
            Assert.Equal(MacB, EthernetFrame.Destination(frame));
            Assert.Contains(neighbour, resolver.Asked);
        }

        [Fact]
        public async Task Egress_Unresolved_DropsPacket()
        {
            var port = new CaptureEthernetChannel();
            await using var host = new VirtualHost(MacA, port, new MapNeighborResolver());   // empty map

            await host.WriteIpPacketAsync(Ipv4Packet(IPAddress.Parse("10.0.0.5"), 1));

            Assert.Empty(port.Written);   // no MAC → nothing on the wire
        }

        [Fact]
        public async Task Egress_NonIpVersion_Dropped()
        {
            var port = new CaptureEthernetChannel();
            var resolver = new MapNeighborResolver();
            await using var host = new VirtualHost(MacA, port, resolver);

            byte[] notIp = new byte[20];
            notIp[0] = 0x50;   // version nibble 5 — neither IPv4 nor IPv6
            await host.WriteIpPacketAsync(notIp);

            Assert.Empty(port.Written);
        }

        // ---- Ingress (wire -> stack) ----

        [Fact]
        public async Task Ingress_Ipv4Frame_SurfacedAsIpPacket()
        {
            var port = new CaptureEthernetChannel();
            await using var host = new VirtualHost(MacA, port, new MapNeighborResolver());
            byte[]? got = null;
            host.InboundIpPacket += p => got = p.ToArray();

            byte[] ip = Ipv4Packet(IPAddress.Parse("10.0.0.9"), 7, 7);
            port.RaiseInbound(EthernetFrame.Build(MacA, MacB, EthernetFrame.EtherTypeIpv4, ip));

            Assert.NotNull(got);
            Assert.Equal(ip, got);
        }

        [Fact]
        public async Task Ingress_Ipv6Frame_SurfacedAsIpPacket()
        {
            var port = new CaptureEthernetChannel();
            await using var host = new VirtualHost(MacA, port, new MapNeighborResolver());
            byte[]? got = null;
            host.InboundIpPacket += p => got = p.ToArray();

            byte[] ip = Ipv6Packet(IPAddress.Parse("fd00::9"), 1);
            port.RaiseInbound(EthernetFrame.Build(MacA, MacB, EthernetFrame.EtherTypeIpv6, ip));

            Assert.NotNull(got);
            Assert.Equal(ip, got);
        }

        [Fact]
        public async Task Ingress_NonIpFrame_GoesToNonIpHook_NotIpHook()
        {
            var port = new CaptureEthernetChannel();
            await using var host = new VirtualHost(MacA, port, new MapNeighborResolver());
            bool ipFired = false;
            byte[]? nonIp = null;
            host.InboundIpPacket += _ => ipFired = true;
            host.InboundNonIpFrame += f => nonIp = f.ToArray();

            byte[] arp = EthernetFrame.Build(MacAddress.Broadcast, MacB, EthernetFrame.EtherTypeArp, new byte[] { 1, 2, 3 });
            port.RaiseInbound(arp);

            Assert.False(ipFired);                  // ARP is NOT an IP packet
            Assert.NotNull(nonIp);
            Assert.Equal(arp, nonIp);               // raw frame surfaced for the neighbor layer
        }

        [Fact]
        public async Task Ingress_RuntFrame_Ignored()
        {
            var port = new CaptureEthernetChannel();
            await using var host = new VirtualHost(MacA, port, new MapNeighborResolver());
            bool any = false;
            host.InboundIpPacket += _ => any = true;
            host.InboundNonIpFrame += _ => any = true;

            port.RaiseInbound(new byte[10]);   // shorter than the 14-byte header

            Assert.False(any);
        }

        // ---- Link properties ----

        [Fact]
        public async Task LinkProperties_ReportIpMediumAndMtuMinusHeader()
        {
            var port = new CaptureEthernetChannel { Mtu = 1500 };
            await using var host = new VirtualHost(MacA, port, new MapNeighborResolver());

            Assert.Equal(LinkMedium.Ip, host.Medium);
            Assert.Equal(1500 - EthernetFrame.HeaderLength, host.Mtu);   // 1486 — clamps MSS for Ethernet overhead
            Assert.Equal(0, host.MaxHeaderLength);
            Assert.False(host.RequiresLinkAddressResolution);
            Assert.Equal(MacA, host.Mac);
        }

        // ---- Integration with the switch ----

        [Fact]
        public async Task Integration_TwoHostsOverSwitch_DeliversIpPacket()
        {
            await using var sw = new EthernetSwitch();
            var resolverA = new MapNeighborResolver();
            IPAddress bIp = IPAddress.Parse("10.0.0.2");
            resolverA.Add(bIp, MacB);

            await using var hostA = new VirtualHost(MacA, sw.ConnectHost(MacA), resolverA);
            await using var hostB = new VirtualHost(MacB, sw.ConnectHost(MacB), new MapNeighborResolver());
            byte[]? bGot = null;
            hostB.InboundIpPacket += p => bGot = p.ToArray();

            byte[] ip = Ipv4Packet(bIp, 7, 7, 7);
            await hostA.WriteIpPacketAsync(ip);   // egress A -> resolve B's MAC -> switch floods (B unknown) -> ingress B

            Assert.NotNull(bGot);
            Assert.Equal(ip, bGot);
        }

        [Fact]
        public async Task DisposeAsync_DetachesPortFromSwitch()
        {
            await using var sw = new EthernetSwitch();
            var host = new VirtualHost(MacA, sw.ConnectHost(MacA), new MapNeighborResolver());
            Assert.Equal(1, sw.PortCount);

            await host.DisposeAsync();

            Assert.Equal(0, sw.PortCount);
        }

        // ---- Helpers ----

        /// <summary>A minimal IPv4 packet: version nibble 4, destination at offset 16 (RFC 791), then payload.</summary>
        static byte[] Ipv4Packet(IPAddress destination, params byte[] payload)
        {
            byte[] packet = new byte[20 + payload.Length];
            packet[0] = 0x45;   // version 4, IHL 5
            destination.GetAddressBytes().CopyTo(packet, 16);
            payload.CopyTo(packet, 20);
            return packet;
        }

        /// <summary>A minimal IPv6 packet: version nibble 6, destination at offset 24 (RFC 8200), then payload.</summary>
        static byte[] Ipv6Packet(IPAddress destination, params byte[] payload)
        {
            byte[] packet = new byte[40 + payload.Length];
            packet[0] = 0x60;   // version 6
            destination.GetAddressBytes().CopyTo(packet, 24);
            payload.CopyTo(packet, 40);
            return packet;
        }

        /// <summary>An <see cref="IEthernetChannel"/> that records frames written out and lets the test raise inbound frames.</summary>
        sealed class CaptureEthernetChannel : IEthernetChannel
        {
            public List<byte[]> Written { get; } = new();
            public int Mtu { get; set; } = 1500;
            public LinkMedium Medium => LinkMedium.Ethernet;
            public int MaxHeaderLength => EthernetFrame.HeaderLength;
            public bool RequiresLinkAddressResolution => true;
            public ReadOnlyMemory<byte> LinkAddress { get; set; }
            public bool Disposed { get; private set; }
            public event Action<ReadOnlyMemory<byte>>? InboundFrame;

            public ValueTask WriteFrameAsync(ReadOnlyMemory<byte> ethernetFrame, CancellationToken cancellationToken = default)
            {
                Written.Add(ethernetFrame.ToArray());
                return default;
            }

            public void RaiseInbound(ReadOnlyMemory<byte> frame) => InboundFrame?.Invoke(frame);

            public ValueTask DisposeAsync()
            {
                Disposed = true;
                InboundFrame = null;
                return default;
            }
        }

        /// <summary>A fake neighbor resolver backed by a fixed IP → MAC map; returns null for anything unmapped.</summary>
        sealed class MapNeighborResolver : INeighborResolver
        {
            readonly Dictionary<string, MacAddress> _map = new();

            /// <summary>Every address a resolve was attempted for — so a test can assert which next hop was chosen.</summary>
            public List<IPAddress> Asked { get; } = new();

            public void Add(IPAddress ip, MacAddress mac) => _map[ip.ToString()] = mac;

            public ValueTask<ReadOnlyMemory<byte>?> ResolveAsync(IPAddress nextHop, CancellationToken cancellationToken = default)
            {
                Asked.Add(nextHop);
                if (_map.TryGetValue(nextHop.ToString(), out MacAddress mac))
                {
                    ReadOnlyMemory<byte> bytes = mac.ToArray();
                    return new ValueTask<ReadOnlyMemory<byte>?>(bytes);
                }
                return new ValueTask<ReadOnlyMemory<byte>?>((ReadOnlyMemory<byte>?)null);
            }
        }
    }
}
