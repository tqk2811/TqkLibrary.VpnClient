using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Threading;
using System.Threading.Channels;
using System.Threading.Tasks;
using TqkLibrary.VpnClient.Abstractions.Channels.Enums;
using TqkLibrary.VpnClient.Abstractions.Channels.Interfaces;
using TqkLibrary.VpnClient.Abstractions.Drivers.Models;
using TqkLibrary.VpnClient.Ethernet;
using TqkLibrary.VpnClient.Ethernet.Models;
using Xunit;

namespace TqkLibrary.VpnClient.Ethernet.Tests
{
    public class EthernetAdapterTests
    {
        static readonly MacAddress MacA = MacAddress.Parse("02:00:00:00:00:0a");
        static readonly MacAddress MacB = MacAddress.Parse("02:00:00:00:00:0b");
        static readonly MacAddress MacC = MacAddress.Parse("02:00:00:00:00:0c");
        static readonly MacAddress ServerMac = MacAddress.Parse("02:00:00:00:00:01");

        static readonly IPAddress IpA = IPAddress.Parse("10.0.0.10");
        static readonly IPAddress IpB = IPAddress.Parse("10.0.0.11");
        static readonly IPAddress IpC = IPAddress.Parse("10.0.0.12");

        static ArpResolverOptions FastArp => new ArpResolverOptions(cacheTtl: TimeSpan.FromSeconds(20), requestTimeout: TimeSpan.FromMilliseconds(200), maxAttempts: 5);

        // ---- Composition ----

        [Fact]
        public async Task AddHost_AttachesPort_AndReturnsIndependentChannelPerHost()
        {
            await using var adapter = new EthernetAdapter();

            EthernetAdapter.EthernetHostHandle a = AddArpHost(adapter, MacA, IpA);
            EthernetAdapter.EthernetHostHandle b = AddArpHost(adapter, MacB, IpB);

            Assert.Equal(2, adapter.HostCount);
            Assert.Equal(2, adapter.Switch.PortCount);
            Assert.NotSame(a.Channel, b.Channel);        // each host its own IPacketChannel
            Assert.Same(a, adapter.GetHost(MacA));
            Assert.Equal(MacB, b.Mac);
            Assert.Equal(LinkMedium.Ip, a.Channel.Medium);                 // the stack only ever sees L3
            Assert.Equal(1500 - EthernetFrame.HeaderLength, a.Channel.Mtu); // switch MTU − Ethernet header
        }

        [Fact]
        public async Task AddHost_DuplicateMac_Throws()
        {
            await using var adapter = new EthernetAdapter();
            AddArpHost(adapter, MacA, IpA);

            Assert.Throws<ArgumentException>(() => AddArpHost(adapter, MacA, IpA));
        }

        [Fact]
        public async Task RemoveHostAsync_DetachesPort_AndDisposesResolver()
        {
            await using var adapter = new EthernetAdapter();

            DisposeTrackingResolver tracked = null!;
            EthernetAdapter.EthernetHostHandle a = adapter.AddHost(MacA, port =>
            {
                tracked = new DisposeTrackingResolver(new ArpResolver(MacA, IpA, port, FastArp));
                return new EthernetHostSpec(tracked) { NonIpFrameHandler = tracked.Inner.HandleInboundFrame };
            });
            EthernetAdapter.EthernetHostHandle b = AddArpHost(adapter, MacB, IpB);
            Assert.Equal(2, adapter.Switch.PortCount);

            bool removed = await adapter.RemoveHostAsync(MacA);

            Assert.True(removed);
            Assert.Equal(1, adapter.HostCount);
            Assert.Equal(1, adapter.Switch.PortCount);        // A's switch port detached
            Assert.Null(adapter.GetHost(MacA));
            Assert.True(tracked.Disposed);                    // owned resolver disposed with the host
            Assert.False(await adapter.RemoveHostAsync(MacA)); // idempotent
            GC.KeepAlive(b);
        }

        // ---- Data plane: independent channels carry IP between hosts (real ARP under the hood) ----

        [Fact]
        public async Task TwoHosts_RealArp_DeliversIpPacketBetweenChannels()
        {
            await using var adapter = new EthernetAdapter();
            EthernetAdapter.EthernetHostHandle a = AddArpHost(adapter, MacA, IpA);
            EthernetAdapter.EthernetHostHandle b = AddArpHost(adapter, MacB, IpB);

            var bInbox = new InboundCollector(b.Channel);

            // A sends an IPv4 packet to B's address. The host's egress resolves B's MAC by REAL ARP across the switch
            // (broadcast request → B answers), wraps the frame, and the switch floods/forwards it to B's channel.
            byte[] packet = Ipv4Packet(IpA, IpB, 1, 2, 3, 4);
            await a.Channel.WriteIpPacketAsync(packet);

            byte[] got = await bInbox.WaitForOneAsync();
            Assert.Equal(packet, got);
        }

        [Fact]
        public async Task ThreeHosts_EachChannelIndependent_OnlyTargetReceives()
        {
            await using var adapter = new EthernetAdapter();
            EthernetAdapter.EthernetHostHandle a = AddArpHost(adapter, MacA, IpA);
            EthernetAdapter.EthernetHostHandle b = AddArpHost(adapter, MacB, IpB);
            EthernetAdapter.EthernetHostHandle c = AddArpHost(adapter, MacC, IpC);

            var bInbox = new InboundCollector(b.Channel);
            var cInbox = new InboundCollector(c.Channel);

            // Warm the FDB: both A and C ARP for B's address (A learns B; the switch learns A, B and C).
            await a.Resolver.ResolveAsync(IpB);
            await c.Resolver.ResolveAsync(IpB);

            byte[] toB = Ipv4Packet(IpA, IpB, 9, 9);
            await a.Channel.WriteIpPacketAsync(toB);

            byte[] gotB = await bInbox.WaitForOneAsync();
            Assert.Equal(toB, gotB);
            await Task.Delay(60);
            Assert.Empty(cInbox.Snapshot());   // a learned-unicast to B never reaches C's channel
        }

        // ---- Data plane: DHCP lease per host from a stub server (real DHCPv4 over the adapter) ----

        [Fact]
        public async Task Host_WithDhcpConfigurator_LeasesAddressFromServerOnSwitch()
        {
            await using var adapter = new EthernetAdapter();

            // A throwaway DHCP server on its own switch port.
            IEthernetChannel serverPort = adapter.Switch.ConnectHost(ServerMac);
            await using var server = new StubDhcpServer(serverPort);

            // A host whose IpPacketHandler feeds inbound IPv4 (DHCP rides broadcast IPv4) to its DHCP client.
            EthernetAdapter.EthernetHostHandle host = adapter.AddHost(MacA, port =>
            {
                var arp = new ArpResolver(MacA, StubDhcpServer.Offered, port, FastArp);
                var dhcp = new DhcpV4Configurator(MacA, port, new DhcpV4ConfiguratorOptions(replyTimeout: TimeSpan.FromMilliseconds(200), maxAttempts: 5));
                return new EthernetHostSpec(arp)
                {
                    Configurator = dhcp,
                    NonIpFrameHandler = arp.HandleInboundFrame,
                    IpPacketHandler = dhcp.HandleInboundFrame,
                };
            });

            TunnelConfig config = await host.ConfigureAsync();

            Assert.Equal(StubDhcpServer.Offered, config.AssignedAddress);
            Assert.Equal(24, config.PrefixLength);
            Assert.Equal(StubDhcpServer.Dns, config.DnsServers.Single());
        }

        [Fact]
        public async Task ConfigureAsync_WithoutConfigurator_Throws()
        {
            await using var adapter = new EthernetAdapter();
            EthernetAdapter.EthernetHostHandle a = AddArpHost(adapter, MacA, IpA);

            await Assert.ThrowsAsync<InvalidOperationException>(async () => await a.ConfigureAsync());
        }

        // ---- Backpressure: a slow consumer drops oldest, never stalls the switch deliver path ----

        [Fact]
        public async Task Backpressure_DropOldest_BoundsQueue_NeverBlocksProducer()
        {
            // Feed an inner channel far past the queue capacity while the consumer is blocked; the producer (the
            // synchronous switch deliver path) must never block and the queue must stay bounded.
            var inner = new ManualPacketChannel();
            var gate = new SemaphoreSlim(0);
            var received = new List<byte[]>();
            await using var channel = new BackpressuredPacketChannel(inner, capacity: 4, fullMode: BoundedChannelFullMode.DropOldest);
            channel.InboundIpPacket += p =>
            {
                gate.Wait();   // hold the pump so the queue overflows
                lock (received) received.Add(p.ToArray());
            };

            for (int i = 0; i < 100; i++)
                inner.RaiseInbound(new byte[] { (byte)i });   // returns immediately even though the pump is blocked

            gate.Release(100);
            await Task.Delay(150);

            lock (received)
            {
                // At most capacity + 1 in-flight (one already handed to the blocked subscriber) survive the overflow.
                Assert.True(received.Count <= 5, $"expected <=5 survivors, got {received.Count}");
                Assert.NotEmpty(received);
                // DropOldest keeps the freshest packets: the very last produced byte (99) must have survived.
                Assert.Contains(received, p => p.Length == 1 && p[0] == 99);
            }
        }

        [Fact]
        public async Task Backpressure_Egress_PassesThroughToInner()
        {
            var inner = new ManualPacketChannel();
            await using var channel = new BackpressuredPacketChannel(inner);

            byte[] packet = { 0x45, 1, 2, 3 };
            await channel.WriteIpPacketAsync(packet);

            Assert.Equal(packet, inner.Written.Single());
        }

        // ---- Teardown ----

        [Fact]
        public async Task DisposeAdapter_DisposesAllHosts_AndOwnedSwitch()
        {
            var adapter = new EthernetAdapter();
            EthernetAdapter.EthernetHostHandle a = AddArpHost(adapter, MacA, IpA);
            AddArpHost(adapter, MacB, IpB);
            Assert.Equal(2, adapter.Switch.PortCount);
            EthernetSwitch sw = adapter.Switch;

            await adapter.DisposeAsync();

            Assert.Equal(0, adapter.HostCount);
            Assert.Equal(0, sw.PortCount);   // owned switch fully torn down
            // Writing to a disposed host channel is a silent no-op.
            await a.Channel.WriteIpPacketAsync(Ipv4Packet(IpA, IpB, 1));
        }

        [Fact]
        public async Task ExternalSwitch_NotOwned_SurvivesAdapterDispose()
        {
            await using var sw = new EthernetSwitch();
            var adapter = new EthernetAdapter(sw, ownsSwitch: false);
            AddArpHost(adapter, MacA, IpA);

            await adapter.DisposeAsync();

            // The adapter detached its host's port but left the externally owned switch usable.
            Assert.Equal(0, sw.PortCount);
            IEthernetChannel port = sw.ConnectHost(MacB);
            Assert.Equal(1, sw.PortCount);
            await port.DisposeAsync();
        }

        // ---- Helpers ----

        static EthernetAdapter.EthernetHostHandle AddArpHost(EthernetAdapter adapter, MacAddress mac, IPAddress ip)
            => adapter.AddHost(mac, port =>
            {
                var arp = new ArpResolver(mac, ip, port, FastArp);
                return new EthernetHostSpec(arp) { NonIpFrameHandler = arp.HandleInboundFrame };
            });

        /// <summary>A minimal IPv4 packet: version 4, source @ offset 12, destination @ offset 16, then payload.</summary>
        static byte[] Ipv4Packet(IPAddress source, IPAddress destination, params byte[] payload)
        {
            byte[] packet = new byte[20 + payload.Length];
            packet[0] = 0x45;
            source.GetAddressBytes().CopyTo(packet, 12);
            destination.GetAddressBytes().CopyTo(packet, 16);
            payload.CopyTo(packet, 20);
            return packet;
        }

        /// <summary>Collects inbound IP packets raised on a channel, with an async wait helper.</summary>
        sealed class InboundCollector
        {
            readonly List<byte[]> _packets = new();

            public InboundCollector(IPacketChannel channel) => channel.InboundIpPacket += p =>
            {
                lock (_packets) _packets.Add(p.ToArray());
            };

            public List<byte[]> Snapshot()
            {
                lock (_packets) return new List<byte[]>(_packets);
            }

            public async Task<byte[]> WaitForOneAsync()
            {
                for (int i = 0; i < 200; i++)
                {
                    lock (_packets)
                        if (_packets.Count > 0) return _packets[0];
                    await Task.Delay(5);
                }
                throw new TimeoutException("No inbound IP packet arrived.");
            }
        }

        /// <summary>A bare <see cref="IPacketChannel"/> the test drives directly (records egress, raises inbound).</summary>
        sealed class ManualPacketChannel : IPacketChannel
        {
            public List<byte[]> Written { get; } = new();
            public LinkMedium Medium => LinkMedium.Ip;
            public int Mtu => 1400;
            public int MaxHeaderLength => 0;
            public bool RequiresLinkAddressResolution => false;
            public event Action<ReadOnlyMemory<byte>>? InboundIpPacket;

            public void RaiseInbound(ReadOnlyMemory<byte> packet) => InboundIpPacket?.Invoke(packet);

            public ValueTask WriteIpPacketAsync(ReadOnlyMemory<byte> ipPacket, CancellationToken cancellationToken = default)
            {
                lock (Written) Written.Add(ipPacket.ToArray());
                return default;
            }

            public ValueTask DisposeAsync() { InboundIpPacket = null; return default; }
        }

        /// <summary>Wraps an <see cref="ArpResolver"/> to flag whether the adapter disposed it (ownership test).</summary>
        sealed class DisposeTrackingResolver : INeighborResolver, IAsyncDisposable
        {
            public DisposeTrackingResolver(ArpResolver inner) => Inner = inner;

            public ArpResolver Inner { get; }
            public bool Disposed { get; private set; }

            public ValueTask<ReadOnlyMemory<byte>?> ResolveAsync(IPAddress nextHop, CancellationToken cancellationToken = default)
                => Inner.ResolveAsync(nextHop, cancellationToken);

            public async ValueTask DisposeAsync()
            {
                Disposed = true;
                await Inner.DisposeAsync();
            }
        }

        /// <summary>A throwaway DHCP server bound to a switch port: OFFER for DISCOVER, ACK for REQUEST.</summary>
        sealed class StubDhcpServer : IAsyncDisposable
        {
            public static readonly IPAddress Offered = IPAddress.Parse("10.0.0.50");
            public static readonly IPAddress ServerId = IPAddress.Parse("10.0.0.1");
            public static readonly IPAddress Mask = IPAddress.Parse("255.255.255.0");
            public static readonly IPAddress Router = IPAddress.Parse("10.0.0.1");
            public static readonly IPAddress Dns = IPAddress.Parse("8.8.8.8");

            readonly IEthernetChannel _port;

            public StubDhcpServer(IEthernetChannel port)
            {
                _port = port;
                _port.InboundFrame += OnFrame;
            }

            void OnFrame(ReadOnlyMemory<byte> frame)
            {
                if (frame.Length < EthernetFrame.HeaderLength || EthernetFrame.EtherType(frame.Span) != EthernetFrame.EtherTypeIpv4)
                    return;
                ReadOnlyMemory<byte> ip = EthernetFrame.Payload(frame);
                ReadOnlySpan<byte> span = ip.Span;
                if ((byte)(span[0] >> 4) != 4 || span[9] != 17)
                    return;
                int ihl = (span[0] & 0x0F) * 4;
                int destPort = (span[ihl + 2] << 8) | span[ihl + 3];
                if (destPort != DhcpV4Packet.ServerPort)
                    return;
                byte[] dhcp = ip.Slice(ihl + 8).ToArray();
                if (dhcp.Length < DhcpV4Packet.HeaderLength + 4 || dhcp[0] != DhcpV4Packet.OpBootRequest
                    || !DhcpV4Options.HasMagicCookie(DhcpV4Packet.OptionField(dhcp).Span))
                    return;
                uint xid = DhcpV4Packet.Xid(dhcp);
                byte type = DhcpV4Options.ReadMessageType(DhcpV4Packet.OptionField(dhcp).Span);
                byte replyType = type == DhcpV4Options.MessageDiscover ? DhcpV4Options.MessageOffer
                    : type == DhcpV4Options.MessageRequest ? DhcpV4Options.MessageAck
                    : (byte)0;
                if (replyType == 0)
                    return;
                _ = _port.WriteFrameAsync(BuildServerReply(replyType, xid));
            }

            static byte[] BuildServerReply(byte messageType, uint xid)
            {
                byte[] options = new byte[128];
                int pos = DhcpV4Options.WriteMagicCookie(options, 0);
                pos = DhcpV4Options.WriteOption(options, pos, DhcpV4Options.CodeMessageType, messageType);
                pos = DhcpV4Options.WriteOption(options, pos, DhcpV4Options.CodeServerId, ServerId);
                pos = DhcpV4Options.WriteOption(options, pos, DhcpV4Options.CodeSubnetMask, Mask);
                pos = DhcpV4Options.WriteOption(options, pos, DhcpV4Options.CodeRouter, Router);
                pos = DhcpV4Options.WriteOption(options, pos, DhcpV4Options.CodeDnsServer, Dns.GetAddressBytes());
                pos = DhcpV4Options.WriteEnd(options, pos);

                byte[] msg = DhcpV4Packet.Build(xid, MacA, requestedCiaddr: null, broadcast: false, options.AsSpan(0, pos));
                msg[0] = DhcpV4Packet.OpBootReply;
                Offered.GetAddressBytes().CopyTo(msg, 16);   // yiaddr @ offset 16

                byte[] udpIp = DhcpV4Packet.BuildUdpIpv4(ServerId, IPAddress.Broadcast,
                    DhcpV4Packet.ServerPort, DhcpV4Packet.ClientPort, msg);
                return EthernetFrame.Build(MacAddress.Broadcast, ServerMac, EthernetFrame.EtherTypeIpv4, udpIp);
            }

            public ValueTask DisposeAsync()
            {
                _port.InboundFrame -= OnFrame;
                return default;
            }
        }
    }
}
