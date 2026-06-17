using System;
using System.Linq;
using System.Net;
using System.Threading.Tasks;
using TqkLibrary.VpnClient.Abstractions.Channels.Interfaces;
using TqkLibrary.VpnClient.Abstractions.Drivers.Enums;
using TqkLibrary.VpnClient.Abstractions.Drivers.Interfaces;
using TqkLibrary.VpnClient.Abstractions.Drivers.Models;
using TqkLibrary.VpnClient.Ethernet;
using TqkLibrary.VpnClient.Ethernet.Models;
using Xunit;

namespace TqkLibrary.VpnClient.Ethernet.Tests
{
    /// <summary>
    /// L2.8 — the multi-host session model: N <see cref="VirtualHost"/> = N "machines on the LAN", each surfaced as an
    /// <see cref="IVpnSession"/> (<see cref="EthernetHostSession"/>) on one shared in-memory switch
    /// (<see cref="MultiHostSession"/> over an <see cref="EthernetAdapter"/>). Pure offline — no network.
    /// </summary>
    public class MultiHostSessionTests
    {
        static readonly MacAddress MacA = MacAddress.Parse("02:00:00:00:00:0a");
        static readonly MacAddress MacB = MacAddress.Parse("02:00:00:00:00:0b");
        static readonly MacAddress ServerMac = MacAddress.Parse("02:00:00:00:00:01");

        static readonly IPAddress IpA = IPAddress.Parse("10.0.0.10");
        static readonly IPAddress IpB = IPAddress.Parse("10.0.0.11");

        static ArpResolverOptions FastArp => new ArpResolverOptions(cacheTtl: TimeSpan.FromSeconds(20), requestTimeout: TimeSpan.FromMilliseconds(200), maxAttempts: 5);

        // ---- The model: it self-describes as an L2 broadcast domain ----

        [Fact]
        public async Task MultiHostSession_DescribesAnL2BroadcastDomain()
        {
            await using var session = new MultiHostSession(new EthernetAdapter());

            Assert.Equal(VpnLinkLayer.L2Ethernet, session.LinkLayer);
            Assert.Equal(MultiHostModel.L2BroadcastDomain, session.MultiHostModel);
            Assert.Equal(0, session.StationCount);
            Assert.Empty(session.Sessions);
        }

        // ---- N stations = N IVpnSession, each its own MAC/IP/channel/config ----

        [Fact]
        public async Task AddStation_EachStationIsAnIndependentVpnSession()
        {
            await using var session = new MultiHostSession(new EthernetAdapter());

            EthernetHostSession a = AddArpStation(session, MacA, IpA);
            EthernetHostSession b = AddArpStation(session, MacB, IpB);

            Assert.Equal(2, session.StationCount);
            Assert.IsAssignableFrom<IVpnSession>(a);
            Assert.NotSame(a.PacketChannel, b.PacketChannel);     // each station its own L3 channel
            Assert.Equal(MacA, a.Mac);
            Assert.Equal(IpA, a.Config.AssignedAddress);
            Assert.Same(a, session.GetStation(MacA));
            Assert.Equal(2, session.Sessions.Count);
            Assert.Contains(b, session.Sessions);
            // The station shares the one switch fabric of the broadcast domain.
            Assert.Equal(2, session.Adapter.Switch.PortCount);
        }

        // ---- Data plane: two stations exchange IP over the shared switch (real ARP) ----

        [Fact]
        public async Task TwoStations_ExchangeIpOverSharedBroadcastDomain()
        {
            await using var session = new MultiHostSession(new EthernetAdapter());
            EthernetHostSession a = AddArpStation(session, MacA, IpA);
            EthernetHostSession b = AddArpStation(session, MacB, IpB);

            var bInbox = new InboundCollector(b.PacketChannel);

            byte[] packet = Ipv4Packet(IpA, IpB, 7, 7, 7);
            await a.PacketChannel.WriteIpPacketAsync(packet);

            byte[] got = await bInbox.WaitForOneAsync();
            Assert.Equal(packet, got);
        }

        // ---- A station can lease its address via DHCP (multi-host equivalent of single-host bind) ----

        [Fact]
        public async Task AddStationAsync_LeasesAddressFromServerOnTheSwitch()
        {
            await using var session = new MultiHostSession(new EthernetAdapter());

            IEthernetChannel serverPort = session.Adapter.Switch.ConnectHost(ServerMac);
            await using var server = new StubDhcpServer(serverPort);

            EthernetHostSession station = await session.AddStationAsync(MacA, port =>
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

            Assert.Equal(StubDhcpServer.Offered, station.Config.AssignedAddress);
            Assert.Equal(24, station.Config.PrefixLength);
            Assert.Equal(1, session.StationCount);
            Assert.Same(station, session.GetStation(MacA));
        }

        [Fact]
        public async Task AddStationAsync_WithoutConfigurator_ThrowsAndDoesNotLeaveAStrayStation()
        {
            await using var session = new MultiHostSession(new EthernetAdapter());

            await Assert.ThrowsAsync<InvalidOperationException>(async () =>
                await session.AddStationAsync(MacA, port =>
                {
                    var arp = new ArpResolver(MacA, IpA, port, FastArp);
                    return new EthernetHostSpec(arp) { NonIpFrameHandler = arp.HandleInboundFrame };
                }));

            Assert.Equal(0, session.StationCount);
            Assert.Equal(0, session.Adapter.Switch.PortCount);   // the failed station's port was detached
        }

        // ---- Lifecycle ----

        [Fact]
        public async Task RemoveStationAsync_DetachesAndDisposesTheStation()
        {
            await using var session = new MultiHostSession(new EthernetAdapter());
            EthernetHostSession a = AddArpStation(session, MacA, IpA);
            AddArpStation(session, MacB, IpB);

            bool removed = await session.RemoveStationAsync(MacA);

            Assert.True(removed);
            Assert.Equal(1, session.StationCount);
            Assert.Null(session.GetStation(MacA));
            Assert.Equal(1, session.Adapter.Switch.PortCount);
            Assert.False(await session.RemoveStationAsync(MacA));   // idempotent
        }

        [Fact]
        public async Task Dispose_TearsDownEveryStationAndTheSwitch()
        {
            var session = new MultiHostSession(new EthernetAdapter());
            AddArpStation(session, MacA, IpA);
            AddArpStation(session, MacB, IpB);
            EthernetSwitch sw = session.Adapter.Switch;

            await session.DisposeAsync();

            Assert.Equal(0, session.StationCount);
            Assert.Equal(0, sw.PortCount);   // owned adapter (and its switch) fully torn down
        }

        [Fact]
        public async Task NotOwningAdapter_LeavesItUsableAfterSessionDispose()
        {
            await using var adapter = new EthernetAdapter();
            var session = new MultiHostSession(adapter, ownsAdapter: false);
            AddArpStation(session, MacA, IpA);

            await session.DisposeAsync();

            // The session released its bookkeeping but left the externally owned adapter (its host) intact.
            Assert.Equal(0, session.StationCount);
            Assert.Equal(1, adapter.HostCount);
        }

        // ---- EthernetHostSession ownership ----

        [Fact]
        public async Task EthernetHostSession_OwningHandle_DisposesItOnDispose()
        {
            await using var adapter = new EthernetAdapter();
            EthernetAdapter.EthernetHostHandle handle = adapter.AddHost(MacA, port =>
            {
                var arp = new ArpResolver(MacA, IpA, port, FastArp);
                return new EthernetHostSpec(arp) { NonIpFrameHandler = arp.HandleInboundFrame };
            });
            var hostSession = new EthernetHostSession(handle, new TunnelConfig { AssignedAddress = IpA }, ownsHandle: true);
            Assert.Equal(1, adapter.Switch.PortCount);

            await hostSession.DisposeAsync();

            Assert.Equal(0, adapter.Switch.PortCount);   // owned handle disposed → its switch port detached
        }

        // ---- Helpers ----

        static EthernetHostSession AddArpStation(MultiHostSession session, MacAddress mac, IPAddress ip)
            => session.AddStation(mac, port =>
            {
                var arp = new ArpResolver(mac, ip, port, FastArp);
                return new EthernetHostSpec(arp) { NonIpFrameHandler = arp.HandleInboundFrame };
            }, new TunnelConfig { AssignedAddress = ip, PrefixLength = 24 });

        static byte[] Ipv4Packet(IPAddress source, IPAddress destination, params byte[] payload)
        {
            byte[] packet = new byte[20 + payload.Length];
            packet[0] = 0x45;
            source.GetAddressBytes().CopyTo(packet, 12);
            destination.GetAddressBytes().CopyTo(packet, 16);
            payload.CopyTo(packet, 20);
            return packet;
        }

        sealed class InboundCollector
        {
            readonly System.Collections.Generic.List<byte[]> _packets = new();

            public InboundCollector(IPacketChannel channel) => channel.InboundIpPacket += p =>
            {
                lock (_packets) _packets.Add(p.ToArray());
            };

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
