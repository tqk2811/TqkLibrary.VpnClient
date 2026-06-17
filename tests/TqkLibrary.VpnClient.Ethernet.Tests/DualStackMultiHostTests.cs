using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Net.Sockets;
using System.Threading;
using System.Threading.Tasks;
using TqkLibrary.VpnClient.Abstractions.Channels.Enums;
using TqkLibrary.VpnClient.Abstractions.Channels.Interfaces;
using TqkLibrary.VpnClient.Abstractions.Drivers.Enums;
using TqkLibrary.VpnClient.Abstractions.Drivers.Models;
using TqkLibrary.VpnClient.Ethernet;
using TqkLibrary.VpnClient.Ethernet.Models;
using Xunit;

namespace TqkLibrary.VpnClient.Ethernet.Tests
{
    /// <summary>
    /// L2.9 — the close-out of the L2 layer: multiple hosts that each speak BOTH IPv4 and IPv6 on one in-memory
    /// broadcast domain. Hosts resolve each other cross-family (ARP for v4, NDISC for v6) through a
    /// <see cref="DualStackNeighborResolver"/>, and a station configures both families at once (DHCPv4 lease +
    /// SLAAC/DHCPv6) through a <see cref="DualStackAddressConfigurator"/>. Pure offline — no real network.
    /// </summary>
    public class DualStackMultiHostTests
    {
        static readonly MacAddress MacA = MacAddress.Parse("02:00:00:00:00:0a");
        static readonly MacAddress MacB = MacAddress.Parse("02:00:00:00:00:0b");
        static readonly MacAddress MacC = MacAddress.Parse("02:00:00:00:00:0c");
        static readonly MacAddress ServerMac = MacAddress.Parse("02:00:00:00:00:01");

        static readonly IPAddress V4A = IPAddress.Parse("10.0.0.10");
        static readonly IPAddress V4B = IPAddress.Parse("10.0.0.11");
        static readonly IPAddress V4C = IPAddress.Parse("10.0.0.12");
        static readonly IPAddress V6A = IPAddress.Parse("fe80::a");
        static readonly IPAddress V6B = IPAddress.Parse("fe80::b");
        static readonly IPAddress V6C = IPAddress.Parse("fe80::c");

        static ArpResolverOptions FastArp => new ArpResolverOptions(cacheTtl: TimeSpan.FromSeconds(20), requestTimeout: TimeSpan.FromMilliseconds(200), maxAttempts: 5);
        static NdiscResolverOptions FastNdisc => new NdiscResolverOptions(requestTimeout: TimeSpan.FromMilliseconds(200), maxAttempts: 5);

        // ---- DualStackNeighborResolver routes by address family ----

        [Fact]
        public async Task DualStackResolver_RoutesByAddressFamily()
        {
            var v4 = new RecordingResolver(MacAddress.Parse("02:00:00:00:00:04"));
            var v6 = new RecordingResolver(MacAddress.Parse("02:00:00:00:00:06"));
            await using var dual = new DualStackNeighborResolver(v4, v6);

            ReadOnlyMemory<byte>? gotV4 = await dual.ResolveAsync(V4B);
            ReadOnlyMemory<byte>? gotV6 = await dual.ResolveAsync(V6B);

            Assert.Equal(AddressFamily.InterNetwork, v4.LastFamily);   // v4 next-hop hit the ARP resolver
            Assert.Equal(AddressFamily.InterNetworkV6, v6.LastFamily); // v6 next-hop hit the NDISC resolver
            Assert.Equal(MacAddress.Parse("02:00:00:00:00:04"), MacAddress.FromBytes(gotV4!.Value.Span));
            Assert.Equal(MacAddress.Parse("02:00:00:00:00:06"), MacAddress.FromBytes(gotV6!.Value.Span));
            Assert.Same(v4, dual.Ipv4);
            Assert.Same(v6, dual.Ipv6);
        }

        [Fact]
        public async Task DualStackResolver_DisposesInnerResolvers_WhenOwned()
        {
            var v4 = new RecordingResolver(MacA);
            var v6 = new RecordingResolver(MacA);
            var dual = new DualStackNeighborResolver(v4, v6);

            await dual.DisposeAsync();

            Assert.True(v4.Disposed);
            Assert.True(v6.Disposed);
        }

        [Fact]
        public async Task DualStackResolver_LeavesInnerResolvers_WhenNotOwned()
        {
            var v4 = new RecordingResolver(MacA);
            var v6 = new RecordingResolver(MacA);
            var dual = new DualStackNeighborResolver(v4, v6, ownsInnerResolvers: false);

            await dual.DisposeAsync();

            Assert.False(v4.Disposed);
            Assert.False(v6.Disposed);
        }

        // ---- Two dual-stack hosts exchange BOTH families over the same switch (real ARP + real NDISC) ----

        [Fact]
        public async Task TwoDualStackHosts_ExchangeV4AndV6_OverSharedBroadcastDomain()
        {
            await using var adapter = new EthernetAdapter();
            EthernetAdapter.EthernetHostHandle a = AddDualStackHost(adapter, MacA, V4A, V6A);
            EthernetAdapter.EthernetHostHandle b = AddDualStackHost(adapter, MacB, V4B, V6B);

            var bInbox = new InboundCollector(b.Channel);

            // A → B over IPv4: egress resolves B's MAC by REAL ARP (broadcast request → B answers) across the switch.
            byte[] v4 = Ipv4Packet(V4A, V4B, 1, 2, 3);
            await a.Channel.WriteIpPacketAsync(v4);
            Assert.Equal(v4, await bInbox.WaitForDataAsync());

            // A → B over IPv6: egress resolves B's MAC by REAL NDISC (NS to solicited-node multicast → B answers NA).
            byte[] v6 = Ipv6Packet(V6A, V6B, 4, 5, 6);
            await a.Channel.WriteIpPacketAsync(v6);
            Assert.Equal(v6, await bInbox.WaitForDataAsync(after: v4));
        }

        // ---- Three dual-stack hosts: cross-family resolution, learned-unicast isolation per family ----

        [Fact]
        public async Task ThreeDualStackHosts_CrossFamilyResolution_OnlyTargetReceives()
        {
            await using var adapter = new EthernetAdapter();
            EthernetAdapter.EthernetHostHandle a = AddDualStackHost(adapter, MacA, V4A, V6A);
            EthernetAdapter.EthernetHostHandle b = AddDualStackHost(adapter, MacB, V4B, V6B);
            EthernetAdapter.EthernetHostHandle c = AddDualStackHost(adapter, MacC, V4C, V6C);

            var bInbox = new InboundCollector(b.Channel);
            var cInbox = new InboundCollector(c.Channel);

            // A resolves B over v6 and C over v4 — the two families use different resolvers but the same switch fabric.
            byte[] v6ToB = Ipv6Packet(V6A, V6B, 7, 7);
            await a.Channel.WriteIpPacketAsync(v6ToB);
            Assert.Equal(v6ToB, await bInbox.WaitForDataAsync());

            byte[] v4ToC = Ipv4Packet(V4A, V4C, 8, 8);
            await a.Channel.WriteIpPacketAsync(v4ToC);
            Assert.Equal(v4ToC, await cInbox.WaitForDataAsync());

            // The v4 datagram destined for C never reached B; B only saw its own v6 packet (learned-unicast isolation).
            await Task.Delay(60);
            Assert.DoesNotContain(bInbox.Snapshot(), p => p.SequenceEqual(v4ToC));
            Assert.DoesNotContain(cInbox.Snapshot(), p => p.SequenceEqual(v6ToB));
        }

        // ---- A dual-stack station configures BOTH families at once (DHCPv4 lease + SLAAC/DHCPv6) ----

        [Fact]
        public async Task DualStackStation_LeasesV4AndConfiguresV6_FromOneStubServer()
        {
            await using var adapter = new EthernetAdapter();

            // One stub on its own port plays DHCPv4 server, IPv6 router (RA) AND DHCPv6 server.
            IEthernetChannel serverPort = adapter.Switch.ConnectHost(ServerMac);
            await using var server = new StubDualStackServer(serverPort);

            EthernetAdapter.EthernetHostHandle host = AddDualStackConfiguredHost(adapter, MacA);

            TunnelConfig config = await host.ConfigureAsync();

            // IPv4 came from DHCPv4.
            Assert.Equal(StubDualStackServer.OfferedV4, config.AssignedAddress);
            Assert.Equal(24, config.PrefixLength);
            // IPv6 came from SLAAC (autonomous /64 prefix in the RA + EUI-64 of MacA).
            Assert.Equal(IPAddress.Parse("2001:db8:1234::ff:fe00:a"), config.AssignedAddressV6);
            Assert.Equal(64, config.PrefixLengthV6);
            // DNS from both families merged; both default routes present.
            Assert.Contains(StubDualStackServer.DnsV4, config.DnsServers);
            Assert.Contains(StubDualStackServer.DnsV6, config.DnsServers);
            Assert.Contains("0.0.0.0/0 " + StubDualStackServer.RouterV4, config.Routes);
            Assert.Contains("::/0 " + StubDualStackServer.RouterLla, config.Routes);
        }

        // ---- The model self-describes the broadcast domain via MultiHostSession (L2.8) carrying dual-stack stations ----

        [Fact]
        public async Task MultiHostSession_OfDualStackStations_ExchangesBothFamilies()
        {
            await using var session = new MultiHostSession(new EthernetAdapter());
            Assert.Equal(VpnLinkLayer.L2Ethernet, session.LinkLayer);
            Assert.Equal(MultiHostModel.L2BroadcastDomain, session.MultiHostModel);

            EthernetHostSession a = AddDualStackStation(session, MacA, V4A, V6A);
            EthernetHostSession b = AddDualStackStation(session, MacB, V4B, V6B);

            Assert.Equal(2, session.StationCount);
            Assert.Equal(V4A, a.Config.AssignedAddress);
            Assert.Equal(V6A, a.Config.AssignedAddressV6);

            var bInbox = new InboundCollector(b.PacketChannel);
            byte[] v6 = Ipv6Packet(V6A, V6B, 9, 9, 9);
            await a.PacketChannel.WriteIpPacketAsync(v6);
            Assert.Equal(v6, await bInbox.WaitForDataAsync());

            byte[] v4 = Ipv4Packet(V4A, V4B, 1, 1);
            await a.PacketChannel.WriteIpPacketAsync(v4);
            Assert.Equal(v4, await bInbox.WaitForDataAsync(after: v6));
        }

        // ---- DualStackAddressConfigurator merges both legs ----

        [Fact]
        public async Task DualStackConfigurator_MergesBothLegs_AndTakesSmallerMtu()
        {
            var v4 = new StubConfigurator(new TunnelConfig
            {
                AssignedAddress = V4A,
                PrefixLength = 24,
                Mtu = 1400,
                DnsServers = { IPAddress.Parse("8.8.8.8") },
                Routes = { "0.0.0.0/0 10.0.0.1" },
            });
            var v6 = new StubConfigurator(new TunnelConfig
            {
                AssignedAddressV6 = IPAddress.Parse("2001:db8::1"),
                PrefixLengthV6 = 64,
                Mtu = 1280,
                DnsServers = { IPAddress.Parse("2001:4860:4860::8888") },
                Routes = { "::/0 fe80::1" },
            });
            await using var dual = new DualStackAddressConfigurator(v4, v6);

            TunnelConfig merged = await dual.ConfigureAsync();

            Assert.Equal(V4A, merged.AssignedAddress);
            Assert.Equal(24, merged.PrefixLength);
            Assert.Equal(IPAddress.Parse("2001:db8::1"), merged.AssignedAddressV6);
            Assert.Equal(64, merged.PrefixLengthV6);
            Assert.Equal(1280, merged.Mtu);                                   // min of the two
            Assert.Equal(2, merged.DnsServers.Count);                         // both families' DNS
            Assert.Equal(new[] { "0.0.0.0/0 10.0.0.1", "::/0 fe80::1" }, merged.Routes.ToArray());
        }

        [Fact]
        public async Task DualStackConfigurator_DisposesInnerConfigurators_WhenOwned()
        {
            var v4 = new StubConfigurator(new TunnelConfig());
            var v6 = new StubConfigurator(new TunnelConfig());
            var dual = new DualStackAddressConfigurator(v4, v6);

            await dual.DisposeAsync();

            Assert.True(v4.Disposed);
            Assert.True(v6.Disposed);
        }

        // ---- Helpers: composing dual-stack hosts/stations ----

        /// <summary>A static-address dual-stack host: ARP for v4, NDISC for v6, no configurator.</summary>
        static EthernetAdapter.EthernetHostHandle AddDualStackHost(EthernetAdapter adapter, MacAddress mac, IPAddress v4, IPAddress v6)
            => adapter.AddHost(mac, port =>
            {
                var arp = new ArpResolver(mac, v4, port, FastArp);
                var ndisc = new NdiscResolver(mac, v6, port, FastNdisc);
                var dual = new DualStackNeighborResolver(arp, ndisc);
                return new EthernetHostSpec(dual)
                {
                    NonIpFrameHandler = arp.HandleInboundFrame,    // ARP rides the non-IP seam
                    IpPacketHandler = ndisc.HandleInboundFrame,    // NDISC rides inside IPv6
                };
            });

        static EthernetHostSession AddDualStackStation(MultiHostSession session, MacAddress mac, IPAddress v4, IPAddress v6)
            => session.AddStation(mac, port =>
            {
                var arp = new ArpResolver(mac, v4, port, FastArp);
                var ndisc = new NdiscResolver(mac, v6, port, FastNdisc);
                var dual = new DualStackNeighborResolver(arp, ndisc);
                return new EthernetHostSpec(dual)
                {
                    NonIpFrameHandler = arp.HandleInboundFrame,
                    IpPacketHandler = ndisc.HandleInboundFrame,
                };
            }, new TunnelConfig { AssignedAddress = v4, PrefixLength = 24, AssignedAddressV6 = v6, PrefixLengthV6 = 64 });

        /// <summary>A dual-stack host that leases v4 by DHCPv4 and configures v6 by SLAAC/DHCPv6.</summary>
        static EthernetAdapter.EthernetHostHandle AddDualStackConfiguredHost(EthernetAdapter adapter, MacAddress mac)
            => adapter.AddHost(mac, port =>
            {
                var arp = new ArpResolver(mac, StubDualStackServer.OfferedV4, port, FastArp);
                var ndisc = new NdiscResolver(mac, StubDualStackServer.ClientLla, port, FastNdisc);
                var dualResolver = new DualStackNeighborResolver(arp, ndisc);

                var dhcp4 = new DhcpV4Configurator(mac, port, new DhcpV4ConfiguratorOptions(replyTimeout: TimeSpan.FromMilliseconds(200), maxAttempts: 5));
                var cfg6 = new Ipv6AddressConfigurator(mac, StubDualStackServer.ClientLla, port, ndisc,
                    new Ipv6AddressConfiguratorOptions(
                        routerAdvertisementTimeout: TimeSpan.FromMilliseconds(200),
                        routerSolicitationAttempts: 5,
                        dhcpReplyTimeout: TimeSpan.FromMilliseconds(200),
                        dhcpMaxAttempts: 5));
                var dualConfig = new DualStackAddressConfigurator(dhcp4, cfg6);

                return new EthernetHostSpec(dualResolver)
                {
                    Configurator = dualConfig,
                    NonIpFrameHandler = arp.HandleInboundFrame,
                    // NDISC (incl. RA), DHCPv4 and DHCPv6 all ride inside ordinary IP, so all three intercept inbound IP.
                    IpPacketHandler = p =>
                    {
                        ndisc.HandleInboundFrame(p);
                        dhcp4.HandleInboundFrame(p);
                        cfg6.HandleInboundFrame(p);
                    },
                };
            });

        static byte[] Ipv4Packet(IPAddress source, IPAddress destination, params byte[] payload)
        {
            byte[] packet = new byte[20 + payload.Length];
            packet[0] = 0x45;
            source.GetAddressBytes().CopyTo(packet, 12);    // RFC 791: src @ 12
            destination.GetAddressBytes().CopyTo(packet, 16); // dst @ 16
            payload.CopyTo(packet, 20);
            return packet;
        }

        /// <summary>A minimal IPv6 packet whose next-header is UDP (17), so the host does not mistake it for NDISC.</summary>
        static byte[] Ipv6Packet(IPAddress source, IPAddress destination, params byte[] payload)
        {
            byte[] packet = new byte[40 + payload.Length];
            packet[0] = 0x60;   // version 6
            packet[4] = (byte)(payload.Length >> 8);
            packet[5] = (byte)payload.Length;
            packet[6] = 17;     // next header = UDP
            packet[7] = 64;
            source.GetAddressBytes().CopyTo(packet, 8);     // RFC 8200: src @ 8
            destination.GetAddressBytes().CopyTo(packet, 24); // dst @ 24
            payload.CopyTo(packet, 40);
            return packet;
        }

        /// <summary>An <see cref="INeighborResolver"/> that records the family it was asked for and a fixed MAC answer.</summary>
        sealed class RecordingResolver : INeighborResolver, IAsyncDisposable
        {
            readonly MacAddress _answer;
            public RecordingResolver(MacAddress answer) => _answer = answer;
            public AddressFamily? LastFamily { get; private set; }
            public bool Disposed { get; private set; }

            public ValueTask<ReadOnlyMemory<byte>?> ResolveAsync(IPAddress nextHop, CancellationToken cancellationToken = default)
            {
                LastFamily = nextHop.AddressFamily;
                return new ValueTask<ReadOnlyMemory<byte>?>(_answer.ToArray());
            }

            public ValueTask DisposeAsync() { Disposed = true; return default; }
        }

        /// <summary>An <see cref="IAddressConfigurator"/> that returns a fixed config and flags disposal.</summary>
        sealed class StubConfigurator : IAddressConfigurator, IAsyncDisposable
        {
            readonly TunnelConfig _config;
            public StubConfigurator(TunnelConfig config) => _config = config;
            public bool Disposed { get; private set; }
            public ValueTask<TunnelConfig> ConfigureAsync(CancellationToken cancellationToken = default)
                => new ValueTask<TunnelConfig>(_config);
            public ValueTask DisposeAsync() { Disposed = true; return default; }
        }

        /// <summary>Collects inbound IP packets raised on a channel, ignoring NDISC/DHCP control packets.</summary>
        sealed class InboundCollector
        {
            readonly List<byte[]> _packets = new();

            public InboundCollector(IPacketChannel channel) => channel.InboundIpPacket += p =>
            {
                byte[] copy = p.ToArray();
                lock (_packets) _packets.Add(copy);
            };

            public List<byte[]> Snapshot()
            {
                lock (_packets) return new List<byte[]>(_packets);
            }

            /// <summary>Waits for a data packet that is NOT a control message (NDISC/DHCP), optionally one not equal to <paramref name="after"/>.</summary>
            public async Task<byte[]> WaitForDataAsync(byte[]? after = null)
            {
                for (int i = 0; i < 200; i++)
                {
                    lock (_packets)
                        foreach (byte[] p in _packets)
                            if (!IsControl(p) && (after is null || !p.SequenceEqual(after)))
                                return p;
                    await Task.Delay(5);
                }
                throw new TimeoutException("No inbound data packet arrived.");
            }

            static bool IsControl(byte[] p)
            {
                if (p.Length < 1)
                    return true;
                byte version = (byte)(p[0] >> 4);
                // ICMPv6 (NDISC) rides IPv6 with next-header 58; treat those as control.
                return version == 6 && p.Length >= 7 && p[6] == 58;
            }
        }

        /// <summary>
        /// A throwaway server on one switch port that plays three roles for a dual-stack client: a DHCPv4 server
        /// (OFFER/ACK), an IPv6 router (RA: Managed + autonomous /64), and a DHCPv6 server (ADVERTISE/REPLY for DNS).
        /// </summary>
        sealed class StubDualStackServer : IAsyncDisposable
        {
            public static readonly IPAddress OfferedV4 = IPAddress.Parse("10.0.0.50");
            public static readonly IPAddress ServerIdV4 = IPAddress.Parse("10.0.0.1");
            public static readonly IPAddress MaskV4 = IPAddress.Parse("255.255.255.0");
            public static readonly IPAddress RouterV4 = IPAddress.Parse("10.0.0.1");
            public static readonly IPAddress DnsV4 = IPAddress.Parse("8.8.8.8");

            public static readonly IPAddress ClientLla = IPAddress.Parse("fe80::a");
            public static readonly IPAddress RouterLla = IPAddress.Parse("fe80::1");
            public static readonly IPAddress ServerLla = IPAddress.Parse("fe80::1");
            public static readonly IPAddress PrefixV6 = IPAddress.Parse("2001:db8:1234::");
            public static readonly IPAddress DnsV6 = IPAddress.Parse("2001:4860:4860::8888");

            readonly IEthernetChannel _port;
            readonly MacAddress _clientMac = MacA;

            public StubDualStackServer(IEthernetChannel port)
            {
                _port = port;
                _port.InboundFrame += OnFrame;
            }

            void OnFrame(ReadOnlyMemory<byte> frame)
            {
                ReadOnlySpan<byte> fspan = frame.Span;
                if (fspan.Length < EthernetFrame.HeaderLength)
                    return;
                ushort etherType = EthernetFrame.EtherType(fspan);
                if (etherType == EthernetFrame.EtherTypeIpv4)
                    HandleIpv4(EthernetFrame.Payload(frame));
                else if (etherType == EthernetFrame.EtherTypeIpv6)
                    HandleIpv6(EthernetFrame.Payload(frame));
            }

            void HandleIpv4(ReadOnlyMemory<byte> ip)
            {
                ReadOnlySpan<byte> span = ip.Span;
                if (span.Length < 20 || (byte)(span[0] >> 4) != 4 || span[9] != 17)
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
                _ = _port.WriteFrameAsync(BuildDhcpV4Reply(replyType, xid));
            }

            void HandleIpv6(ReadOnlyMemory<byte> ip)
            {
                ReadOnlySpan<byte> p = ip.Span;
                if (p.Length < 48 || (byte)(p[0] >> 4) != 6)
                    return;

                if (p[6] == Icmpv6Ndisc.ProtocolNumber)
                {
                    ReadOnlySpan<byte> message = p.Slice(40);
                    if (Icmpv6Ndisc.IsNdisc(message) && Icmpv6Ndisc.Type(message) == Icmpv6Ndisc.TypeRouterSolicitation)
                        _ = _port.WriteFrameAsync(BuildRaFrame());
                    return;
                }

                if (p[6] == 17 && p.Length >= 40 + 8 && ((p[40 + 2] << 8) | p[40 + 3]) == Dhcpv6Packet.ServerPort)
                {
                    ReadOnlySpan<byte> dhcp = p.Slice(40 + 8);
                    uint xid = Dhcpv6Packet.TransactionId(dhcp);
                    byte type = Dhcpv6Packet.MessageType(dhcp);
                    byte reply = type switch
                    {
                        Dhcpv6Packet.MessageSolicit => Dhcpv6Packet.MessageAdvertise,
                        Dhcpv6Packet.MessageRequest => Dhcpv6Packet.MessageReply,
                        _ => (byte)0,
                    };
                    if (reply != 0)
                        _ = _port.WriteFrameAsync(BuildDhcpV6Reply(reply, xid));
                }
            }

            byte[] BuildDhcpV4Reply(byte messageType, uint xid)
            {
                byte[] options = new byte[128];
                int pos = DhcpV4Options.WriteMagicCookie(options, 0);
                pos = DhcpV4Options.WriteOption(options, pos, DhcpV4Options.CodeMessageType, messageType);
                pos = DhcpV4Options.WriteOption(options, pos, DhcpV4Options.CodeServerId, ServerIdV4);
                pos = DhcpV4Options.WriteOption(options, pos, DhcpV4Options.CodeSubnetMask, MaskV4);
                pos = DhcpV4Options.WriteOption(options, pos, DhcpV4Options.CodeRouter, RouterV4);
                pos = DhcpV4Options.WriteOption(options, pos, DhcpV4Options.CodeDnsServer, DnsV4.GetAddressBytes());
                pos = DhcpV4Options.WriteEnd(options, pos);

                byte[] msg = DhcpV4Packet.Build(xid, _clientMac, requestedCiaddr: null, broadcast: false, options.AsSpan(0, pos));
                msg[0] = DhcpV4Packet.OpBootReply;
                OfferedV4.GetAddressBytes().CopyTo(msg, 16);   // yiaddr @ offset 16

                byte[] udpIp = DhcpV4Packet.BuildUdpIpv4(ServerIdV4, IPAddress.Broadcast,
                    DhcpV4Packet.ServerPort, DhcpV4Packet.ClientPort, msg);
                return EthernetFrame.Build(MacAddress.Broadcast, ServerMac, EthernetFrame.EtherTypeIpv4, udpIp);
            }

            byte[] BuildRaFrame()
            {
                byte prefixFlags = (byte)(Icmpv6Ndisc.PrefixFlagOnLink | Icmpv6Ndisc.PrefixFlagAutonomous);
                byte[] ra = Icmpv6Ndisc.BuildRouterAdvertisement(RouterLla, Icmpv6Ndisc.AllNodes, ServerMac,
                    curHopLimit: 64, routerLifetimeSeconds: 1800,
                    prefix: PrefixV6, prefixLength: 64, prefixFlags: prefixFlags,
                    validLifetime: 86400, preferredLifetime: 14400);
                // Managed (M) + Other (O): SLAAC forms the address (autonomous prefix), DHCPv6 brings DNS.
                ra[5] = (byte)(Icmpv6Ndisc.RaFlagManaged | Icmpv6Ndisc.RaFlagOther);
                byte[] ipv6 = Icmpv6Ndisc.BuildIpv6(RouterLla, Icmpv6Ndisc.AllNodes, ra);
                return EthernetFrame.Build(Icmpv6Ndisc.MulticastMac(Icmpv6Ndisc.AllNodes), ServerMac, EthernetFrame.EtherTypeIpv6, ipv6);
            }

            byte[] BuildDhcpV6Reply(byte messageType, uint xid)
            {
                byte[] serverDuid = Dhcpv6Options.BuildDuidLinkLayer(ServerMac);
                byte[] clientDuid = Dhcpv6Options.BuildDuidLinkLayer(_clientMac);
                byte[] options = new byte[256];
                int pos = Dhcpv6Options.WriteOption(options, 0, Dhcpv6Options.CodeServerId, serverDuid);
                pos = Dhcpv6Options.WriteOption(options, pos, Dhcpv6Options.CodeClientId, clientDuid);
                // Offer a DHCPv6 address too; SLAAC is preferred by the configurator but DNS is what we need from here.
                byte[] iaAddr = Dhcpv6Options.BuildIaAddressOption(IPAddress.Parse("2001:db8:1234::100"), 3600, 7200);
                byte[] iaNa = Dhcpv6Options.BuildIaNa(1, 3600, 7200, iaAddr);
                pos = Dhcpv6Options.WriteOption(options, pos, Dhcpv6Options.CodeIaNa, iaNa);
                pos = Dhcpv6Options.WriteOption(options, pos, Dhcpv6Options.CodeDnsServers, DnsV6.GetAddressBytes());

                byte[] dhcp = Dhcpv6Packet.Build(messageType, xid, options.AsSpan(0, pos));
                byte[] udpIp = Dhcpv6Packet.BuildUdpIpv6(ServerLla, ClientLla,
                    Dhcpv6Packet.ServerPort, Dhcpv6Packet.ClientPort, dhcp);
                return EthernetFrame.Build(_clientMac, ServerMac, EthernetFrame.EtherTypeIpv6, udpIp);
            }

            public ValueTask DisposeAsync()
            {
                _port.InboundFrame -= OnFrame;
                return default;
            }
        }
    }
}
