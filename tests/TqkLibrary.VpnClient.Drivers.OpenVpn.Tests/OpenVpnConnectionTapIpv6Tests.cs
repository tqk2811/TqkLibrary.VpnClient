using System;
using System.Net;
using System.Net.Sockets;
using System.Security.Cryptography.X509Certificates;
using System.Threading;
using System.Threading.Channels;
using System.Threading.Tasks;
using TqkLibrary.VpnClient.Ethernet;
using TqkLibrary.VpnClient.Ethernet.Helpers;
using TqkLibrary.VpnClient.OpenVpn;
using TqkLibrary.VpnClient.OpenVpn.DataChannel;
using TqkLibrary.VpnClient.OpenVpn.Enums;
using Xunit;

namespace TqkLibrary.VpnClient.Drivers.OpenVpn.Tests
{
    /// <summary>
    /// Drives the OpenVPN driver in <b>tap-mode with IPv6 enabled</b> offline. Mirrors the SoftEther IPv6 tests: the
    /// simulated tap bridge advertises an autonomous /64 prefix (Router Advertisement) and answers DHCPv6 for DNS, so the
    /// real <see cref="OpenVpnConnection"/> forms a global IPv6 address by SLAAC over the same L2 segment that carries the
    /// IPv4 ifconfig/DHCP lease — pushing <c>AssignedAddressV6</c>/<c>PrefixLengthV6</c> onto the tunnel config. A second
    /// case proves the IPv6 leg is best-effort: an IPv4-only bridge (no RA) still connects on IPv4 with no v6 address. The
    /// responder is throwaway test scaffolding (this library is a client).
    /// </summary>
    public class OpenVpnConnectionTapIpv6Tests
    {
        [Fact]
        public async Task Connect_TapMode_WithIpv6Enabled_ConfiguresV6BySlaac_PushesV6Address()
        {
            var link = new LoopbackLink();
            using var serverCert = OpenVpnTestPki.CreateSelfSignedServerCert();
            using var server = new SimulatedOpenVpnTapIpv6Server(link.Server, serverCert, advertiseIpv6: true);

            using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(30));
            var connection = new OpenVpnConnection("127.0.0.1", 1194, new InProcessTransportFactory(link.Client),
                optionsString: "V4,cipher AES-256-GCM",
                device: OpenVpnDeviceType.Tap,
                serverCertificateValidation: (_, _, _, _) => true,
                enableIpv6: true,
                reliabilityOptions: new OpenVpnReliabilityOptions { Interval = TimeSpan.FromSeconds(30) });

            await connection.ConnectAsync(cts.Token);

            // IPv4 still bound from the pushed ifconfig exactly as before.
            Assert.Equal(IPAddress.Parse("10.8.0.2"), connection.AssignedAddress);
            Assert.Equal(24, connection.Config.PrefixLength);

            // IPv6 configured by SLAAC: the advertised /64 prefix + Modified EUI-64 of the connection's MAC, prefix /64.
            Assert.True(connection.IsIpv6Enabled);
            Assert.NotNull(connection.AssignedAddressV6);
            Assert.True(server.RouterAdvertisements >= 1);   // the bridge solicited an RA
            Assert.Equal(AddressFamily.InterNetworkV6, connection.AssignedAddressV6!.AddressFamily);
            byte[] v6 = connection.AssignedAddressV6.GetAddressBytes();
            Assert.Equal(SimulatedOpenVpnTapIpv6Server.Ipv6Prefix.GetAddressBytes()[..8], v6[..8]);   // shares the advertised /64
            Assert.Equal(64, connection.Config.PrefixLengthV6);
            Assert.Contains(IPAddress.Parse("2001:4860:4860::8888"), connection.Config.DnsServers);    // DHCPv6 DNS
            Assert.Contains("::/0 fe80::1", connection.Config.Routes);                                  // v6 default route via the RA router

            await connection.DisposeAsync();
        }

        [Fact]
        public async Task Connect_TapMode_WithIpv6Enabled_ButIpv4OnlyBridge_StillConnects_NoV6Address()
        {
            var link = new LoopbackLink();
            using var serverCert = OpenVpnTestPki.CreateSelfSignedServerCert();
            // The bridge advertises no IPv6 (IPv4-only): no RA / no DHCPv6, so SLAAC forms nothing.
            using var server = new SimulatedOpenVpnTapIpv6Server(link.Server, serverCert, advertiseIpv6: false);

            using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(30));
            var connection = new OpenVpnConnection("127.0.0.1", 1194, new InProcessTransportFactory(link.Client),
                optionsString: "V4,cipher AES-256-GCM",
                device: OpenVpnDeviceType.Tap,
                serverCertificateValidation: (_, _, _, _) => true,
                enableIpv6: true,
                ipv6Options: new TqkLibrary.VpnClient.Ethernet.Ipv6AddressConfiguratorOptions(
                    routerAdvertisementTimeout: TimeSpan.FromMilliseconds(150), routerSolicitationAttempts: 2),
                reliabilityOptions: new OpenVpnReliabilityOptions { Interval = TimeSpan.FromSeconds(30) });

            await connection.ConnectAsync(cts.Token);

            // IPv4 still works; the best-effort IPv6 leg left the config IPv4-only.
            Assert.Equal(IPAddress.Parse("10.8.0.2"), connection.AssignedAddress);
            Assert.Null(connection.AssignedAddressV6);

            await connection.DisposeAsync();
        }

        [Fact]
        public async Task Connect_TapMode_MultiHost_WithIpv6Enabled_PrimaryConfiguresV4AndV6()
        {
            var link = new LoopbackLink();
            using var serverCert = OpenVpnTestPki.CreateSelfSignedServerCert();
            using var server = new SimulatedOpenVpnTapIpv6Server(link.Server, serverCert, advertiseIpv6: true);

            using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(30));
            var connection = new OpenVpnConnection("127.0.0.1", 1194, new InProcessTransportFactory(link.Client),
                optionsString: "V4,cipher AES-256-GCM",
                device: OpenVpnDeviceType.Tap,
                serverCertificateValidation: (_, _, _, _) => true,
                multiHost: true,
                enableIpv6: true,
                reliabilityOptions: new OpenVpnReliabilityOptions { Interval = TimeSpan.FromSeconds(30) });

            await connection.ConnectAsync(cts.Token);

            // The primary station took the pushed ifconfig (static IPv4) AND configured IPv6 by SLAAC over the shared switch.
            Assert.True(connection.IsMultiHost);
            Assert.True(connection.IsIpv6Enabled);
            Assert.Equal(IPAddress.Parse("10.8.0.2"), connection.AssignedAddress);
            Assert.NotNull(connection.AssignedAddressV6);
            Assert.Equal(SimulatedOpenVpnTapIpv6Server.Ipv6Prefix.GetAddressBytes()[..8],
                connection.AssignedAddressV6!.GetAddressBytes()[..8]);   // SLAAC address under the advertised /64
            Assert.Equal(1, connection.MultiHostSession!.StationCount);

            await connection.DisposeAsync();
        }

        /// <summary>
        /// A dual-stack tap responder: each decrypted P_DATA payload is a full Ethernet frame. It answers ARP (v4), echoes
        /// IPv4, and — when <c>advertiseIpv6</c> — answers NDISC (RS→RA autonomous /64, NS→NA) and DHCPv6 (SOLICIT→ADVERTISE,
        /// REQUEST→REPLY carrying DNS) so the client forms a global IPv6 by SLAAC. When IPv6 is not advertised it stays silent
        /// on IPv6 (an IPv4-only bridge). Mirrors the SoftEther SecureNAT IPv6 simulator.
        /// </summary>
        sealed class SimulatedOpenVpnTapIpv6Server : SimulatedOpenVpnServerBase
        {
            public static readonly IPAddress Ipv6Prefix = IPAddress.Parse("2001:db8:abcd:1::");
            static readonly IPAddress RouterLla = IPAddress.Parse("fe80::1");
            static readonly IPAddress DnsV6 = IPAddress.Parse("2001:4860:4860::8888");
            static readonly MacAddress ServerMac = MacAddress.Parse("02:00:5e:00:00:01");

            readonly bool _advertiseIpv6;
            MacAddress _clientMac;
            int _raReplies;

            public SimulatedOpenVpnTapIpv6Server(IOpenVpnTransport transport, X509Certificate2 certificate, bool advertiseIpv6)
                : base(transport, certificate)
            {
                _advertiseIpv6 = advertiseIpv6;
            }

            public int RouterAdvertisements => _raReplies;

            protected override string PushReply
                => $"PUSH_REPLY,ifconfig 10.8.0.2 255.255.255.0,topology subnet,peer-id {PeerId},cipher AES-256-GCM";

            protected override void OnData(byte[] frame)
            {
                if (frame.Length < EthernetFrame.HeaderLength) return;
                _clientMac = EthernetFrame.Source(frame);
                ushort etherType = EthernetFrame.EtherType(frame);

                if (etherType == EthernetFrame.EtherTypeArp)
                {
                    ReadOnlySpan<byte> arp = EthernetFrame.Payload(frame).Span;
                    if (!ArpPacket.IsIpv4OverEthernet(arp) || ArpPacket.Operation(arp) != ArpPacket.OperationRequest) return;
                    MacAddress senderMac = ArpPacket.SenderMac(arp);
                    IPAddress senderIp = ArpPacket.SenderIp(arp);
                    IPAddress targetIp = ArpPacket.TargetIp(arp);
                    byte[] reply = EthernetFrame.Build(senderMac, ServerMac, EthernetFrame.EtherTypeArp,
                        ArpPacket.BuildReply(ServerMac, targetIp, senderMac, senderIp));
                    SendData(reply);
                    return;
                }

                if (etherType == EthernetFrame.EtherTypeIpv6 && _advertiseIpv6)
                {
                    byte[]? reply = BuildIpv6Reply(frame);
                    if (reply != null) SendData(reply);
                }
            }

            // IPv6 bridge: answer NDISC (RS→RA, NS→NA) and DHCPv6 (SOLICIT→ADVERTISE, REQUEST→REPLY).
            byte[]? BuildIpv6Reply(byte[] frame)
            {
                ReadOnlyMemory<byte> ipMem = EthernetFrame.Payload(frame);
                ReadOnlySpan<byte> p = ipMem.Span;
                if (p.Length < 40 || (byte)(p[0] >> 4) != 6) return null;

                byte nextHeader = p[6];
                if (nextHeader == Icmpv6Ndisc.ProtocolNumber)   // ICMPv6 (NDISC)
                {
                    ReadOnlySpan<byte> message = p.Slice(40);
                    if (!Icmpv6Ndisc.IsNdisc(message)) return null;
                    byte type = Icmpv6Ndisc.Type(message);
                    if (type == Icmpv6Ndisc.TypeRouterSolicitation) return BuildRaFrame();
                    if (type == Icmpv6Ndisc.TypeNeighborSolicitation) return BuildNaFrame(message);
                    return null;
                }
                if (nextHeader == 17 && p.Length >= 40 + 8 && ((p[40 + 2] << 8) | p[40 + 3]) == Dhcpv6Packet.ServerPort)
                {
                    ReadOnlySpan<byte> dhcp = p.Slice(40 + 8);
                    uint xid = Dhcpv6Packet.TransactionId(dhcp);
                    byte type = Dhcpv6Packet.MessageType(dhcp);
                    byte reply = type == Dhcpv6Packet.MessageSolicit ? Dhcpv6Packet.MessageAdvertise
                        : type == Dhcpv6Packet.MessageRequest ? Dhcpv6Packet.MessageReply : (byte)0;
                    if (reply == 0) return null;
                    return BuildDhcpV6ReplyFrame(reply, xid);
                }
                return null;
            }

            byte[] BuildRaFrame()
            {
                _raReplies++;
                byte prefixFlags = (byte)(Icmpv6Ndisc.PrefixFlagOnLink | Icmpv6Ndisc.PrefixFlagAutonomous);
                byte[] ra = Icmpv6Ndisc.BuildRouterAdvertisement(RouterLla, Icmpv6Ndisc.AllNodes, ServerMac,
                    curHopLimit: 64, routerLifetimeSeconds: 1800,
                    prefix: Ipv6Prefix, prefixLength: 64, prefixFlags: prefixFlags,
                    validLifetime: 86400, preferredLifetime: 14400);
                ra[5] = Icmpv6Ndisc.RaFlagOther;   // O flag: SLAAC forms the address, DHCPv6 brings DNS (no M → no stateful address)
                byte[] ipv6 = Icmpv6Ndisc.BuildIpv6(RouterLla, Icmpv6Ndisc.AllNodes, ra);
                return EthernetFrame.Build(Icmpv6Ndisc.MulticastMac(Icmpv6Ndisc.AllNodes), ServerMac, EthernetFrame.EtherTypeIpv6, ipv6);
            }

            byte[] BuildNaFrame(ReadOnlySpan<byte> nsMessage)
            {
                IPAddress target = Icmpv6Ndisc.TargetAddress(nsMessage);
                byte[] na = Icmpv6Ndisc.BuildNeighborAdvertisement(target, ClientLla(), target, ServerMac,
                    (byte)(Icmpv6Ndisc.FlagSolicited | Icmpv6Ndisc.FlagOverride));
                byte[] ipv6 = Icmpv6Ndisc.BuildIpv6(target, ClientLla(), na);
                return EthernetFrame.Build(_clientMac, ServerMac, EthernetFrame.EtherTypeIpv6, ipv6);
            }

            byte[] BuildDhcpV6ReplyFrame(byte messageType, uint xid)
            {
                byte[] serverDuid = Dhcpv6Options.BuildDuidLinkLayer(ServerMac);
                byte[] clientDuid = Dhcpv6Options.BuildDuidLinkLayer(_clientMac);
                byte[] options = new byte[256];
                int pos = Dhcpv6Options.WriteOption(options, 0, Dhcpv6Options.CodeServerId, serverDuid);
                pos = Dhcpv6Options.WriteOption(options, pos, Dhcpv6Options.CodeClientId, clientDuid);
                pos = Dhcpv6Options.WriteOption(options, pos, Dhcpv6Options.CodeDnsServers, DnsV6.GetAddressBytes());
                byte[] dhcp = Dhcpv6Packet.Build(messageType, xid, options.AsSpan(0, pos));
                byte[] udpIp = Dhcpv6Packet.BuildUdpIpv6(RouterLla, ClientLla(),
                    Dhcpv6Packet.ServerPort, Dhcpv6Packet.ClientPort, dhcp);
                return EthernetFrame.Build(_clientMac, ServerMac, EthernetFrame.EtherTypeIpv6, udpIp);
            }

            // The client's link-local address (fe80::/64 + Modified EUI-64 of its MAC) — destination of unicast NA/DHCPv6.
            IPAddress ClientLla()
                => SlaacAddress.Combine(IPAddress.Parse("fe80::"), 64, SlaacAddress.ModifiedEui64(_clientMac));
        }
    }
}
