using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Threading;
using System.Threading.Tasks;
using TqkLibrary.VpnClient.Abstractions.Channels.Enums;
using TqkLibrary.VpnClient.Abstractions.Channels.Interfaces;
using TqkLibrary.VpnClient.Abstractions.Drivers.Models;
using TqkLibrary.VpnClient.Ethernet;
using TqkLibrary.VpnClient.Ethernet.Enums;
using TqkLibrary.VpnClient.Ethernet.Helpers;
using Xunit;

namespace TqkLibrary.VpnClient.Ethernet.Tests
{
    public class Ipv6AddressConfiguratorTests
    {
        static readonly MacAddress ClientMac = MacAddress.Parse("02:00:00:00:00:0a");
        static readonly MacAddress RouterMac = MacAddress.Parse("02:00:00:00:00:01");
        static readonly MacAddress ServerMac = MacAddress.Parse("02:00:00:00:00:02");
        static readonly IPAddress LinkLocal = IPAddress.Parse("fe80::a");
        static readonly IPAddress RouterLla = IPAddress.Parse("fe80::1");
        static readonly IPAddress Prefix = IPAddress.Parse("2001:db8:1234::");
        static readonly IPAddress DhcpAddress = IPAddress.Parse("2001:db8:1234::100");
        static readonly IPAddress Dns1 = IPAddress.Parse("2001:4860:4860::8888");
        static readonly IPAddress Dns2 = IPAddress.Parse("2606:4700:4700::1111");
        static readonly IPAddress ServerLla = IPAddress.Parse("fe80::2");

        static Ipv6AddressConfiguratorOptions FastOptions(bool forceDhcp = false, SlaacInterfaceIdentifierMode mode = SlaacInterfaceIdentifierMode.ModifiedEui64)
            => new Ipv6AddressConfiguratorOptions(
                interfaceIdentifierMode: mode,
                routerAdvertisementTimeout: TimeSpan.FromMilliseconds(60),
                routerSolicitationAttempts: 3,
                dhcpReplyTimeout: TimeSpan.FromMilliseconds(60),
                dhcpMaxAttempts: 3,
                forceDhcp: forceDhcp);

        // ---- SLAAC address derivation ----

        [Fact]
        public void Eui64_InsertsFffe_AndFlipsUlBit()
        {
            // 02:00:00:00:00:0a → flip U/L bit of first octet (0x02 ^ 0x02 = 0x00), insert ff:fe in the middle.
            byte[] iid = SlaacAddress.ModifiedEui64(ClientMac);
            Assert.Equal(new byte[] { 0x00, 0x00, 0x00, 0xFF, 0xFE, 0x00, 0x00, 0x0a }, iid);
        }

        [Fact]
        public void Combine_Eui64_FormsGlobalAddress()
        {
            byte[] iid = SlaacAddress.ModifiedEui64(ClientMac);
            IPAddress addr = SlaacAddress.Combine(Prefix, 64, iid);
            Assert.Equal(IPAddress.Parse("2001:db8:1234::ff:fe00:a"), addr);
        }

        [Fact]
        public void StableOpaque_IsDeterministic_AndNotEui64()
        {
            byte[] a = SlaacAddress.StableInterfaceIdentifier(Prefix, ClientMac);
            byte[] b = SlaacAddress.StableInterfaceIdentifier(Prefix, ClientMac);
            Assert.Equal(a, b);                                                 // deterministic per (prefix, MAC)
            Assert.NotEqual(SlaacAddress.ModifiedEui64(ClientMac), a);          // not the MAC-derived identifier
            // A different prefix yields a different identifier.
            byte[] other = SlaacAddress.StableInterfaceIdentifier(IPAddress.Parse("2001:db8:9999::"), ClientMac);
            Assert.NotEqual(a, other);
        }

        [Fact]
        public void Combine_RejectsNon64Prefix()
            => Assert.Throws<ArgumentException>(() => SlaacAddress.Combine(Prefix, 48, SlaacAddress.ModifiedEui64(ClientMac)));

        // ---- DHCPv6 option / packet codec round-trips ----

        [Fact]
        public void Options_IaNa_WithAddress_ReadsBack()
        {
            byte[] iaAddr = Dhcpv6Options.BuildIaAddressOption(DhcpAddress, preferredLifetime: 3600, validLifetime: 7200);
            byte[] iaNa = Dhcpv6Options.BuildIaNa(iaid: 1, t1: 0, t2: 0, iaAddr);
            byte[] options = new byte[128];
            int pos = Dhcpv6Options.WriteOption(options, 0, Dhcpv6Options.CodeIaNa, iaNa);
            pos = Dhcpv6Options.WriteOption(options, pos, Dhcpv6Options.CodeDnsServers, ConcatV6(Dns1, Dns2));

            ReadOnlySpan<byte> span = options.AsSpan(0, pos);
            IPAddress? read = Dhcpv6Options.ReadAssignedAddress(span, out uint pref, out uint valid);
            Assert.Equal(DhcpAddress, read);
            Assert.Equal(3600u, pref);
            Assert.Equal(7200u, valid);
            Assert.Equal(new[] { Dns1, Dns2 }, Dhcpv6Options.ReadDnsServers(span).ToArray());
            Assert.Equal(Dhcpv6Options.StatusSuccess, Dhcpv6Options.ReadStatusCode(span));
        }

        [Fact]
        public void Options_NoAddrsAvailStatusInsideIa_YieldsNoAddress()
        {
            byte[] status = { 0x00, (byte)Dhcpv6Options.StatusNoAddrsAvail };   // status-code(2) + (no message)
            byte[] inner = new byte[16];
            int innerPos = Dhcpv6Options.WriteOption(inner, 0, Dhcpv6Options.CodeStatusCode, status);
            byte[] iaNa = Dhcpv6Options.BuildIaNa(1, 0, 0, inner.AsSpan(0, innerPos));
            byte[] options = new byte[64];
            int pos = Dhcpv6Options.WriteOption(options, 0, Dhcpv6Options.CodeIaNa, iaNa);

            Assert.Null(Dhcpv6Options.ReadAssignedAddress(options.AsSpan(0, pos), out _, out _));
        }

        [Fact]
        public void Packet_BuildAndReadBack_Header()
        {
            byte[] msg = Dhcpv6Packet.Build(Dhcpv6Packet.MessageSolicit, 0xABCDEF, new byte[] { 1, 2, 3 });
            Assert.Equal(Dhcpv6Packet.MessageSolicit, Dhcpv6Packet.MessageType(msg));
            Assert.Equal(0xABCDEFu, Dhcpv6Packet.TransactionId(msg));
            Assert.Equal(new byte[] { 1, 2, 3 }, Dhcpv6Packet.OptionField(msg).ToArray());
        }

        [Fact]
        public void UdpIpv6_RoundTrip_RejectsClientToServerDirection()
        {
            byte[] dhcp = Dhcpv6Packet.Build(Dhcpv6Packet.MessageSolicit, 1, Array.Empty<byte>());
            // client → server (546→547) must NOT parse at the client port.
            byte[] up = Dhcpv6Packet.BuildUdpIpv6(LinkLocal, Dhcpv6Packet.AllRelayAgentsAndServers,
                Dhcpv6Packet.ClientPort, Dhcpv6Packet.ServerPort, dhcp);
            Assert.False(Dhcpv6Packet.TryReadUdpIpv6(up, out _));

            // server → client (547→546) is what the client accepts.
            byte[] down = Dhcpv6Packet.BuildUdpIpv6(ServerLla, LinkLocal,
                Dhcpv6Packet.ServerPort, Dhcpv6Packet.ClientPort, dhcp);
            Assert.True(Dhcpv6Packet.TryReadUdpIpv6(down, out ReadOnlyMemory<byte> extracted));
            Assert.Equal(dhcp, extracted.ToArray());
        }

        // ---- SLAAC: form an address from a fake Router Advertisement ----

        [Fact]
        public async Task Configure_Slaac_FromAutonomousRa_FormsGlobalAddress()
        {
            await using var port = new CaptureEthernetChannel();
            await using var ndisc = new NdiscResolver(ClientMac, LinkLocal, port);
            await using var cfg = new Ipv6AddressConfigurator(ClientMac, LinkLocal, port, ndisc, FastOptions());

            ValueTask<TunnelConfig> pending = cfg.ConfigureAsync();

            // A Router Solicitation goes out (to ff02::2 → MAC 33:33:00:00:00:02).
            byte[] rsFrame = await WaitForOneWrittenAsync(port);
            Assert.Equal(EthernetFrame.EtherTypeIpv6, EthernetFrame.EtherType(rsFrame));
            Assert.Equal(Icmpv6Ndisc.TypeRouterSolicitation, Icmpv6Ndisc.Type(NdiscMessage(rsFrame)));

            // The router answers with an autonomous /64 prefix RA → NdiscResolver parses it, the configurator picks it up.
            ndisc.HandleInboundFrame(BuildRaFrame(managed: false, otherConfig: false, autonomous: true));

            TunnelConfig config = await pending;
            Assert.Equal(IPAddress.Parse("2001:db8:1234::ff:fe00:a"), config.AssignedAddressV6);   // EUI-64
            Assert.Equal(64, config.PrefixLengthV6);
            Assert.Equal($"::/0 {RouterLla}", Assert.Single(config.Routes));
            Assert.Empty(config.DnsServers);                                                       // pure SLAAC, no DHCPv6
        }

        [Fact]
        public async Task Configure_Slaac_StableOpaque_UsesRfc7217Identifier()
        {
            await using var port = new CaptureEthernetChannel();
            await using var ndisc = new NdiscResolver(ClientMac, LinkLocal, port);
            await using var cfg = new Ipv6AddressConfigurator(ClientMac, LinkLocal, port, ndisc, FastOptions(mode: SlaacInterfaceIdentifierMode.StableOpaque));

            ValueTask<TunnelConfig> pending = cfg.ConfigureAsync();
            await WaitForOneWrittenAsync(port);
            ndisc.HandleInboundFrame(BuildRaFrame(managed: false, otherConfig: false, autonomous: true));

            TunnelConfig config = await pending;
            byte[] iid = SlaacAddress.StableInterfaceIdentifier(Prefix, ClientMac);
            Assert.Equal(SlaacAddress.Combine(Prefix, 64, iid), config.AssignedAddressV6);
        }

        [Fact]
        public async Task Configure_NoRa_Throws_AfterRetransmittingRouterSolicitations()
        {
            await using var port = new CaptureEthernetChannel();
            await using var ndisc = new NdiscResolver(ClientMac, LinkLocal, port);
            await using var cfg = new Ipv6AddressConfigurator(ClientMac, LinkLocal, port, ndisc,
                new Ipv6AddressConfiguratorOptions(routerAdvertisementTimeout: TimeSpan.FromMilliseconds(20), routerSolicitationAttempts: 3));

            await Assert.ThrowsAsync<InvalidOperationException>(async () => await cfg.ConfigureAsync());
            Assert.True(port.Written.Count >= 2);   // RS retransmitted
        }

        // ---- DHCPv6: stateful handshake when the RA sets the Managed flag ----

        [Fact]
        public async Task Configure_ManagedRa_RunsDhcpv6Handshake()
        {
            await using var port = new CaptureEthernetChannel();
            await using var ndisc = new NdiscResolver(ClientMac, LinkLocal, port);
            await using var cfg = new Ipv6AddressConfigurator(ClientMac, LinkLocal, port, ndisc, FastOptions());

            ValueTask<TunnelConfig> pending = cfg.ConfigureAsync();

            await WaitForOneWrittenAsync(port);                                  // RS
            // Managed RA, NOT autonomous → no SLAAC, must use DHCPv6.
            ndisc.HandleInboundFrame(BuildRaFrame(managed: true, otherConfig: true, autonomous: false));

            // SOLICIT goes out → answer with ADVERTISE.
            byte[] solicitFrame = await WaitForWrittenWhereAsync(port, f => IsDhcpv6(f, Dhcpv6Packet.MessageSolicit));
            uint xid = Dhcpv6Packet.TransactionId(ExtractDhcpv6(solicitFrame));
            cfg.HandleInboundFrame(BuildServerReply(Dhcpv6Packet.MessageAdvertise, xid, withAddress: true, withDns: true));

            // REQUEST goes out echoing the offered address → answer with REPLY.
            byte[] requestFrame = await WaitForWrittenWhereAsync(port, f => IsDhcpv6(f, Dhcpv6Packet.MessageRequest));
            byte[] requestDhcp = ExtractDhcpv6(requestFrame);
            AssertRequestEchoesServerAndAddress(requestDhcp);   // span work kept out of the async body (C# 12)
            cfg.HandleInboundFrame(BuildServerReply(Dhcpv6Packet.MessageReply, xid, withAddress: true, withDns: true));

            TunnelConfig config = await pending;
            Assert.Equal(DhcpAddress, config.AssignedAddressV6);
            Assert.Equal(128, config.PrefixLengthV6);
            Assert.Equal(new[] { Dns1, Dns2 }, config.DnsServers.ToArray());
            Assert.Equal($"::/0 {RouterLla}", Assert.Single(config.Routes));
        }

        [Fact]
        public async Task Configure_ManagedRa_DhcpNoAddress_Throws()
        {
            await using var port = new CaptureEthernetChannel();
            await using var ndisc = new NdiscResolver(ClientMac, LinkLocal, port);
            await using var cfg = new Ipv6AddressConfigurator(ClientMac, LinkLocal, port, ndisc, FastOptions());

            ValueTask<TunnelConfig> pending = cfg.ConfigureAsync();
            await WaitForOneWrittenAsync(port);
            ndisc.HandleInboundFrame(BuildRaFrame(managed: true, otherConfig: false, autonomous: false));

            byte[] solicitFrame = await WaitForWrittenWhereAsync(port, f => IsDhcpv6(f, Dhcpv6Packet.MessageSolicit));
            uint xid = Dhcpv6Packet.TransactionId(ExtractDhcpv6(solicitFrame));
            cfg.HandleInboundFrame(BuildServerReply(Dhcpv6Packet.MessageAdvertise, xid, withAddress: false, withDns: false));
            await WaitForWrittenWhereAsync(port, f => IsDhcpv6(f, Dhcpv6Packet.MessageRequest));
            cfg.HandleInboundFrame(BuildServerReply(Dhcpv6Packet.MessageReply, xid, withAddress: false, withDns: false));

            await Assert.ThrowsAsync<InvalidOperationException>(async () => await pending);
        }

        // ---- Integration: real SLAAC + DHCPv6 over the in-memory switch with a stub server ----

        [Fact]
        public async Task Integration_SlaacPlusDhcpv6OverSwitch_ConfiguresHost()
        {
            await using var sw = new EthernetSwitch();
            IEthernetChannel clientPort = sw.ConnectHost(ClientMac);
            IEthernetChannel serverPort = sw.ConnectHost(ServerMac);

            await using var ndisc = new NdiscResolver(ClientMac, LinkLocal, clientPort);
            await using var host = new VirtualHost(ClientMac, clientPort, ndisc);
            await using var cfg = new Ipv6AddressConfigurator(ClientMac, LinkLocal, clientPort, ndisc, FastOptions());
            // RAs/DHCPv6 ride inside IPv6, so the configurator and resolver see the inbound IP packets.
            host.InboundIpPacket += ndisc.HandleInboundFrame;
            host.InboundIpPacket += cfg.HandleInboundFrame;

            // A stub router + DHCPv6 server on its own switch port: answers RS with a Managed+autonomous RA, then the
            // DHCPv6 four-message exchange.
            await using var server = new StubV6Server(serverPort);

            TunnelConfig config = await cfg.ConfigureAsync();

            // Managed + autonomous RA: SLAAC forms the address (preferred), DHCPv6 brings DNS.
            Assert.Equal(IPAddress.Parse("2001:db8:1234::ff:fe00:a"), config.AssignedAddressV6);
            Assert.Equal(64, config.PrefixLengthV6);
            Assert.Equal($"::/0 {RouterLla}", Assert.Single(config.Routes));
            Assert.Equal(new[] { Dns1, Dns2 }, config.DnsServers.ToArray());
        }

        [Fact]
        public async Task Dispose_CancelsPendingConfigure()
        {
            var port = new CaptureEthernetChannel();
            var ndisc = new NdiscResolver(ClientMac, LinkLocal, port);
            var cfg = new Ipv6AddressConfigurator(ClientMac, LinkLocal, port, ndisc, FastOptions());

            ValueTask<TunnelConfig> pending = cfg.ConfigureAsync();
            await WaitForOneWrittenAsync(port);
            await cfg.DisposeAsync();

            await Assert.ThrowsAnyAsync<OperationCanceledException>(async () => await pending);
            await ndisc.DisposeAsync();
        }

        // ---- Helpers ----

        static byte[] ConcatV6(params IPAddress[] addresses)
        {
            byte[] result = new byte[addresses.Length * 16];
            for (int i = 0; i < addresses.Length; i++)
                addresses[i].GetAddressBytes().CopyTo(result, i * 16);
            return result;
        }

        static byte[] BuildRaFrame(bool managed, bool otherConfig, bool autonomous)
        {
            byte prefixFlags = (byte)(Icmpv6Ndisc.PrefixFlagOnLink | (autonomous ? Icmpv6Ndisc.PrefixFlagAutonomous : 0));
            byte[] ra = Icmpv6Ndisc.BuildRouterAdvertisement(RouterLla, Icmpv6Ndisc.AllNodes, RouterMac,
                curHopLimit: 64, routerLifetimeSeconds: 1800,
                prefix: Prefix, prefixLength: 64, prefixFlags: prefixFlags,
                validLifetime: 86400, preferredLifetime: 14400);
            // Set the M/O flags in the RA flag byte (byte 5 of the message) — the codec leaves them zero.
            ra[5] = (byte)((managed ? Icmpv6Ndisc.RaFlagManaged : 0) | (otherConfig ? Icmpv6Ndisc.RaFlagOther : 0));
            // Re-checksum after toggling the flag byte (checksum field is bytes 2..4; zero then recompute the trivial way
            // via the codec is unnecessary because the resolver does not verify it, but keep the frame well-formed enough).
            byte[] ipv6 = Icmpv6Ndisc.BuildIpv6(RouterLla, Icmpv6Ndisc.AllNodes, ra);
            return EthernetFrame.Build(Icmpv6Ndisc.MulticastMac(Icmpv6Ndisc.AllNodes), RouterMac, EthernetFrame.EtherTypeIpv6, ipv6);
        }

        static byte[] BuildServerReply(byte messageType, uint xid, bool withAddress, bool withDns)
        {
            byte[] dhcp = BuildDhcpv6Reply(messageType, xid, withAddress, withDns);
            byte[] udpIp = Dhcpv6Packet.BuildUdpIpv6(ServerLla, LinkLocal,
                Dhcpv6Packet.ServerPort, Dhcpv6Packet.ClientPort, dhcp);
            return EthernetFrame.Build(ClientMac, ServerMac, EthernetFrame.EtherTypeIpv6, udpIp);
        }

        static byte[] BuildDhcpv6Reply(byte messageType, uint xid, bool withAddress, bool withDns)
        {
            byte[] serverDuid = Dhcpv6Options.BuildDuidLinkLayer(ServerMac);
            byte[] clientDuid = Dhcpv6Options.BuildDuidLinkLayer(ClientMac);
            byte[] options = new byte[256];
            int pos = Dhcpv6Options.WriteOption(options, 0, Dhcpv6Options.CodeServerId, serverDuid);
            pos = Dhcpv6Options.WriteOption(options, pos, Dhcpv6Options.CodeClientId, clientDuid);

            byte[] iaNa;
            if (withAddress)
            {
                byte[] iaAddr = Dhcpv6Options.BuildIaAddressOption(DhcpAddress, 3600, 7200);
                iaNa = Dhcpv6Options.BuildIaNa(1, 3600, 7200, iaAddr);
            }
            else
            {
                byte[] status = { 0x00, (byte)Dhcpv6Options.StatusNoAddrsAvail };
                byte[] inner = new byte[16];
                int innerPos = Dhcpv6Options.WriteOption(inner, 0, Dhcpv6Options.CodeStatusCode, status);
                iaNa = Dhcpv6Options.BuildIaNa(1, 0, 0, inner.AsSpan(0, innerPos));
            }
            pos = Dhcpv6Options.WriteOption(options, pos, Dhcpv6Options.CodeIaNa, iaNa);
            if (withDns)
                pos = Dhcpv6Options.WriteOption(options, pos, Dhcpv6Options.CodeDnsServers, ConcatV6(Dns1, Dns2));
            return Dhcpv6Packet.Build(messageType, xid, options.AsSpan(0, pos));
        }

        static void AssertRequestEchoesServerAndAddress(byte[] requestDhcp)
        {
            ReadOnlySpan<byte> reqOptions = Dhcpv6Packet.OptionField(requestDhcp).Span;
            Assert.True(Dhcpv6Options.TryGetOption(reqOptions, Dhcpv6Options.CodeServerId, out _));   // chosen server echoed
            Assert.Equal(DhcpAddress, Dhcpv6Options.ReadAssignedAddress(reqOptions, out _, out _));   // offered addr echoed
        }

        static byte[] NdiscMessage(byte[] frame)
        {
            byte[] ipv6 = EthernetFrame.Payload(frame).ToArray();
            return new ReadOnlySpan<byte>(ipv6, 40, ipv6.Length - 40).ToArray();
        }

        static bool IsDhcpv6(byte[] frame, byte messageType)
        {
            byte[]? dhcp = TryExtractOutboundDhcpv6(frame);
            return dhcp != null && Dhcpv6Packet.MessageType(dhcp) == messageType;
        }

        static byte[] ExtractDhcpv6(byte[] frame) => TryExtractOutboundDhcpv6(frame)!;

        /// <summary>
        /// Reads the DHCPv6 message from an Ethernet/IPv6/UDP frame the client SENT (546→547), which the production
        /// reader (gated on the client port 546) intentionally rejects. Reads the UDP payload at the fixed offset.
        /// </summary>
        static byte[]? TryExtractOutboundDhcpv6(byte[] frame)
        {
            if (frame.Length < EthernetFrame.HeaderLength || EthernetFrame.EtherType(frame) != EthernetFrame.EtherTypeIpv6)
                return null;
            ReadOnlyMemory<byte> ip = EthernetFrame.Payload(frame);
            ReadOnlySpan<byte> span = ip.Span;
            if (span.Length < 40 + 8 || (byte)(span[0] >> 4) != 6 || span[6] != 17)
                return null;   // not an IPv6/UDP packet
            int destPort = (span[40 + 2] << 8) | span[40 + 3];
            if (destPort != Dhcpv6Packet.ServerPort)
                return null;   // not a DHCPv6 client→server datagram
            return ip.Slice(40 + 8).ToArray();
        }

        static async Task<byte[]> WaitForOneWrittenAsync(CaptureEthernetChannel port) => await WaitForWriteCountAsync(port, 1);

        static async Task<byte[]> WaitForWriteCountAsync(CaptureEthernetChannel port, int count)
        {
            for (int i = 0; i < 300; i++)
            {
                lock (port.Written)
                {
                    if (port.Written.Count >= count)
                        return port.Written[count - 1];
                }
                await Task.Delay(5);
            }
            throw new TimeoutException($"Expected at least {count} written frame(s).");
        }

        static async Task<byte[]> WaitForWrittenWhereAsync(CaptureEthernetChannel port, Func<byte[], bool> predicate)
        {
            for (int i = 0; i < 300; i++)
            {
                lock (port.Written)
                {
                    for (int j = port.Written.Count - 1; j >= 0; j--)
                        if (predicate(port.Written[j]))
                            return port.Written[j];
                }
                await Task.Delay(5);
            }
            throw new TimeoutException("Expected a matching written frame.");
        }

        sealed class CaptureEthernetChannel : IEthernetChannel
        {
            public List<byte[]> Written { get; } = new();
            public int Mtu { get; set; } = 1500;
            public LinkMedium Medium => LinkMedium.Ethernet;
            public int MaxHeaderLength => EthernetFrame.HeaderLength;
            public bool RequiresLinkAddressResolution => true;
            public ReadOnlyMemory<byte> LinkAddress { get; set; }
            public event Action<ReadOnlyMemory<byte>>? InboundFrame;

            public ValueTask WriteFrameAsync(ReadOnlyMemory<byte> ethernetFrame, CancellationToken cancellationToken = default)
            {
                lock (Written) Written.Add(ethernetFrame.ToArray());
                return default;
            }

            public void RaiseInbound(ReadOnlyMemory<byte> frame) => InboundFrame?.Invoke(frame);

            public ValueTask DisposeAsync()
            {
                InboundFrame = null;
                return default;
            }
        }

        /// <summary>A throwaway router + DHCPv6 server bound to a switch port: RA for an RS, ADVERTISE/REPLY for the exchange.</summary>
        sealed class StubV6Server : IAsyncDisposable
        {
            readonly IEthernetChannel _port;

            public StubV6Server(IEthernetChannel port)
            {
                _port = port;
                _port.InboundFrame += OnFrame;
            }

            void OnFrame(ReadOnlyMemory<byte> frame)
            {
                ReadOnlySpan<byte> span = frame.Span;
                if (span.Length < EthernetFrame.HeaderLength || EthernetFrame.EtherType(span) != EthernetFrame.EtherTypeIpv6)
                    return;
                ReadOnlyMemory<byte> ipv6 = EthernetFrame.Payload(frame);
                ReadOnlySpan<byte> p = ipv6.Span;
                if (p.Length < 48 || (byte)(p[0] >> 4) != 6)
                    return;

                if (p[6] == Icmpv6Ndisc.ProtocolNumber)
                {
                    ReadOnlySpan<byte> message = p.Slice(40);
                    if (Icmpv6Ndisc.IsNdisc(message) && Icmpv6Ndisc.Type(message) == Icmpv6Ndisc.TypeRouterSolicitation)
                        _ = _port.WriteFrameAsync(BuildRaFrame(managed: true, otherConfig: true, autonomous: true));
                    return;
                }

                // A client→server datagram (546→547): the production reader is gated on the client port, so read the
                // UDP payload at its fixed offset here.
                if (p[6] == 17 && p.Length >= 40 + 8 && ((p[40 + 2] << 8) | p[40 + 3]) == Dhcpv6Packet.ServerPort)
                {
                    ReadOnlySpan<byte> dhcp = p.Slice(40 + 8);
                    uint xid = Dhcpv6Packet.TransactionId(dhcp);
                    byte type = Dhcpv6Packet.MessageType(dhcp);
                    byte reply = type switch
                    {
                        Dhcpv6Packet.MessageSolicit => Dhcpv6Packet.MessageAdvertise,
                        Dhcpv6Packet.MessageRequest => Dhcpv6Packet.MessageReply,
                        _ => 0,
                    };
                    if (reply != 0)
                        _ = _port.WriteFrameAsync(BuildServerReply(reply, xid, withAddress: true, withDns: true));
                }
            }

            public ValueTask DisposeAsync()
            {
                _port.InboundFrame -= OnFrame;
                return default;
            }
        }
    }
}
