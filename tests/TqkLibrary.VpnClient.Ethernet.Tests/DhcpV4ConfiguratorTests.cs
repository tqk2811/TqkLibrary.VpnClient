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
using Xunit;

namespace TqkLibrary.VpnClient.Ethernet.Tests
{
    public class DhcpV4ConfiguratorTests
    {
        static readonly MacAddress ClientMac = MacAddress.Parse("02:00:00:00:00:0a");
        static readonly MacAddress ServerMac = MacAddress.Parse("02:00:00:00:00:01");
        static readonly IPAddress Offered = IPAddress.Parse("10.20.30.40");
        static readonly IPAddress ServerId = IPAddress.Parse("10.20.30.1");
        static readonly IPAddress Mask = IPAddress.Parse("255.255.255.0");
        static readonly IPAddress Router = IPAddress.Parse("10.20.30.1");
        static readonly IPAddress Dns1 = IPAddress.Parse("8.8.8.8");
        static readonly IPAddress Dns2 = IPAddress.Parse("1.1.1.1");

        static DhcpV4ConfiguratorOptions FastOptions => new DhcpV4ConfiguratorOptions(replyTimeout: TimeSpan.FromMilliseconds(40), maxAttempts: 3);

        // ---- Codec round-trips ----

        [Fact]
        public void Options_RoundTrip_ReadsBackEveryField()
        {
            byte[] buf = new byte[128];
            int pos = DhcpV4Options.WriteMagicCookie(buf, 0);
            pos = DhcpV4Options.WriteOption(buf, pos, DhcpV4Options.CodeMessageType, DhcpV4Options.MessageAck);
            pos = DhcpV4Options.WriteOption(buf, pos, DhcpV4Options.CodeServerId, ServerId);
            pos = DhcpV4Options.WriteOption(buf, pos, DhcpV4Options.CodeSubnetMask, Mask);
            pos = DhcpV4Options.WriteOption(buf, pos, DhcpV4Options.CodeRouter, Router);
            pos = DhcpV4Options.WriteOption(buf, pos, DhcpV4Options.CodeDnsServer, ConcatAddresses(Dns1, Dns2));
            byte[] lease = { 0x00, 0x00, 0x0E, 0x10 };   // 3600 seconds
            pos = DhcpV4Options.WriteOption(buf, pos, DhcpV4Options.CodeLeaseTime, lease);
            pos = DhcpV4Options.WriteEnd(buf, pos);

            ReadOnlySpan<byte> options = buf.AsSpan(0, pos);
            Assert.True(DhcpV4Options.HasMagicCookie(options));
            Assert.Equal(DhcpV4Options.MessageAck, DhcpV4Options.ReadMessageType(options));
            Assert.Equal(ServerId, DhcpV4Options.ReadAddress(options, DhcpV4Options.CodeServerId));
            Assert.Equal(Mask, DhcpV4Options.ReadAddress(options, DhcpV4Options.CodeSubnetMask));
            Assert.Equal(new[] { Router }, DhcpV4Options.ReadAddresses(options, DhcpV4Options.CodeRouter));
            Assert.Equal(new[] { Dns1, Dns2 }, DhcpV4Options.ReadAddresses(options, DhcpV4Options.CodeDnsServer));
            Assert.Equal(3600u, DhcpV4Options.ReadLeaseTime(options));
        }

        [Fact]
        public void Options_MissingMagicCookie_ReadsNothing()
        {
            byte[] buf = new byte[16];   // no cookie
            Assert.False(DhcpV4Options.HasMagicCookie(buf));
            Assert.Equal(0, DhcpV4Options.ReadMessageType(buf));
            Assert.Null(DhcpV4Options.ReadAddress(buf, DhcpV4Options.CodeSubnetMask));
        }

        [Fact]
        public void Packet_BuildAndReadBack_HeaderFields()
        {
            byte[] opt = new byte[8];
            int pos = DhcpV4Options.WriteMagicCookie(opt, 0);
            pos = DhcpV4Options.WriteOption(opt, pos, DhcpV4Options.CodeMessageType, DhcpV4Options.MessageDiscover);
            byte[] msg = DhcpV4Packet.Build(0xDEADBEEF, ClientMac, requestedCiaddr: null, broadcast: true, opt.AsSpan(0, pos));

            Assert.Equal(DhcpV4Packet.OpBootRequest, msg[0]);
            Assert.Equal(0xDEADBEEFu, DhcpV4Packet.Xid(msg));
            // The Broadcast flag is set and chaddr carries the MAC.
            Assert.Equal(0x80, msg[10]);
            Assert.Equal(ClientMac, MacAddress.FromBytes(msg.AsSpan(28, 6)));
            Assert.Equal(DhcpV4Options.MessageDiscover, DhcpV4Options.ReadMessageType(DhcpV4Packet.OptionField(msg).Span));
        }

        [Fact]
        public void UdpIpv4_RoundTrip_ExtractsDhcpMessage()
        {
            byte[] dhcp = DhcpV4Packet.Build(1, ClientMac, null, true, MagicCookieOnly());
            byte[] packet = DhcpV4Packet.BuildUdpIpv4(IPAddress.Any, IPAddress.Broadcast,
                DhcpV4Packet.ClientPort, DhcpV4Packet.ServerPort, dhcp);

            // IPv4 version + protocol UDP, addressed to the client port via the reverse direction would parse;
            // here we sent client→server, so reading at the *client* port must reject it.
            Assert.False(DhcpV4Packet.TryReadUdpIpv4(packet, out _));

            // A server reply (67 → 68) is what the client accepts.
            byte[] reply = DhcpV4Packet.BuildUdpIpv4(ServerId, IPAddress.Broadcast,
                DhcpV4Packet.ServerPort, DhcpV4Packet.ClientPort, dhcp);
            Assert.True(DhcpV4Packet.TryReadUdpIpv4(reply, out ReadOnlyMemory<byte> extracted));
            Assert.Equal(dhcp, extracted.ToArray());
        }

        [Fact]
        public void MaskToPrefix_CountsContiguousOneBits()
        {
            Assert.Equal(24, DhcpV4Configurator.MaskToPrefix(IPAddress.Parse("255.255.255.0")));
            Assert.Equal(16, DhcpV4Configurator.MaskToPrefix(IPAddress.Parse("255.255.0.0")));
            Assert.Equal(30, DhcpV4Configurator.MaskToPrefix(IPAddress.Parse("255.255.255.252")));
            Assert.Equal(32, DhcpV4Configurator.MaskToPrefix(IPAddress.Parse("255.255.255.255")));
            Assert.Equal(0, DhcpV4Configurator.MaskToPrefix(IPAddress.Parse("0.0.0.0")));
        }

        // ---- ConfigureAsync against a captured-channel server ----

        [Fact]
        public async Task Configure_FullHandshake_ProducesTunnelConfig()
        {
            var port = new CaptureEthernetChannel();
            await using var dhcp = new DhcpV4Configurator(ClientMac, port, FastOptions);

            ValueTask<TunnelConfig> pending = dhcp.ConfigureAsync();

            // 1) DISCOVER goes out, broadcast UDP/IPv4 68→67.
            byte[] discoverFrame = await WaitForOneWrittenAsync(port);
            byte discoverType = ReadDhcpType(discoverFrame);
            Assert.Equal(DhcpV4Options.MessageDiscover, discoverType);
            uint xid = ReadXid(discoverFrame);
            Assert.Equal(EthernetFrame.EtherTypeIpv4, EthernetFrame.EtherType(discoverFrame));
            Assert.Equal(MacAddress.Broadcast, EthernetFrame.Destination(discoverFrame));

            // 2) Server OFFERs.
            dhcp.HandleInboundFrame(BuildServerReply(DhcpV4Options.MessageOffer, xid));

            // 3) REQUEST goes out echoing the offered address + server id.
            byte[] requestFrame = await WaitForWriteCountAsync(port, 2);
            byte[] requestDhcp = ExtractDhcp(requestFrame);
            byte[] reqOptions = DhcpV4Packet.OptionField(requestDhcp).ToArray();
            Assert.Equal(DhcpV4Options.MessageRequest, DhcpV4Options.ReadMessageType(reqOptions));
            Assert.Equal(Offered, DhcpV4Options.ReadAddress(reqOptions, DhcpV4Options.CodeRequestedIp));
            Assert.Equal(ServerId, DhcpV4Options.ReadAddress(reqOptions, DhcpV4Options.CodeServerId));

            // 4) Server ACKs.
            dhcp.HandleInboundFrame(BuildServerReply(DhcpV4Options.MessageAck, xid));

            TunnelConfig config = await pending;
            Assert.Equal(Offered, config.AssignedAddress);
            Assert.Equal(24, config.PrefixLength);                                  // 255.255.255.0 → /24
            Assert.Equal(new[] { Dns1, Dns2 }, config.DnsServers.ToArray());
            Assert.Equal($"0.0.0.0/0 {Router}", Assert.Single(config.Routes));
            Assert.Equal(Router, config.Gateway);                                   // the typed next hop the L2 bridge routes by
            Assert.Equal(FastOptions.Mtu, config.Mtu);
        }

        [Fact]
        public async Task Configure_ServerNak_Fails()
        {
            var port = new CaptureEthernetChannel();
            await using var dhcp = new DhcpV4Configurator(ClientMac, port, FastOptions);

            ValueTask<TunnelConfig> pending = dhcp.ConfigureAsync();
            byte[] discoverFrame = await WaitForOneWrittenAsync(port);
            uint xid = ReadXid(discoverFrame);
            dhcp.HandleInboundFrame(BuildServerReply(DhcpV4Options.MessageOffer, xid));
            await WaitForWriteCountAsync(port, 2);                                  // REQUEST went out
            dhcp.HandleInboundFrame(BuildServerReply(DhcpV4Options.MessageNak, xid));

            await Assert.ThrowsAsync<InvalidOperationException>(async () => await pending);
        }

        [Fact]
        public async Task Configure_NoServer_TimesOut()
        {
            var port = new CaptureEthernetChannel();
            var options = new DhcpV4ConfiguratorOptions(replyTimeout: TimeSpan.FromMilliseconds(20), maxAttempts: 2);
            await using var dhcp = new DhcpV4Configurator(ClientMac, port, options);

            await Assert.ThrowsAsync<InvalidOperationException>(async () => await dhcp.ConfigureAsync());
            Assert.True(port.Written.Count >= 2);   // DISCOVER retransmitted at least twice
        }

        [Fact]
        public async Task Configure_IgnoresReplyForWrongXid()
        {
            var port = new CaptureEthernetChannel();
            var options = new DhcpV4ConfiguratorOptions(replyTimeout: TimeSpan.FromMilliseconds(40), maxAttempts: 1);
            await using var dhcp = new DhcpV4Configurator(ClientMac, port, options);

            ValueTask<TunnelConfig> pending = dhcp.ConfigureAsync();
            await WaitForOneWrittenAsync(port);
            dhcp.HandleInboundFrame(BuildServerReply(DhcpV4Options.MessageOffer, 0x12345678));   // wrong xid — ignored

            // With only one attempt and no matching OFFER, the exchange fails.
            await Assert.ThrowsAsync<InvalidOperationException>(async () => await pending);
        }

        [Fact]
        public async Task Dispose_CancelsPendingConfigure()
        {
            var port = new CaptureEthernetChannel();
            var dhcp = new DhcpV4Configurator(ClientMac, port, FastOptions);

            ValueTask<TunnelConfig> pending = dhcp.ConfigureAsync();
            await WaitForOneWrittenAsync(port);
            await dhcp.DisposeAsync();

            await Assert.ThrowsAnyAsync<OperationCanceledException>(async () => await pending);
        }

        // ---- Integration: real DHCP exchange over the in-memory switch ----

        [Fact]
        public async Task Integration_DhcpOverSwitch_ConfiguresHost()
        {
            await using var sw = new EthernetSwitch();
            IEthernetChannel clientPort = sw.ConnectHost(ClientMac);
            IEthernetChannel serverPort = sw.ConnectHost(ServerMac);

            await using var dhcp = new DhcpV4Configurator(ClientMac, clientPort, FastOptions);
            // The VirtualHost surfaces the inbound IPv4 broadcast to the DHCP client (DHCP rides inside IPv4).
            await using var arp = new ArpResolver(ClientMac, Offered, clientPort);
            await using var host = new VirtualHost(ClientMac, clientPort, arp);
            host.InboundIpPacket += dhcp.HandleInboundFrame;

            // A minimal stub DHCP server on its own switch port: answers DISCOVER with OFFER, REQUEST with ACK.
            await using var server = new StubDhcpServer(ServerMac, serverPort);

            TunnelConfig config = await dhcp.ConfigureAsync();

            Assert.Equal(Offered, config.AssignedAddress);
            Assert.Equal(24, config.PrefixLength);
            Assert.Equal(new[] { Dns1, Dns2 }, config.DnsServers.ToArray());
            Assert.Equal($"0.0.0.0/0 {Router}", Assert.Single(config.Routes));
            Assert.Equal(Router, config.Gateway);                                   // the typed next hop the L2 bridge routes by
        }

        // ---- Helpers ----

        static byte[] MagicCookieOnly()
        {
            byte[] opt = new byte[8];
            int pos = DhcpV4Options.WriteMagicCookie(opt, 0);
            pos = DhcpV4Options.WriteEnd(opt, pos);
            return opt.AsSpan(0, pos).ToArray();
        }

        static byte[] ConcatAddresses(params IPAddress[] addresses)
        {
            byte[] result = new byte[addresses.Length * 4];
            for (int i = 0; i < addresses.Length; i++)
                addresses[i].GetAddressBytes().CopyTo(result, i * 4);
            return result;
        }

        static byte[] BuildServerReply(byte messageType, uint xid)
        {
            byte[] dhcp = BuildDhcpReply(messageType, xid);
            byte[] udpIp = DhcpV4Packet.BuildUdpIpv4(ServerId, IPAddress.Broadcast,
                DhcpV4Packet.ServerPort, DhcpV4Packet.ClientPort, dhcp);
            return EthernetFrame.Build(MacAddress.Broadcast, ServerMac, EthernetFrame.EtherTypeIpv4, udpIp);
        }

        static byte[] BuildDhcpReply(byte messageType, uint xid)
        {
            byte[] options = new byte[128];
            int pos = DhcpV4Options.WriteMagicCookie(options, 0);
            pos = DhcpV4Options.WriteOption(options, pos, DhcpV4Options.CodeMessageType, messageType);
            pos = DhcpV4Options.WriteOption(options, pos, DhcpV4Options.CodeServerId, ServerId);
            if (messageType != DhcpV4Options.MessageNak)
            {
                pos = DhcpV4Options.WriteOption(options, pos, DhcpV4Options.CodeSubnetMask, Mask);
                pos = DhcpV4Options.WriteOption(options, pos, DhcpV4Options.CodeRouter, Router);
                pos = DhcpV4Options.WriteOption(options, pos, DhcpV4Options.CodeDnsServer, ConcatAddresses(Dns1, Dns2));
                byte[] lease = { 0x00, 0x00, 0x0E, 0x10 };
                pos = DhcpV4Options.WriteOption(options, pos, DhcpV4Options.CodeLeaseTime, lease);
            }
            pos = DhcpV4Options.WriteEnd(options, pos);

            // yiaddr carries the offered/assigned address (zero on a NAK).
            byte[] msg = DhcpV4Packet.Build(xid, ClientMac, requestedCiaddr: null, broadcast: false, options.AsSpan(0, pos));
            msg[0] = DhcpV4Packet.OpBootReply;
            if (messageType != DhcpV4Options.MessageNak)
                Offered.GetAddressBytes().CopyTo(msg, 16);   // yiaddr at offset 16
            return msg;
        }

        static byte ReadDhcpType(byte[] frame) => DhcpV4Options.ReadMessageType(DhcpV4Packet.OptionField(ExtractDhcp(frame)).Span);

        static uint ReadXid(byte[] frame) => DhcpV4Packet.Xid(ExtractDhcp(frame));

        static byte[] ExtractDhcp(byte[] frame)
        {
            ReadOnlyMemory<byte> ip = EthernetFrame.Payload(frame);
            // The client's DISCOVER/REQUEST is 68→67; read it directly from the UDP payload (offset 20 IP + 8 UDP).
            ReadOnlySpan<byte> span = ip.Span;
            int ihl = (span[0] & 0x0F) * 4;
            return ip.Slice(ihl + 8).ToArray();
        }

        static async Task<byte[]> WaitForOneWrittenAsync(CaptureEthernetChannel port) => await WaitForWriteCountAsync(port, 1);

        static async Task<byte[]> WaitForWriteCountAsync(CaptureEthernetChannel port, int count)
        {
            for (int i = 0; i < 200; i++)
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

        /// <summary>A throwaway DHCP server bound to a switch port: OFFER for DISCOVER, ACK for REQUEST.</summary>
        sealed class StubDhcpServer : IAsyncDisposable
        {
            readonly MacAddress _mac;
            readonly IEthernetChannel _port;

            public StubDhcpServer(MacAddress mac, IEthernetChannel port)
            {
                _mac = mac;
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
                byte replyType = type switch
                {
                    DhcpV4Options.MessageDiscover => DhcpV4Options.MessageOffer,
                    DhcpV4Options.MessageRequest => DhcpV4Options.MessageAck,
                    _ => 0,
                };
                if (replyType == 0)
                    return;
                _ = _port.WriteFrameAsync(BuildServerReply(replyType, xid));
            }

            public ValueTask DisposeAsync()
            {
                _port.InboundFrame -= OnFrame;
                return default;
            }
        }
    }
}
