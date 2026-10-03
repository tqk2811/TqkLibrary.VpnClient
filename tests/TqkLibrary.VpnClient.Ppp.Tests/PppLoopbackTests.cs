using System.Net;
using TqkLibrary.VpnClient.Ppp;
using Xunit;

namespace TqkLibrary.VpnClient.Ppp.Tests
{
    public class PppLoopbackTests
    {
        static readonly IPAddress ClientIp = IPAddress.Parse("10.0.0.2");
        static readonly IPAddress ServerIp = IPAddress.Parse("10.0.0.1");
        static readonly IPAddress Dns = IPAddress.Parse("8.8.8.8");

        [Fact]
        public void TwoEngines_NegotiateLcpAndIpcp_ClientGetsAssignedAddress()
        {
            var (ca, cb) = LoopbackPppChannel.CreatePair();

            var client = new PppEngine(ca, magic: 0x11111111, localAddress: IPAddress.Any);
            var server = new PppEngine(cb, magic: 0x22222222, localAddress: ServerIp, assignPeerAddress: ClientIp, assignPeerDns: Dns);

            bool clientUp = false;
            client.LinkUp += () => clientUp = true;

            client.Start();
            server.Start();
            LoopbackPppChannel.Pump(ca, cb);

            Assert.True(clientUp);
            Assert.True(server.IsLinkUp);
            Assert.Equal(ClientIp, client.AssignedAddress);
            Assert.Equal(Dns, client.AssignedDns);
            Assert.Equal(ServerIp, server.AssignedAddress);
        }

        [Fact]
        public void TwoEngines_DualStack_ClientGetsIpv4AndLinkLocalIpv6()
        {
            var (ca, cb) = LoopbackPppChannel.CreatePair();
            byte[] assignedIid = { 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x42 };

            var client = new PppEngine(ca, magic: 0x11111111, localAddress: IPAddress.Any, enableIpv6: true);
            var server = new PppEngine(cb, magic: 0x22222222, localAddress: ServerIp,
                assignPeerAddress: ClientIp, assignPeerDns: Dns,
                enableIpv6: true, assignPeerInterfaceId: assignedIid);

            bool v4 = false, v6 = false;
            client.LinkUp += () => v4 = true;
            client.Ipv6Up += () => v6 = true;

            client.Start();
            server.Start();
            LoopbackPppChannel.Pump(ca, cb);

            Assert.True(v4);                                       // IPCP unaffected by enabling IPv6
            Assert.True(v6);
            Assert.Equal(ClientIp, client.AssignedAddress);
            Assert.Equal(IPAddress.Parse("fe80::200:0:0:42"), client.AssignedAddressV6);
            Assert.True(server.IsIpv6Up);
        }

        [Fact]
        public void DescribeNetworkLayer_DualStack_ReportsAddressDnsAndLinkLocal()
        {
            var (ca, cb) = LoopbackPppChannel.CreatePair();
            var client = new PppEngine(ca, 0x11111111, IPAddress.Any, enableIpv6: true);
            var server = new PppEngine(cb, 0x22222222, ServerIp, ClientIp, Dns,
                enableIpv6: true, assignPeerInterfaceId: new byte[] { 0x02, 0, 0, 0, 0, 0, 0, 0x42 });

            client.Start();
            server.Start();
            LoopbackPppChannel.Pump(ca, cb);

            Assert.Equal("IPv4 10.0.0.2, DNS 8.8.8.8; IPv6 link-local fe80::200:0:0:42", client.DescribeNetworkLayer());
        }

        [Fact]
        public void DescribeNetworkLayer_ServerWithoutIpv6_SaysIpv6WasNotOffered()
        {
            var (ca, cb) = LoopbackPppChannel.CreatePair();
            var client = new PppEngine(ca, 0x11111111, IPAddress.Any, enableIpv6: true);
            var server = new PppEngine(cb, 0x22222222, ServerIp, ClientIp, Dns);   // ignores IPV6CP silently

            client.Start();
            server.Start();
            LoopbackPppChannel.Pump(ca, cb);

            Assert.False(client.Ipv6RejectedByPeer);
            Assert.Equal("IPv4 10.0.0.2, DNS 8.8.8.8; IPv6 not offered (the server never opened IPV6CP)", client.DescribeNetworkLayer());
        }

        [Fact]
        public void LcpProtocolRejectOfIpv6cp_IsRecordedAndDescribed()
        {
            var (ca, cb) = LoopbackPppChannel.CreatePair();
            var client = new PppEngine(ca, 0x11111111, IPAddress.Any, enableIpv6: true);
            var server = new PppEngine(cb, 0x22222222, ServerIp, ClientIp, Dns);

            client.Start();
            server.Start();
            LoopbackPppChannel.Pump(ca, cb);

            // What an IPv4-only server (e.g. RRAS) answers to IPV6CP: LCP (C021) Protocol-Reject (code 8) naming 0x8057.
            cb.SendAsync(new byte[] { 0xFF, 0x03, 0xC0, 0x21, 0x08, 0x07, 0x00, 0x06, 0x80, 0x57 });
            ca.Deliver();

            Assert.True(client.Ipv6RejectedByPeer);
            Assert.True(client.IsLinkUp);   // IPv4 unaffected
            Assert.Equal("IPv4 10.0.0.2, DNS 8.8.8.8; IPv6 refused by the server (Protocol-Reject of IPV6CP)", client.DescribeNetworkLayer());
        }

        [Fact]
        public void LcpProtocolRejectOfAnotherProtocol_DoesNotMarkIpv6Refused()
        {
            var (ca, cb) = LoopbackPppChannel.CreatePair();
            var client = new PppEngine(ca, 0x11111111, IPAddress.Any, enableIpv6: true);

            cb.SendAsync(new byte[] { 0xFF, 0x03, 0xC0, 0x21, 0x08, 0x07, 0x00, 0x06, 0x80, 0xFD });   // CCP
            ca.Deliver();

            Assert.False(client.Ipv6RejectedByPeer);
        }

        [Fact]
        public void DescribeNetworkLayer_Ipv6Disabled_SaysNotRequested()
        {
            var (ca, cb) = LoopbackPppChannel.CreatePair();
            var client = new PppEngine(ca, 0x11111111, IPAddress.Any);
            var server = new PppEngine(cb, 0x22222222, ServerIp, ClientIp, Dns);

            client.Start();
            server.Start();
            LoopbackPppChannel.Pump(ca, cb);

            Assert.Equal("IPv4 10.0.0.2, DNS 8.8.8.8; IPv6 not requested", client.DescribeNetworkLayer());
        }

        [Fact]
        public void AfterLinkUp_IpPacketIsRelayed()
        {
            var (ca, cb) = LoopbackPppChannel.CreatePair();
            var client = new PppEngine(ca, 0x11111111, IPAddress.Any);
            var server = new PppEngine(cb, 0x22222222, ServerIp, ClientIp, Dns);

            client.Start();
            server.Start();
            LoopbackPppChannel.Pump(ca, cb);
            Assert.True(client.IsLinkUp);

            byte[]? received = null;
            server.PacketChannel.InboundIpPacket += p => received = p.ToArray();

            // A minimal 20-byte IPv4 header (content is opaque to PPP — it just relays).
            byte[] ipPacket =
            {
                0x45, 0x00, 0x00, 0x14, 0x00, 0x01, 0x00, 0x00,
                0x40, 0x01, 0x00, 0x00, 0x0A, 0x00, 0x00, 0x02,
                0x0A, 0x00, 0x00, 0x01,
            };

            client.PacketChannel.WriteIpPacketAsync(ipPacket);
            LoopbackPppChannel.Pump(ca, cb);

            Assert.Equal(ipPacket, received);
        }

        [Fact]
        public void DualStack_Ipv6PacketIsRelayedOnTheSameChannel()
        {
            var (ca, cb) = LoopbackPppChannel.CreatePair();
            var client = new PppEngine(ca, 0x11111111, IPAddress.Any, enableIpv6: true);
            var server = new PppEngine(cb, 0x22222222, ServerIp, ClientIp, Dns,
                enableIpv6: true, assignPeerInterfaceId: new byte[] { 0x02, 0, 0, 0, 0, 0, 0, 0x42 });

            client.Start();
            server.Start();
            LoopbackPppChannel.Pump(ca, cb);
            Assert.True(client.IsIpv6Up);

            byte[]? received = null;
            server.PacketChannel.InboundIpPacket += p => received = p.ToArray();

            // A minimal 40-byte IPv6 header (version nibble 6) — PPP must carry it as protocol 0x0057, not 0x0021.
            byte[] ipv6Packet = new byte[40];
            ipv6Packet[0] = 0x60;                 // version 6, traffic class/flow 0
            ipv6Packet[6] = 59;                   // NextHeader = No Next Header

            client.PacketChannel.WriteIpPacketAsync(ipv6Packet);
            LoopbackPppChannel.Pump(ca, cb);

            Assert.Equal(ipv6Packet, received);   // demuxed back into the one L3 channel on the server side
        }
    }
}
