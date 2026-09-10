using System.Net;
using System.Text;
using TqkLibrary.VpnClient.Abstractions.Drivers.Models;
using TqkLibrary.VpnClient.OpenVpn.DataChannel;
using Xunit;

namespace TqkLibrary.VpnClient.OpenVpn.Tests
{
    /// <summary>
    /// Tests the V2.e config pull: the PUSH_REPLY parser and its mapping onto <see cref="TunnelConfig"/>, plus the
    /// NUL-terminated control-message codec used to carry PUSH_REQUEST/PUSH_REPLY over the TLS channel.
    /// </summary>
    public class OpenVpnPushReplyTests
    {
        [Fact]
        public void TryParse_SubnetTopology_MapsToTunnelConfig()
        {
            const string push = "PUSH_REPLY,redirect-gateway def1,route-gateway 10.8.0.1,topology subnet," +
                "ping 10,ping-restart 60,ifconfig 10.8.0.6 255.255.255.0,route 192.168.1.0 255.255.255.0," +
                "dhcp-option DNS 8.8.8.8,dhcp-option DNS 1.1.1.1,peer-id 3,cipher AES-256-GCM";

            Assert.True(OpenVpnPushReply.TryParse(push, out OpenVpnPushReply reply));
            Assert.Equal(IPAddress.Parse("10.8.0.6"), reply.IfconfigLocal);
            Assert.Equal(IPAddress.Parse("10.8.0.1"), reply.RouteGateway);
            Assert.Equal("subnet", reply.Topology);
            Assert.Equal(3u, reply.PeerId);
            Assert.Equal(10, reply.Ping);
            Assert.Equal(60, reply.PingRestart);
            Assert.Equal("AES-256-GCM", reply.Cipher);
            Assert.Equal(new[] { IPAddress.Parse("8.8.8.8"), IPAddress.Parse("1.1.1.1") }, reply.DnsServers);
            Assert.Equal(new[] { "192.168.1.0/24" }, reply.Routes);

            TunnelConfig config = reply.ToTunnelConfig();
            Assert.Equal(IPAddress.Parse("10.8.0.6"), config.AssignedAddress);
            Assert.Equal(24, config.PrefixLength); // from the 255.255.255.0 netmask
            Assert.Equal(IPAddress.Parse("10.8.0.1"), config.Gateway);   // the next hop a tap bridge sends off-link packets to
            Assert.Equal(2, config.DnsServers.Count);
            Assert.Equal(new[] { "192.168.1.0/24" }, config.Routes);
        }

        [Fact]
        public void TryParse_Net30Topology_UsesPrefix30()
        {
            Assert.True(OpenVpnPushReply.TryParse("PUSH_REPLY,topology net30,ifconfig 10.8.0.6 10.8.0.5", out OpenVpnPushReply reply));
            Assert.Equal(IPAddress.Parse("10.8.0.5"), reply.IfconfigRemoteOrMask);
            Assert.Equal(30, reply.ToTunnelConfig().PrefixLength);
        }

        [Fact]
        public void TryParse_RejectsNonPushReply()
        {
            Assert.False(OpenVpnPushReply.TryParse("AUTH_FAILED,session expired", out _));
            Assert.False(OpenVpnPushReply.TryParse("", out _));
        }

        [Fact]
        public void TryParse_KeepsUnknownOptionsVerbatim()
        {
            Assert.True(OpenVpnPushReply.TryParse("PUSH_REPLY,explicit-exit-notify,sndbuf 0", out OpenVpnPushReply reply));
            Assert.Contains("explicit-exit-notify", reply.Options);
            Assert.Contains("sndbuf 0", reply.Options);
        }

        [Fact]
        public async Task ControlMessage_RoundTripsThroughAStream()
        {
            byte[] wire = OpenVpnControlMessage.Build("PUSH_REQUEST");
            Assert.Equal(0, wire[^1]); // NUL terminated
            Assert.Equal("PUSH_REQUEST", Encoding.ASCII.GetString(wire, 0, wire.Length - 1));

            using var stream = new MemoryStream();
            await stream.WriteAsync(wire, 0, wire.Length);
            stream.Position = 0;
            Assert.Equal("PUSH_REQUEST", await OpenVpnControlMessage.ReadAsync(stream));
        }
    }
}
