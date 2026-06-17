using TqkLibrary.VpnClient.Abstractions.Drivers.Enums;
using TqkLibrary.VpnClient.Abstractions.Drivers.Models;
using TqkLibrary.VpnClient.OpenVpn.Config;
using TqkLibrary.VpnClient.OpenVpn.Enums;
using Xunit;

namespace TqkLibrary.VpnClient.Drivers.OpenVpn.Tests
{
    /// <summary>
    /// Server-free client checks for the OpenVPN driver: the capability surface and the input guards. The full handshake
    /// + data plane is driven offline against an in-process responder in <see cref="OpenVpnConnectionHandshakeTests"/>,
    /// and validated live in lab Q.1 (an OpenVPN community server).
    /// </summary>
    public class OpenVpnDriverTests
    {
        static OpenVpnProfile TunUdpProfile() => new() { Protocol = OpenVpnProtocol.Udp, Device = OpenVpnDeviceType.Tun };
        static OpenVpnProfile TapUdpProfile() => new() { Protocol = OpenVpnProtocol.Udp, Device = OpenVpnDeviceType.Tap };

        [Fact]
        public void Capabilities_TunMode_DescribeAnL3SingleHostTlsDriverOverUdpOrTcpWithoutPpp()
        {
            VpnDriverCapabilities caps = new OpenVpnDriver(TunUdpProfile()).Capabilities;

            Assert.Equal("openvpn", new OpenVpnDriver(TunUdpProfile()).Name);
            Assert.Equal(VpnLinkLayer.L3Ip, caps.LinkLayer);          // tun-mode → IP channel directly
            Assert.False(caps.SupportsMultiHost);                     // one assigned IP per connection
            Assert.Equal(MultiHostModel.None, caps.MultiHostModel);
            Assert.False(caps.UsesPpp);                               // PUSH_REPLY config, not PPP
            Assert.Equal(VpnSecurityKind.Tls, caps.SecurityKinds);    // TLS control + AEAD data channel
            Assert.Equal(VpnTransportKind.Udp | VpnTransportKind.Tcp, caps.TransportKinds);
            Assert.Equal(VpnAuthMethod.Certificate | VpnAuthMethod.UserPassword, caps.AuthMethods);
            Assert.Equal(AddressAssignment.ConfigPush, caps.AddressAssignment);
        }

        [Fact]
        public void Capabilities_TapMode_DescribeAnL2BroadcastDomain()
        {
            // L2.8 — tap-mode bridges Ethernet frames through the userspace L2 fabric (EthernetAdapter), so the driver
            // advertises an L2Ethernet / L2BroadcastDomain multi-host capability instead of single-host L3.
            VpnDriverCapabilities caps = new OpenVpnDriver(TapUdpProfile()).Capabilities;

            Assert.Equal(VpnLinkLayer.L2Ethernet, caps.LinkLayer);
            Assert.True(caps.SupportsMultiHost);
            Assert.Equal(MultiHostModel.L2BroadcastDomain, caps.MultiHostModel);
            // Everything else matches tun mode (same control/data security, transports, auth, address push).
            Assert.False(caps.UsesPpp);
            Assert.Equal(VpnSecurityKind.Tls, caps.SecurityKinds);
            Assert.Equal(VpnTransportKind.Udp | VpnTransportKind.Tcp, caps.TransportKinds);
            Assert.Equal(VpnAuthMethod.Certificate | VpnAuthMethod.UserPassword, caps.AuthMethods);
            Assert.Equal(AddressAssignment.ConfigPush, caps.AddressAssignment);
        }

        [Fact]
        public void Constructor_WithoutProfile_Throws()
        {
            Assert.Throws<ArgumentNullException>(() => new OpenVpnDriver(null!));
        }

        // tap-mode is no longer rejected — it bridges the Ethernet data channel through the userspace L2 fabric. Its
        // end-to-end behaviour (address bind, IP round-trip over ARP, and the no-ifconfig → DHCP/L2.5 guard) is driven
        // against an in-process responder in OpenVpnConnectionTapHandshakeTests.

        [Fact]
        public async Task OpenSessionAsync_IsRejected_BecauseTunModeIsSingleSession()
        {
            // The connection is never established; we only assert the documented single-session policy.
            var inner = new OpenVpnConnection("127.0.0.1", 1194, new ThrowingTransportFactory());
            await using var connection = new OpenVpnVpnConnection(inner,
                new OpenVpnVpnSession(inner.PacketChannel, new TunnelConfig()));

            Assert.Single(connection.Sessions);
            await Assert.ThrowsAsync<NotSupportedException>(() => connection.OpenSessionAsync());
        }

        sealed class ThrowingTransportFactory : Transport.IOpenVpnTransportFactory
        {
            public Task<Transport.OpenVpnTransportHandle> ConnectAsync(System.Net.IPEndPoint remote, CancellationToken cancellationToken)
                => throw new InvalidOperationException("not used");
        }
    }
}
