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

        [Fact]
        public void Capabilities_DescribeAnL3TlsDriverOverUdpOrTcpWithoutPpp()
        {
            VpnDriverCapabilities caps = new OpenVpnDriver(TunUdpProfile()).Capabilities;

            Assert.Equal("openvpn", new OpenVpnDriver(TunUdpProfile()).Name);
            Assert.Equal(VpnLinkLayer.L3Ip, caps.LinkLayer);          // tun-mode → IP channel directly
            Assert.False(caps.UsesPpp);                               // PUSH_REPLY config, not PPP
            Assert.Equal(VpnSecurityKind.Tls, caps.SecurityKinds);    // TLS control + AEAD data channel
            Assert.Equal(VpnTransportKind.Udp | VpnTransportKind.Tcp, caps.TransportKinds);
            Assert.Equal(VpnAuthMethod.Certificate | VpnAuthMethod.UserPassword, caps.AuthMethods);
            Assert.Equal(AddressAssignment.ConfigPush, caps.AddressAssignment);
            Assert.Equal(MultiHostModel.None, caps.MultiHostModel);
        }

        [Fact]
        public void Constructor_WithoutProfile_Throws()
        {
            Assert.Throws<ArgumentNullException>(() => new OpenVpnDriver(null!));
        }

        [Fact]
        public async Task ConnectAsync_TapDevice_IsRejected_BecauseL2FabricIsNotWired()
        {
            // tap-mode needs an L2 Ethernet fabric (DHCP/ARP — roadmap L2.5); the driver refuses it before any handshake.
            var driver = new OpenVpnDriver(new OpenVpnProfile { Protocol = OpenVpnProtocol.Udp, Device = OpenVpnDeviceType.Tap });
            var endpoint = new VpnEndpoint("127.0.0.1", 1194);

            await Assert.ThrowsAsync<TqkLibrary.VpnClient.Abstractions.Drivers.VpnConnectionException>(
                () => driver.ConnectAsync(endpoint, new VpnCredentials()));
        }

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
