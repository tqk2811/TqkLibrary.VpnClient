using TqkLibrary.VpnClient.Abstractions.Drivers.Enums;
using TqkLibrary.VpnClient.Abstractions.Drivers.Models;
using TqkLibrary.VpnClient.Drivers.CiscoIpsec;
using Xunit;

namespace TqkLibrary.VpnClient.Drivers.CiscoIpsec.Tests
{
    /// <summary>
    /// Server-free client checks for the Cisco IPsec / EzVPN driver: capability surface and the input guards. The live
    /// Aggressive Mode + XAUTH + Mode-Config + ESP-tunnel handshake/data plane is validated against a real gateway in
    /// lab cisco-ipsec (strongSwan Cisco-compatible remote-access); the protocol math (Aggressive Mode, XAUTH,
    /// Mode-Config, tunnel-mode Quick Mode) is covered by the IkeV1Client unit tests (IkeV1CiscoIpsecTests).
    /// </summary>
    public class CiscoIpsecDriverTests
    {
        static byte[] Psk(string s) => System.Text.Encoding.ASCII.GetBytes(s);

        [Fact]
        public void Capabilities_DescribeAnEspTunnelL3DriverWithoutPpp()
        {
            var driver = new CiscoIpsecDriver("vpngroup");
            VpnDriverCapabilities caps = driver.Capabilities;

            Assert.Equal("cisco-ipsec", driver.Name);
            Assert.Equal(VpnLinkLayer.L3Ip, caps.LinkLayer);
            Assert.False(caps.UsesPpp);                                  // ESP tunnel mode → IP channel directly
            Assert.Equal(VpnSecurityKind.Esp, caps.SecurityKinds);
            Assert.Equal(VpnTransportKind.Udp, caps.TransportKinds);
            // Group PSK (Aggressive Mode) + XAUTH user name/password.
            Assert.Equal(VpnAuthMethod.PreSharedKey | VpnAuthMethod.UserPassword, caps.AuthMethods);
            Assert.Equal(AddressAssignment.ConfigPush, caps.AddressAssignment); // Mode-Config pushes the virtual IP
            Assert.Equal(MultiHostModel.None, caps.MultiHostModel);
        }

        [Fact]
        public void Constructor_NullGroupName_Throws()
        {
            Assert.Throws<ArgumentNullException>(() => new CiscoIpsecDriver(null!));
        }

        [Fact]
        public async Task ConnectAsync_WithoutGroupPreSharedKey_ThrowsArgumentException()
        {
            var driver = new CiscoIpsecDriver("vpngroup");
            var endpoint = new VpnEndpoint("vpn.example.com", 500);

            await Assert.ThrowsAsync<ArgumentException>(() =>
                driver.ConnectAsync(endpoint, new VpnCredentials { PreSharedKey = null, Username = "u", Password = "p" }));
            await Assert.ThrowsAsync<ArgumentException>(() =>
                driver.ConnectAsync(endpoint, new VpnCredentials { PreSharedKey = Array.Empty<byte>(), Username = "u", Password = "p" }));
        }

        [Fact]
        public async Task ConnectAsync_WithMissingXAuthCredentials_ThrowsArgumentException()
        {
            // XAUTH needs both the user name and the password; either half missing is rejected before any network I/O.
            var driver = new CiscoIpsecDriver("vpngroup");
            var endpoint = new VpnEndpoint("vpn.example.com", 500);
            byte[] groupPsk = Psk("groupsecret");

            await Assert.ThrowsAsync<ArgumentException>(() =>
                driver.ConnectAsync(endpoint, new VpnCredentials { PreSharedKey = groupPsk, Username = "user" }));
            await Assert.ThrowsAsync<ArgumentException>(() =>
                driver.ConnectAsync(endpoint, new VpnCredentials { PreSharedKey = groupPsk, Password = "secret" }));
            await Assert.ThrowsAsync<ArgumentException>(() =>
                driver.ConnectAsync(endpoint, new VpnCredentials { PreSharedKey = groupPsk }));
        }

        [Fact]
        public async Task OpenSessionAsync_IsRejected_BecauseCiscoIpsecIsSingleChildSa()
        {
            // The connection is never established here; we only assert the documented single-session policy.
            var inner = new CiscoIpsecConnection("vpn.example.com", "vpngroup", Psk("groupsecret"), "user", "pass");
            await using var connection = new CiscoIpsecVpnConnection(inner,
                new CiscoIpsecVpnSession(inner.PacketChannel, new TunnelConfig()));

            Assert.Single(connection.Sessions);
            await Assert.ThrowsAsync<NotSupportedException>(() => connection.OpenSessionAsync());
        }
    }
}
