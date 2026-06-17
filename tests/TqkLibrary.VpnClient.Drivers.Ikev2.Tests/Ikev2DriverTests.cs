using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using TqkLibrary.VpnClient.Abstractions.Drivers.Enums;
using TqkLibrary.VpnClient.Abstractions.Drivers.Models;
using TqkLibrary.VpnClient.Drivers.Ikev2;
using TqkLibrary.VpnClient.Ipsec.Ike.V2.Models;
using Xunit;

namespace TqkLibrary.VpnClient.Drivers.Ikev2.Tests
{
    /// <summary>
    /// Server-free client checks for the IKEv2-native driver: capability surface and the input guards. The live
    /// handshake/data plane is validated against a real gateway in lab Q.1 (strongSwan); the protocol math is
    /// covered by the IkeClient / EspTunnelChannel unit tests.
    /// </summary>
    public class Ikev2DriverTests
    {
        [Fact]
        public void Capabilities_DescribeAnEspTunnelL3DriverWithoutPpp()
        {
            VpnDriverCapabilities caps = new Ikev2Driver().Capabilities;

            Assert.Equal("ikev2", new Ikev2Driver().Name);
            Assert.Equal(VpnLinkLayer.L3Ip, caps.LinkLayer);
            Assert.False(caps.UsesPpp);                                  // ESP tunnel mode → IP channel directly
            Assert.Equal(VpnSecurityKind.Esp, caps.SecurityKinds);
            Assert.Equal(VpnTransportKind.Udp, caps.TransportKinds);
            Assert.Equal(VpnAuthMethod.PreSharedKey | VpnAuthMethod.Eap, caps.AuthMethods); // PSK or EAP-MSCHAPv2
            Assert.Equal(AddressAssignment.ConfigPush, caps.AddressAssignment); // CFG_REPLY pushes the virtual IP
            Assert.Equal(MultiHostModel.None, caps.MultiHostModel);
        }

        [Fact]
        public void Capabilities_AdvertiseCertificate_WhenResponderTrustConfigured()
        {
            using var rsa = RSA.Create(2048);
            var request = new CertificateRequest("CN=gateway", rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
            using X509Certificate2 cert = request.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddDays(1));

            var driver = new Ikev2Driver(responderTrust: IkeCertificateTrust.PinLeaf(cert));
            VpnDriverCapabilities caps = driver.Capabilities;

            // Certificate is added to the always-present PSK/EAP methods when a trust anchor is configured.
            Assert.True(caps.AuthMethods.HasFlag(VpnAuthMethod.Certificate));
            Assert.True(caps.AuthMethods.HasFlag(VpnAuthMethod.PreSharedKey));
            Assert.True(caps.AuthMethods.HasFlag(VpnAuthMethod.Eap));
        }

        [Fact]
        public async Task ConnectAsync_WithoutPreSharedKey_ThrowsArgumentException()
        {
            var driver = new Ikev2Driver();
            var endpoint = new VpnEndpoint("vpn.example.com", 500);

            await Assert.ThrowsAsync<ArgumentException>(() =>
                driver.ConnectAsync(endpoint, new VpnCredentials { PreSharedKey = null }));
            await Assert.ThrowsAsync<ArgumentException>(() =>
                driver.ConnectAsync(endpoint, new VpnCredentials { PreSharedKey = Array.Empty<byte>() }));
        }

        [Fact]
        public async Task ConnectAsync_WithUserNameButNoPassword_ThrowsArgumentException()
        {
            // EAP-MSCHAPv2 needs both halves; a half-filled credential is rejected before any network I/O.
            var driver = new Ikev2Driver();
            var endpoint = new VpnEndpoint("vpn.example.com", 500);
            byte[] psk = System.Text.Encoding.ASCII.GetBytes("vpn");

            await Assert.ThrowsAsync<ArgumentException>(() =>
                driver.ConnectAsync(endpoint, new VpnCredentials { PreSharedKey = psk, Username = "user" }));
            await Assert.ThrowsAsync<ArgumentException>(() =>
                driver.ConnectAsync(endpoint, new VpnCredentials { PreSharedKey = psk, Password = "secret" }));
        }

        [Fact]
        public async Task OpenSessionAsync_IsRejected_BecauseIkev2IsSingleChildSa()
        {
            // The connection is never established here; we only assert the documented single-session policy.
            var inner = new Ikev2Connection("vpn.example.com", System.Text.Encoding.ASCII.GetBytes("vpn"));
            await using var connection = new Ikev2VpnConnection(inner, new Ikev2VpnSession(inner.PacketChannel, new TunnelConfig()));

            Assert.Single(connection.Sessions);
            await Assert.ThrowsAsync<NotSupportedException>(() => connection.OpenSessionAsync());
        }
    }
}
