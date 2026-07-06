using System.Net;
using TqkLibrary.VpnClient.Abstractions.Drivers.Enums;
using TqkLibrary.VpnClient.Drivers.L2tpv3Eth;
using TqkLibrary.VpnClient.Drivers.L2tpv3Eth.Config;
using Xunit;

namespace TqkLibrary.VpnClient.Drivers.L2tpv3Eth.Tests
{
    /// <summary>Verifies the driver's advertised capabilities (L2 / UDP / no security / no auth / no elevation).</summary>
    public class L2tpv3EthDriverTests
    {
        static L2tpv3EthConfig BuildConfig() => new L2tpv3EthConfig
        {
            LocalSessionId = 0x00000101,
            RemoteSessionId = 0x00000202,
            OverlayAddress = IPAddress.Parse("10.30.0.2"),
        };

        [Fact]
        public void Driver_AdvertisesL2Udp_NoSecurity_NoElevation()
        {
            var driver = new L2tpv3EthDriver(BuildConfig());

            Assert.Equal("l2tpv3-eth", driver.Name);
            Assert.Equal(VpnLinkLayer.L2Ethernet, driver.Capabilities.LinkLayer);
            Assert.Equal(VpnTransportKind.Udp, driver.Capabilities.TransportKinds);
            Assert.Equal(VpnSecurityKind.None, driver.Capabilities.SecurityKinds);
            Assert.Equal(VpnAuthMethod.None, driver.Capabilities.AuthMethods);
            Assert.Equal(AddressAssignment.OutOfBand, driver.Capabilities.AddressAssignment);
            Assert.False(driver.Capabilities.RequiresElevation);
            Assert.False(driver.Capabilities.RequiresRawIpSocket);
            Assert.False(driver.Capabilities.UsesPpp);
        }
    }
}
