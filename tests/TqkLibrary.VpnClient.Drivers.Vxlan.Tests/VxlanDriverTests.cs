using System.Net;
using TqkLibrary.VpnClient.Abstractions.Drivers.Enums;
using TqkLibrary.VpnClient.Drivers.Vxlan;
using TqkLibrary.VpnClient.Drivers.Vxlan.Config;
using Xunit;

namespace TqkLibrary.VpnClient.Drivers.Vxlan.Tests
{
    /// <summary>Verifies the driver's advertised capabilities (L2 / UDP / no security / no auth / no elevation).</summary>
    public class VxlanDriverTests
    {
        static VxlanConfig BuildConfig() => new VxlanConfig
        {
            Vni = 0x000064,
            OverlayAddress = IPAddress.Parse("10.20.0.2"),
        };

        [Fact]
        public void Driver_AdvertisesL2Udp_NoSecurity_NoElevation()
        {
            var driver = new VxlanDriver(BuildConfig());

            Assert.Equal("vxlan", driver.Name);
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
