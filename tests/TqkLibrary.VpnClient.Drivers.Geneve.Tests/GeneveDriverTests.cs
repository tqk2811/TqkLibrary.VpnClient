using System.Net;
using TqkLibrary.VpnClient.Abstractions.Drivers.Enums;
using TqkLibrary.VpnClient.Drivers.Geneve;
using TqkLibrary.VpnClient.Drivers.Geneve.Config;
using Xunit;

namespace TqkLibrary.VpnClient.Drivers.Geneve.Tests
{
    /// <summary>Verifies the driver's advertised capabilities (L2 / UDP / no security / no auth / no elevation).</summary>
    public class GeneveDriverTests
    {
        static GeneveConfig BuildConfig() => new GeneveConfig
        {
            Vni = 0x000064,
            OverlayAddress = IPAddress.Parse("10.20.0.2"),
        };

        [Fact]
        public void Driver_AdvertisesL2Udp_NoSecurity_NoElevation()
        {
            var driver = new GeneveDriver(BuildConfig());

            Assert.Equal("geneve", driver.Name);
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
