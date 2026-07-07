using System;
using System.Net;
using TqkLibrary.VpnClient.Abstractions.Drivers.Enums;
using TqkLibrary.VpnClient.Drivers.EoGre;
using TqkLibrary.VpnClient.Drivers.EoGre.Config;
using TqkLibrary.VpnClient.Drivers.EoGre.Enums;
using Xunit;

namespace TqkLibrary.VpnClient.Drivers.EoGre.Tests
{
    /// <summary>Verifies the driver's advertised capabilities and its mode-derived name (eogre / nvgre).</summary>
    public class EoGreDriverTests
    {
        static EoGreConfig BuildConfig(uint? vsid = 0x000064) => new EoGreConfig
        {
            Vsid = vsid,
            OverlayAddress = IPAddress.Parse("10.20.0.2"),
        };

        [Fact]
        public void Driver_AdvertisesL2Udp_NoSecurity_NoElevation()
        {
            var driver = new EoGreDriver(BuildConfig());

            Assert.Equal("eogre", driver.Name);
            Assert.Equal(VpnLinkLayer.L2Ethernet, driver.Capabilities.LinkLayer);
            Assert.Equal(VpnTransportKind.Udp, driver.Capabilities.TransportKinds);
            Assert.Equal(VpnSecurityKind.None, driver.Capabilities.SecurityKinds);
            Assert.Equal(VpnAuthMethod.None, driver.Capabilities.AuthMethods);
            Assert.Equal(AddressAssignment.OutOfBand, driver.Capabilities.AddressAssignment);
            Assert.False(driver.Capabilities.RequiresElevation);
            Assert.False(driver.Capabilities.RequiresRawIpSocket);
            Assert.False(driver.Capabilities.UsesPpp);
        }

        [Fact]
        public void Driver_NvgreMode_HasNvgreName()
        {
            var driver = new EoGreDriver(BuildConfig(), EoGreMode.Nvgre);
            Assert.Equal("nvgre", driver.Name);
        }

        [Fact]
        public void Driver_NvgreMode_Throws_WhenNoVsid()
        {
            Assert.Throws<ArgumentException>(() => new EoGreDriver(BuildConfig(vsid: null), EoGreMode.Nvgre));
        }

        [Fact]
        public void Driver_EoGreMode_AllowsNoVsid()
        {
            var driver = new EoGreDriver(BuildConfig(vsid: null), EoGreMode.EoGre);
            Assert.Equal("eogre", driver.Name);
        }
    }
}
