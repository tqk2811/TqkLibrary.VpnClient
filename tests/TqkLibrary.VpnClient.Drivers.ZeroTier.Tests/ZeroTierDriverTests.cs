using System.Net;
using TqkLibrary.VpnClient.Abstractions.Drivers.Enums;
using TqkLibrary.VpnClient.Abstractions.Drivers.Models;
using TqkLibrary.VpnClient.Drivers.ZeroTier.Config;
using TqkLibrary.VpnClient.ZeroTier.Identity;
using TqkLibrary.VpnClient.ZeroTier.Identity.Models;
using TqkLibrary.VpnClient.ZeroTier.Vl2.Models;
using Xunit;

namespace TqkLibrary.VpnClient.Drivers.ZeroTier.Tests
{
    /// <summary>Driver-surface tests: capabilities, name, and the single-session contract (mirrors the n2n driver tests).</summary>
    public class ZeroTierDriverTests
    {
        const string ClientSecret =
            "0ef6d8cebd:0:490d7a076365facb4bb070cca733d251055fbd089a5dc372b67c07295b84a108dbb9c861d301d92bbdda8ecf89dbd4a204b044946f8f1af5883106c4c66d6017" +
            ":1cf9b219d9693b2eed3d24a43e0033a5a5fa52c830efcac164ad0c592f27bbfdae6c19ffd91a37c600adec412dd1b5c145ab519c288a6ca5d046469f78b909d3";
        const string NodePublic =
            "7494911ed3:0:02df0fa2fca3ef4e618c063d325217d5484b4b3de85302c3731481098841525b08e3ff6b728ce7f4f73496489159680827d4f96bd2fcc048bff57d07fe320d28";

        static ZeroTierConfig BuildConfig()
        {
            var codec = new ZeroTierIdentityCodec();
            return new ZeroTierConfig
            {
                Identity = codec.ParseString(ClientSecret),
                PeerIdentity = codec.ParseString(NodePublic),
                NetworkId = NetworkId.Parse("7494911ed3000001"),
                OverlayAddress = IPAddress.Parse("10.144.0.2"),
            };
        }

        [Fact]
        public void Capabilities_ReportL2Ethernet_Udp_OutOfBand()
        {
            var driver = new ZeroTierDriver(BuildConfig());
            Assert.Equal("zerotier", driver.Name);
            Assert.Equal(VpnLinkLayer.L2Ethernet, driver.Capabilities.LinkLayer);
            Assert.Equal(VpnTransportKind.Udp, driver.Capabilities.TransportKinds);
            Assert.Equal(AddressAssignment.OutOfBand, driver.Capabilities.AddressAssignment);
            Assert.False(driver.Capabilities.UsesPpp);
        }

        [Fact]
        public void Connection_RejectsIdentityWithoutPrivateKey()
        {
            var codec = new ZeroTierIdentityCodec();
            var config = new ZeroTierConfig
            {
                Identity = codec.ParseString(NodePublic),   // public-only: no private key for ECDH
                PeerIdentity = codec.ParseString(NodePublic),
                NetworkId = NetworkId.Parse("7494911ed3000001"),
                OverlayAddress = IPAddress.Parse("10.144.0.2"),
            };
            Assert.Throws<ArgumentException>(() =>
                new ZeroTierConnection("127.0.0.1", 9993, config,
                    new InProcessZeroTierTransportFactory(new LoopbackUdpLink().Client)));
        }
    }
}
