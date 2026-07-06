using System;
using System.Net;
using System.Threading.Tasks;
using TqkLibrary.VpnClient.Abstractions.Channels.Enums;
using TqkLibrary.VpnClient.Abstractions.Drivers.Models;
using TqkLibrary.VpnClient.Drivers.VxlanGpe;
using TqkLibrary.VpnClient.Drivers.VxlanGpe.Config;
using TqkLibrary.VpnClient.Drivers.VxlanGpe.DataChannel;
using TqkLibrary.VpnClient.Drivers.VxlanGpe.Enums;
using TqkLibrary.VpnClient.Ethernet;
using Xunit;

namespace TqkLibrary.VpnClient.Drivers.VxlanGpe.Tests
{
    /// <summary>Unit tests for the L2 data-plane channel and the static config projection (no transport / no fabric).</summary>
    public class VxlanGpeEthernetChannelTests
    {
        const uint Vni = 0x0A0B0C;

        static byte[] BuildEthernetFrame(MacAddress dst, MacAddress src, byte tail)
        {
            byte[] payload = new byte[20];
            payload[19] = tail;
            return EthernetFrame.Build(dst, src, EthernetFrame.EtherTypeIpv4, payload);
        }

        [Fact]
        public async Task WriteFrame_EncapsulatesFrame_WithGpeHeader_AndCodecRoundTrips()
        {
            MacAddress src = MacAddress.Parse("02:00:00:00:00:01");
            MacAddress dst = MacAddress.Parse("02:00:00:00:00:02");

            byte[]? sent = null;
            var channel = new VxlanGpeEthernetChannel(Vni, VxlanGpeHeader.NextProtocolEthernet, src, (wire, ct) => { sent = wire.ToArray(); return default; });

            byte[] frame = BuildEthernetFrame(dst, src, 0x7E);
            await channel.WriteFrameAsync(frame, TestContext.Current.CancellationToken);

            Assert.NotNull(sent);
            Assert.Equal(0x0C, sent![0]);                         // VXLAN-GPE I|P bits
            Assert.Equal(0x03, sent![3]);                         // Next Protocol = Ethernet
            Assert.True(VxlanGpeHeader.TryDecodeVxlanGpe(sent!, out uint vni, out byte nextProtocol, out ReadOnlyMemory<byte> decodedFrame));
            Assert.Equal(Vni, vni);
            Assert.Equal(VxlanGpeHeader.NextProtocolEthernet, nextProtocol);
            Assert.Equal(frame, decodedFrame.ToArray());          // the whole Ethernet frame follows the header verbatim
        }

        [Fact]
        public void Channel_IsL2Ethernet_RequiresLinkResolution()
        {
            var channel = new VxlanGpeEthernetChannel(Vni, VxlanGpeHeader.NextProtocolEthernet, MacAddress.Parse("02:00:00:00:00:01"), (_, _) => default);
            Assert.Equal(LinkMedium.Ethernet, channel.Medium);
            Assert.Equal(14, channel.MaxHeaderLength);
            Assert.True(channel.RequiresLinkAddressResolution);
            Assert.Equal(MacAddress.Parse("02:00:00:00:00:01").ToArray(), channel.LinkAddress.ToArray());
        }

        [Fact]
        public void Deliver_RaisesInboundFrame_ForAnEthernetFrame_AndDropsRunts()
        {
            var channel = new VxlanGpeEthernetChannel(Vni, VxlanGpeHeader.NextProtocolEthernet, MacAddress.Parse("02:00:00:00:00:01"), (_, _) => default);

            byte[]? received = null;
            channel.InboundFrame += f => received = f.ToArray();

            channel.Deliver(new byte[8]);        // runt: dropped
            Assert.Null(received);

            byte[] frame = BuildEthernetFrame(MacAddress.Parse("02:00:00:00:00:02"), MacAddress.Parse("02:00:00:00:00:01"), 0x11);
            channel.Deliver(frame);
            Assert.Equal(frame, received);
        }

        [Fact]
        public void Config_DefaultsNextProtocolToEthernet()
        {
            var config = new VxlanGpeConfig
            {
                Vni = Vni,
                OverlayAddress = IPAddress.Parse("10.20.0.2"),
            };
            Assert.Equal(VxlanGpeNextProtocol.Ethernet, config.NextProtocol);
            Assert.Equal(0x03, config.NextProtocolByte);
            Assert.Equal(VxlanGpeHeader.DefaultPort, config.Port);
        }

        [Fact]
        public void Config_ProjectsToTunnelConfig_WithStaticAddressAndDefaultRoute()
        {
            var config = new VxlanGpeConfig
            {
                Vni = Vni,
                OverlayAddress = IPAddress.Parse("10.20.0.2"),
                PrefixLength = 24,
            };
            TunnelConfig tunnel = config.ToTunnelConfig();
            Assert.Equal(IPAddress.Parse("10.20.0.2"), tunnel.AssignedAddress);
            Assert.Equal(24, tunnel.PrefixLength);
            Assert.Equal(VxlanGpeDriverConstants.DefaultMtu, tunnel.Mtu);
            Assert.Contains("10.20.0.2/24", tunnel.Routes);
        }

        [Fact]
        public void Config_Throws_WhenVniExceeds24Bits()
        {
            var config = new VxlanGpeConfig
            {
                Vni = 0x1000000,
                OverlayAddress = IPAddress.Parse("10.20.0.2"),
            };
            Assert.Throws<ArgumentOutOfRangeException>(() => config.ToTunnelConfig());
        }
    }
}
