using System;
using System.Net;
using System.Threading.Tasks;
using TqkLibrary.VpnClient.Abstractions.Channels.Enums;
using TqkLibrary.VpnClient.Abstractions.Drivers.Models;
using TqkLibrary.VpnClient.Drivers.L2tpv3Eth;
using TqkLibrary.VpnClient.Drivers.L2tpv3Eth.Config;
using TqkLibrary.VpnClient.Drivers.L2tpv3Eth.DataChannel;
using TqkLibrary.VpnClient.Drivers.L2tpv3Eth.Enums;
using TqkLibrary.VpnClient.Ethernet;
using Xunit;

namespace TqkLibrary.VpnClient.Drivers.L2tpv3Eth.Tests
{
    /// <summary>Unit tests for the L2 data-plane channel and the static config projection (no transport / no fabric).</summary>
    public class L2tpv3EthEthernetChannelTests
    {
        const uint RemoteSessionId = 0x0A0B0C0D;

        static byte[] BuildEthernetFrame(MacAddress dst, MacAddress src, byte tail)
        {
            byte[] payload = new byte[20];
            payload[19] = tail;
            return EthernetFrame.Build(dst, src, EthernetFrame.EtherTypeIpv4, payload);
        }

        [Fact]
        public async Task WriteFrame_EncapsulatesFrame_WithL2tpv3Header_AndCodecRoundTrips()
        {
            MacAddress src = MacAddress.Parse("02:00:00:00:00:01");
            MacAddress dst = MacAddress.Parse("02:00:00:00:00:02");
            byte[] cookie = { 0xAA, 0xBB, 0xCC, 0xDD };

            byte[]? sent = null;
            var channel = new L2tpv3EthEthernetChannel(RemoteSessionId, cookie, sequencing: false, src, (wire, ct) => { sent = wire.ToArray(); return default; });

            byte[] frame = BuildEthernetFrame(dst, src, 0x7E);
            await channel.WriteFrameAsync(frame, TestContext.Current.CancellationToken);

            Assert.NotNull(sent);
            Assert.Equal(0x0A, sent![0]);   // Session ID (remote) big-endian
            Assert.Equal(0x0B, sent![1]);
            Assert.Equal(0x0C, sent![2]);
            Assert.Equal(0x0D, sent![3]);
            Assert.True(L2tpv3DataHeader.TryDecodeData(sent!, RemoteSessionId, cookie, sequencing: false,
                out _, out ReadOnlyMemory<byte> decodedFrame, out L2tpv3DecodeError error));
            Assert.Equal(L2tpv3DecodeError.None, error);
            Assert.Equal(frame, decodedFrame.ToArray());  // the whole Ethernet frame follows the header verbatim
        }

        [Fact]
        public async Task WriteFrame_WithSequencing_IncrementsSequenceNumber()
        {
            MacAddress src = MacAddress.Parse("02:00:00:00:00:01");
            MacAddress dst = MacAddress.Parse("02:00:00:00:00:02");

            byte[]? sent = null;
            var channel = new L2tpv3EthEthernetChannel(RemoteSessionId, ReadOnlyMemory<byte>.Empty, sequencing: true, src, (wire, ct) => { sent = wire.ToArray(); return default; });

            byte[] frame = BuildEthernetFrame(dst, src, 0x11);
            await channel.WriteFrameAsync(frame, TestContext.Current.CancellationToken);
            Assert.True(L2tpv3DataHeader.TryDecodeData(sent!, RemoteSessionId, ReadOnlyMemory<byte>.Empty.Span, sequencing: true, out uint seq0, out _, out _));
            Assert.Equal(0u, seq0);   // first frame carries sequence 0

            await channel.WriteFrameAsync(frame, TestContext.Current.CancellationToken);
            Assert.True(L2tpv3DataHeader.TryDecodeData(sent!, RemoteSessionId, ReadOnlyMemory<byte>.Empty.Span, sequencing: true, out uint seq1, out _, out _));
            Assert.Equal(1u, seq1);   // second frame carries sequence 1
        }

        [Fact]
        public void Channel_IsL2Ethernet_RequiresLinkResolution()
        {
            var channel = new L2tpv3EthEthernetChannel(RemoteSessionId, ReadOnlyMemory<byte>.Empty, sequencing: false, MacAddress.Parse("02:00:00:00:00:01"), (_, _) => default);
            Assert.Equal(LinkMedium.Ethernet, channel.Medium);
            Assert.Equal(14, channel.MaxHeaderLength);
            Assert.True(channel.RequiresLinkAddressResolution);
            Assert.Equal(MacAddress.Parse("02:00:00:00:00:01").ToArray(), channel.LinkAddress.ToArray());
        }

        [Fact]
        public void Deliver_RaisesInboundFrame_ForAnEthernetFrame_AndDropsRunts()
        {
            var channel = new L2tpv3EthEthernetChannel(RemoteSessionId, ReadOnlyMemory<byte>.Empty, sequencing: false, MacAddress.Parse("02:00:00:00:00:01"), (_, _) => default);

            byte[]? received = null;
            channel.InboundFrame += f => received = f.ToArray();

            channel.Deliver(new byte[8]);        // runt: dropped
            Assert.Null(received);

            byte[] frame = BuildEthernetFrame(MacAddress.Parse("02:00:00:00:00:02"), MacAddress.Parse("02:00:00:00:00:01"), 0x11);
            channel.Deliver(frame);
            Assert.Equal(frame, received);
        }

        [Fact]
        public void Config_ProjectsToTunnelConfig_WithStaticAddressAndDefaultRoute()
        {
            var config = new L2tpv3EthConfig
            {
                LocalSessionId = 0x00000101,
                RemoteSessionId = 0x00000202,
                OverlayAddress = IPAddress.Parse("10.30.0.2"),
                PrefixLength = 24,
            };
            TunnelConfig tunnel = config.ToTunnelConfig();
            Assert.Equal(IPAddress.Parse("10.30.0.2"), tunnel.AssignedAddress);
            Assert.Equal(24, tunnel.PrefixLength);
            Assert.Equal(L2tpv3EthDriverConstants.DefaultMtu, tunnel.Mtu);
            Assert.Contains("10.30.0.2/24", tunnel.Routes);
        }

        [Fact]
        public void Config_Throws_WhenSessionIdIsZero()
        {
            var config = new L2tpv3EthConfig
            {
                LocalSessionId = 0,
                RemoteSessionId = 0x00000202,
                OverlayAddress = IPAddress.Parse("10.30.0.2"),
            };
            Assert.Throws<ArgumentOutOfRangeException>(() => config.ToTunnelConfig());
        }

        [Fact]
        public void Config_Throws_WhenCookieLengthInvalid()
        {
            var config = new L2tpv3EthConfig
            {
                LocalSessionId = 0x00000101,
                RemoteSessionId = 0x00000202,
                OverlayAddress = IPAddress.Parse("10.30.0.2"),
                Cookie = new byte[3],
            };
            Assert.Throws<ArgumentOutOfRangeException>(() => config.ToTunnelConfig());
        }
    }
}
