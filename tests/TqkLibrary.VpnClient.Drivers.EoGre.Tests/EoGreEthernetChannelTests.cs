using System;
using System.Net;
using System.Threading.Tasks;
using TqkLibrary.VpnClient.Abstractions.Channels.Enums;
using TqkLibrary.VpnClient.Abstractions.Drivers.Models;
using TqkLibrary.VpnClient.Drivers.EoGre;
using TqkLibrary.VpnClient.Drivers.EoGre.Config;
using TqkLibrary.VpnClient.Drivers.EoGre.DataChannel;
using TqkLibrary.VpnClient.Drivers.EoGre.Enums;
using TqkLibrary.VpnClient.Ethernet;
using Xunit;

namespace TqkLibrary.VpnClient.Drivers.EoGre.Tests
{
    /// <summary>Unit tests for the L2 data-plane channel and the static config projection / validation (no transport / no fabric).</summary>
    public class EoGreEthernetChannelTests
    {
        static byte[] BuildEthernetFrame(MacAddress dst, MacAddress src, byte tail)
        {
            byte[] payload = new byte[20];
            payload[19] = tail;
            return EthernetFrame.Build(dst, src, EthernetFrame.EtherTypeIpv4, payload);
        }

        [Fact]
        public async Task WriteFrame_EncapsulatesFrame_WithNvgreKey_AndCodecRoundTrips()
        {
            MacAddress src = MacAddress.Parse("02:00:00:00:00:01");
            MacAddress dst = MacAddress.Parse("02:00:00:00:00:02");
            uint vsid = 0x0A0B0C;
            byte flowId = 0x5E;

            byte[]? sent = null;
            var channel = new EoGreEthernetChannel(vsid, flowId, includeChecksum: false, emitSequence: false, src,
                (wire, ct) => { sent = wire.ToArray(); return default; });

            byte[] frame = BuildEthernetFrame(dst, src, 0x7E);
            await channel.WriteFrameAsync(frame, TestContext.Current.CancellationToken);

            Assert.NotNull(sent);
            Assert.Equal(0x20, sent![0] & 0x20);                  // K bit set (VSID present)
            Assert.Equal(0x65, sent![2]);                         // Protocol Type 0x6558 (Transparent Ethernet Bridging)
            Assert.Equal(0x58, sent![3]);
            Assert.True(EoGreCodec.TryDecodeEoGre(sent!, out ushort protocolType, out ReadOnlyMemory<byte> decodedFrame, out uint? key, out _));
            Assert.Equal(EoGreCodec.ProtocolTypeTransparentEthernet, protocolType);
            Assert.Equal(frame, decodedFrame.ToArray());          // the whole Ethernet frame follows the header verbatim
            Assert.Equal((vsid << 8) | flowId, key);
        }

        [Fact]
        public async Task WriteFrame_NoVsid_EmitsNoKey_PlainGretap()
        {
            MacAddress src = MacAddress.Parse("02:00:00:00:00:01");
            byte[]? sent = null;
            var channel = new EoGreEthernetChannel(vsid: null, flowId: 0, includeChecksum: false, emitSequence: false, src,
                (wire, ct) => { sent = wire.ToArray(); return default; });

            byte[] frame = BuildEthernetFrame(MacAddress.Parse("02:00:00:00:00:02"), src, 0x11);
            await channel.WriteFrameAsync(frame, TestContext.Current.CancellationToken);

            Assert.NotNull(sent);
            Assert.Equal(0x00, sent![0]);                         // no C/K/S flags — a plain GRETAP header
            Assert.True(EoGreCodec.TryDecodeEoGre(sent!, out _, out _, out uint? key, out _));
            Assert.Null(key);
        }

        [Fact]
        public async Task WriteFrame_WithSequence_EmitsIncrementingSequenceNumbers()
        {
            MacAddress src = MacAddress.Parse("02:00:00:00:00:01");
            var seqs = new System.Collections.Generic.List<uint?>();
            var channel = new EoGreEthernetChannel(vsid: null, flowId: 0, includeChecksum: false, emitSequence: true, src,
                (wire, ct) => { EoGreCodec.TryDecodeEoGre(wire.Span, out _, out _, out _, out uint? s); seqs.Add(s); return default; });

            byte[] frame = BuildEthernetFrame(MacAddress.Parse("02:00:00:00:00:02"), src, 0x11);
            await channel.WriteFrameAsync(frame, TestContext.Current.CancellationToken);
            await channel.WriteFrameAsync(frame, TestContext.Current.CancellationToken);
            await channel.WriteFrameAsync(frame, TestContext.Current.CancellationToken);

            Assert.Equal(new uint?[] { 0u, 1u, 2u }, seqs);
        }

        [Fact]
        public void Channel_IsL2Ethernet_RequiresLinkResolution()
        {
            var channel = new EoGreEthernetChannel(vsid: 1, flowId: 0, includeChecksum: false, emitSequence: false,
                MacAddress.Parse("02:00:00:00:00:01"), (_, _) => default);
            Assert.Equal(LinkMedium.Ethernet, channel.Medium);
            Assert.Equal(14, channel.MaxHeaderLength);
            Assert.True(channel.RequiresLinkAddressResolution);
            Assert.Equal(MacAddress.Parse("02:00:00:00:00:01").ToArray(), channel.LinkAddress.ToArray());
        }

        [Fact]
        public void Deliver_RaisesInboundFrame_ForAnEthernetFrame_AndDropsRunts()
        {
            var channel = new EoGreEthernetChannel(vsid: null, flowId: 0, includeChecksum: false, emitSequence: false,
                MacAddress.Parse("02:00:00:00:00:01"), (_, _) => default);

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
            var config = new EoGreConfig
            {
                Vsid = 0x0A0B0C,
                OverlayAddress = IPAddress.Parse("10.20.0.2"),
                PrefixLength = 24,
            };
            TunnelConfig tunnel = config.ToTunnelConfig();
            Assert.Equal(IPAddress.Parse("10.20.0.2"), tunnel.AssignedAddress);
            Assert.Equal(24, tunnel.PrefixLength);
            Assert.Equal(EoGreDriverConstants.DefaultMtu, tunnel.Mtu);
            Assert.Contains("10.20.0.2/24", tunnel.Routes);
        }

        [Fact]
        public void Config_Throws_WhenVsidExceeds24Bits()
        {
            var config = new EoGreConfig
            {
                Vsid = 0x1000000,
                OverlayAddress = IPAddress.Parse("10.20.0.2"),
            };
            Assert.Throws<ArgumentOutOfRangeException>(() => config.ToTunnelConfig());
        }

        [Fact]
        public void Config_Validate_Nvgre_RequiresVsid()
        {
            var noVsid = new EoGreConfig { OverlayAddress = IPAddress.Parse("10.20.0.2") };
            Assert.Throws<ArgumentException>(() => noVsid.Validate(EoGreMode.Nvgre));

            var withVsid = new EoGreConfig { Vsid = 42, OverlayAddress = IPAddress.Parse("10.20.0.2") };
            withVsid.Validate(EoGreMode.Nvgre);   // does not throw
            withVsid.Validate(EoGreMode.EoGre);   // VSID optional in EoGRE mode — does not throw
        }

        [Fact]
        public void Config_Validate_EoGre_AllowsMissingVsid()
        {
            var config = new EoGreConfig { OverlayAddress = IPAddress.Parse("10.20.0.2") };
            config.Validate(EoGreMode.EoGre);     // plain GRETAP without a VSID is valid
        }
    }
}
