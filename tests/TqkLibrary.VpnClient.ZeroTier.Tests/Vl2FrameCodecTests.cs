using TqkLibrary.VpnClient.ZeroTier.Identity.Models;
using TqkLibrary.VpnClient.ZeroTier.Vl2;
using TqkLibrary.VpnClient.ZeroTier.Vl2.Models;
using Xunit;

namespace TqkLibrary.VpnClient.ZeroTier.Tests
{
    public class Vl2FrameCodecTests
    {
        readonly Vl2FrameCodec _codec = new Vl2FrameCodec();

        [Fact]
        public void NetworkId_Parse_Write_RoundTrips()
        {
            var nwid = NetworkId.Parse("8056c2e21c000001");
            Assert.Equal("8056c2e21c000001", nwid.ToString());
            byte[] b = new byte[8];
            nwid.Write(b);
            Assert.Equal(nwid, NetworkId.Read(b));
            Assert.Equal(0x8056c2e21cUL, nwid.ControllerAddress);
        }

        [Fact]
        public void Frame_Encode_Decode_RoundTrips()
        {
            var frame = new Vl2Frame
            {
                Network = NetworkId.Parse("8056c2e21c000001"),
                EtherType = 0x0800, // IPv4
                FrameData = new byte[] { 0x45, 0x00, 0x00, 0x14, 0xDE, 0xAD },
            };

            byte[] body = _codec.Encode(frame);
            Assert.True(_codec.TryDecode(body, out var parsed));
            Assert.Equal(frame.Network, parsed.Network);
            Assert.Equal(frame.EtherType, parsed.EtherType);
            Assert.Equal(frame.FrameData, parsed.FrameData);
        }

        [Fact]
        public void TryDecode_RejectsShortBody()
        {
            Assert.False(_codec.TryDecode(new byte[5], out _));
        }

        [Fact]
        public void DeriveMac_IsDeterministic_UnicastLocallyAdministered()
        {
            var addr = ZeroTierAddress.Parse("8056c2e21c");
            var nwid = NetworkId.Parse("8056c2e21c000001");

            byte[] mac1 = _codec.DeriveMac(addr, nwid);
            byte[] mac2 = _codec.DeriveMac(addr, nwid);
            Assert.Equal(mac1, mac2);

            Assert.Equal(6, mac1.Length);
            Assert.Equal(0, mac1[0] & 0x01);       // I/G bit clear -> unicast
            Assert.Equal(0x02, mac1[0] & 0x02);    // U/L bit set   -> locally administered
        }

        /// <summary>
        /// KAT: the MAC derivation must match a real ZeroTier node's per-network tap MAC byte-for-byte. Node
        /// <c>7bfd7adbee</c> on network <c>7bfd7adbeeae27fe</c> shows tap MAC <c>fe:5c:53:94:00:94</c> (captured live from
        /// zerotier-one 1.4.6 via <c>zerotier-cli listnetworks</c>). This pins <c>MAC::fromAddress</c> (first octet from
        /// nwid + 40-bit address + nwid byte XOR-fold into bytes 1..5).
        /// </summary>
        [Theory]
        // Two real members of network 7bfd7adbeeae27fe, tap MACs captured live (zerotier-one 1.4.6, zerotier-cli listnetworks).
        [InlineData("7bfd7adbee", "7bfd7adbeeae27fe", new byte[] { 0xfe, 0x5c, 0x53, 0x94, 0x00, 0x94 })]
        [InlineData("e3595d21fa", "7bfd7adbeeae27fe", new byte[] { 0xfe, 0xc4, 0xf7, 0xb3, 0xfa, 0x80 })]
        public void DeriveMac_MatchesRealNodeTapMac(string address, string network, byte[] expected)
        {
            byte[] mac = _codec.DeriveMac(ZeroTierAddress.Parse(address), NetworkId.Parse(network));
            Assert.Equal(expected, mac);
        }

        [Fact]
        public void DeriveMac_DiffersAcrossNetworks()
        {
            var addr = ZeroTierAddress.Parse("8056c2e21c");
            byte[] m1 = _codec.DeriveMac(addr, NetworkId.Parse("8056c2e21c000001"));
            byte[] m2 = _codec.DeriveMac(addr, NetworkId.Parse("ffffffffff000099"));
            Assert.NotEqual(m1, m2); // the network id is folded into the MAC
        }
    }
}
