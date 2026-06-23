using System;
using System.Net;
using TqkLibrary.VpnClient.Ethernet;
using Xunit;

namespace TqkLibrary.VpnClient.Ethernet.Tests
{
    /// <summary>
    /// Regression for the RA-options offset bug: <see cref="Icmpv6Ndisc.OptionsOffsetFor"/> for a Router Advertisement
    /// (and <see cref="Icmpv6Ndisc.BuildRouterAdvertisement"/>) once placed options at byte 20 instead of 16 (RFC 4861
    /// §4.2), so <see cref="Icmpv6Ndisc.TryGetPrefixInformation"/> failed on a *real* RA from radvd/Linux and SLAAC
    /// (P1.1) never formed a global address. These bytes are an actual RA captured from radvd in the lab.
    /// </summary>
    public class RadvdRaDecodeTests
    {
        static byte[] Hex(string h)
        {
            byte[] b = new byte[h.Length / 2];
            for (int i = 0; i < b.Length; i++) b[i] = Convert.ToByte(h.Substring(i * 2, 2), 16);
            return b;
        }

        // The ICMPv6 Router Advertisement body radvd emitted (prefix fd00:dead:beef::/64, A+L set, RDNSS option after it).
        const string RealRadvdRaIcmp6 =
            "86009d244000000f0000000000000000030440e0000151800000384000000000fd00deadbeef00000000000000000000190300000000001e26064700470000000000000000001111";

        [Fact]
        public void TryGetPrefixInformation_ParsesRealRadvdRa()
        {
            byte[] msg = Hex(RealRadvdRaIcmp6);
            Assert.Equal(72, msg.Length);
            Assert.Equal(Icmpv6Ndisc.TypeRouterAdvertisement, msg[0]);

            bool ok = Icmpv6Ndisc.TryGetPrefixInformation(msg, out IPAddress prefix, out byte pLen, out byte pFlags, out uint valid, out uint pref);

            Assert.True(ok, "Prefix Information option of a real radvd RA must be found (options begin at byte 16).");
            Assert.Equal(IPAddress.Parse("fd00:dead:beef::"), prefix);
            Assert.Equal(64, pLen);
            Assert.True((pFlags & Icmpv6Ndisc.PrefixFlagAutonomous) != 0, "A flag (SLAAC) set");
            Assert.True((pFlags & Icmpv6Ndisc.PrefixFlagOnLink) != 0, "L flag (on-link) set");
            Assert.Equal(86400u, valid);
            Assert.NotEqual(0u, pref);
        }

        [Fact]
        public void OptionsOffsetFor_RouterAdvertisement_Is16()
        {
            // RFC 4861 §4.2: type/code/checksum(4) + curHop/flags/routerLifetime(4) + reachable(4) + retrans(4) = 16.
            Assert.Equal(16, Icmpv6Ndisc.OptionsOffsetFor(Icmpv6Ndisc.TypeRouterAdvertisement));
        }

        [Fact]
        public void BuildRouterAdvertisement_RoundTripsThroughParser()
        {
            // The builder must place options at the same offset the parser reads — and at the wire-correct 16.
            byte[] msg = Icmpv6Ndisc.BuildRouterAdvertisement(
                source: IPAddress.Parse("fe80::1"), destination: IPAddress.Parse("ff02::1"),
                routerMac: MacAddress.Parse("02:00:00:00:00:01"), curHopLimit: 64, routerLifetimeSeconds: 1800,
                prefix: IPAddress.Parse("2001:db8:abcd::"), prefixLength: 64,
                prefixFlags: (byte)(Icmpv6Ndisc.PrefixFlagOnLink | Icmpv6Ndisc.PrefixFlagAutonomous),
                validLifetime: 7200, preferredLifetime: 3600);

            Assert.True(Icmpv6Ndisc.TryGetPrefixInformation(msg, out IPAddress prefix, out byte pLen, out byte pFlags, out uint valid, out uint pref));
            Assert.Equal(IPAddress.Parse("2001:db8:abcd::"), prefix);
            Assert.Equal(64, pLen);
            Assert.True((pFlags & Icmpv6Ndisc.PrefixFlagAutonomous) != 0);
            Assert.Equal(7200u, valid);
            Assert.Equal(3600u, pref);
        }
    }
}
