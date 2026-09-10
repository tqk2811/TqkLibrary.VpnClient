using System.Net;
using TqkLibrary.VpnClient.Abstractions.Drivers.Models;
using TqkLibrary.VpnClient.Ethernet;
using Xunit;

namespace TqkLibrary.VpnClient.Ethernet.Tests
{
    public class NextHopTableTests
    {
        static readonly IPAddress Local = IPAddress.Parse("10.245.96.168");
        static readonly IPAddress Gateway = IPAddress.Parse("10.245.254.254");

        [Fact]
        public void Empty_SendsEverythingToItself()
        {
            var table = new NextHopTable();

            // No lease yet: every destination is its own next hop, which is what an overlay LAN with no router wants.
            Assert.Equal(IPAddress.Parse("1.1.1.1"), table.SelectNextHop(IPAddress.Parse("1.1.1.1")));
            Assert.Equal(IPAddress.Parse("fd00::2"), table.SelectNextHop(IPAddress.Parse("fd00::2")));
            Assert.Null(table.Gateway);
            Assert.Null(table.GatewayV6);
        }

        [Fact]
        public void OffLink_GoesToTheGateway()
        {
            var table = new NextHopTable();
            table.SetIpv4(Local, 16, Gateway);

            // The failure this whole type exists for: ARPing 23.15.142.182 goes unanswered forever.
            Assert.Equal(Gateway, table.SelectNextHop(IPAddress.Parse("23.15.142.182")));
            Assert.Equal(Gateway, table.SelectNextHop(IPAddress.Parse("8.8.8.8")));
        }

        [Fact]
        public void OnLink_GoesToTheDestination()
        {
            var table = new NextHopTable();
            table.SetIpv4(Local, 16, Gateway);

            IPAddress neighbour = IPAddress.Parse("10.245.1.2");
            Assert.Equal(neighbour, table.SelectNextHop(neighbour));
            Assert.Equal(Gateway, table.SelectNextHop(Gateway));   // the gateway is on-link and answers for itself
        }

        [Fact]
        public void PrefixBoundary_IsRespectedToTheBit()
        {
            var table = new NextHopTable();
            table.SetIpv4(IPAddress.Parse("192.168.1.10"), 25, IPAddress.Parse("192.168.1.1"));

            Assert.Equal(IPAddress.Parse("192.168.1.126"), table.SelectNextHop(IPAddress.Parse("192.168.1.126")));   // inside /25
            Assert.Equal(IPAddress.Parse("192.168.1.1"), table.SelectNextHop(IPAddress.Parse("192.168.1.130")));     // outside /25
        }

        [Fact]
        public void NoGateway_LeavesTheOnLinkBehaviour()
        {
            var table = new NextHopTable();
            table.SetIpv4(Local, 16, gateway: null);

            IPAddress far = IPAddress.Parse("1.1.1.1");
            Assert.Equal(far, table.SelectNextHop(far));   // nothing better to do than ask for it
        }

        [Fact]
        public void MulticastAndBroadcast_NeverLeaveTheLink()
        {
            var table = new NextHopTable();
            table.SetIpv4(Local, 16, Gateway);
            table.SetIpv6(IPAddress.Parse("2001:db8::1"), 64, IPAddress.Parse("fe80::1"));

            Assert.Equal(IPAddress.Parse("255.255.255.255"), table.SelectNextHop(IPAddress.Parse("255.255.255.255")));
            Assert.Equal(IPAddress.Parse("224.0.0.251"), table.SelectNextHop(IPAddress.Parse("224.0.0.251")));
            Assert.Equal(IPAddress.Parse("ff02::2"), table.SelectNextHop(IPAddress.Parse("ff02::2")));
            Assert.Equal(IPAddress.Parse("fe80::5"), table.SelectNextHop(IPAddress.Parse("fe80::5")));
        }

        [Fact]
        public void EachFamilyRoutesOnItsOwn()
        {
            var table = new NextHopTable();
            table.SetIpv4(Local, 16, Gateway);

            // IPv6 is unconfigured, so a v6 destination must not be handed to the v4 gateway.
            IPAddress v6 = IPAddress.Parse("2001:db8::99");
            Assert.Equal(v6, table.SelectNextHop(v6));

            table.SetIpv6(IPAddress.Parse("2001:db8::1"), 64, IPAddress.Parse("fe80::1"));
            Assert.Equal(IPAddress.Parse("fe80::1"), table.SelectNextHop(IPAddress.Parse("2001:4860::8888")));
            Assert.Equal(Gateway, table.SelectNextHop(IPAddress.Parse("1.1.1.1")));   // v4 routing is untouched
        }

        [Fact]
        public void Apply_TakesBothFamiliesFromTheLease_AndLeavesTheOtherAlone()
        {
            var table = new NextHopTable();
            table.Apply(new TunnelConfig
            {
                AssignedAddress = Local,
                PrefixLength = 16,
                Gateway = Gateway,
            });
            Assert.Equal(Gateway, table.Gateway);
            Assert.Equal(Gateway, table.SelectNextHop(IPAddress.Parse("1.1.1.1")));

            // A later IPv6-only config (SoftEther merges v6 in after the v4 lease) must not erase the v4 routing.
            table.Apply(new TunnelConfig
            {
                AssignedAddressV6 = IPAddress.Parse("2001:db8::1"),
                PrefixLengthV6 = 64,
                GatewayV6 = IPAddress.Parse("fe80::1"),
            });
            Assert.Equal(Gateway, table.SelectNextHop(IPAddress.Parse("1.1.1.1")));
            Assert.Equal(IPAddress.Parse("fe80::1"), table.SelectNextHop(IPAddress.Parse("2001:4860::8888")));
        }

        [Fact]
        public void MismatchedFamilies_AreRejected()
        {
            var table = new NextHopTable();

            Assert.Throws<ArgumentException>(() => table.SetIpv4(IPAddress.Parse("fd00::1"), 64, null));
            Assert.Throws<ArgumentException>(() => table.SetIpv4(Local, 16, IPAddress.Parse("fd00::1")));
            Assert.Throws<ArgumentException>(() => table.SetIpv6(Local, 16, null));
        }

        [Theory]
        [InlineData("10.0.0.1", "10.0.0.2", 24, true)]
        [InlineData("10.0.0.1", "10.0.1.2", 24, false)]
        [InlineData("10.0.0.1", "10.0.1.2", 16, true)]
        [InlineData("10.0.0.1", "11.0.0.1", 0, true)]     // a /0 puts everything on-link
        [InlineData("10.0.0.1", "10.0.0.1", 32, true)]
        [InlineData("10.0.0.1", "10.0.0.2", 32, false)]
        public void SamePrefix_ComparesLeadingBits(string a, string b, int prefixLength, bool expected)
            => Assert.Equal(expected, NextHopTable.SamePrefix(IPAddress.Parse(a), IPAddress.Parse(b), prefixLength));

        [Fact]
        public void SamePrefix_AcrossFamilies_IsNever()
            => Assert.False(NextHopTable.SamePrefix(IPAddress.Parse("10.0.0.1"), IPAddress.Parse("fd00::1"), 8));
    }
}
