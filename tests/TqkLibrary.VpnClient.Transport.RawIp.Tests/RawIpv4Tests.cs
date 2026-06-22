using System.Net;
using TqkLibrary.VpnClient.Transport.RawIp.Helpers;
using Xunit;

namespace TqkLibrary.VpnClient.Transport.RawIp.Tests
{
    /// <summary>
    /// Pure IPv4 header parsing for the raw-IP receive path: payload offset (incl. options), protocol, fragment
    /// detection, and source address — the genuinely risky logic that a raw socket cannot be unit-tested for offline.
    /// </summary>
    public class RawIpv4Tests
    {
        [Fact]
        public void PayloadOffset_MinimalHeader_Is20()
        {
            byte[] datagram = Header(ihlWords: 5, protocol: 50, totalLength: 28);
            Assert.Equal(20, RawIpv4.PayloadOffset(datagram));
        }

        [Fact]
        public void PayloadOffset_WithOptions_FollowsIhl()
        {
            byte[] datagram = Header(ihlWords: 6, protocol: 50, totalLength: 32); // IHL 6 → 24-byte header (4 option bytes)
            Assert.Equal(24, RawIpv4.PayloadOffset(datagram));
        }

        [Fact]
        public void PayloadOffset_WrongVersion_IsMinusOne()
        {
            byte[] datagram = Header(ihlWords: 5, protocol: 50, totalLength: 28);
            datagram[0] = 0x65; // version 6 in an IPv4-shaped buffer
            Assert.Equal(-1, RawIpv4.PayloadOffset(datagram));
        }

        [Fact]
        public void PayloadOffset_TooShortForOwnHeader_IsMinusOne()
        {
            byte[] datagram = Header(ihlWords: 6, protocol: 50, totalLength: 32);
            Assert.Equal(-1, RawIpv4.PayloadOffset(datagram.AsSpan(0, 22).ToArray())); // claims 24 but only 22 present
        }

        [Fact]
        public void PayloadOffset_BelowMinimum_IsMinusOne()
        {
            Assert.Equal(-1, RawIpv4.PayloadOffset(new byte[19]));
        }

        [Fact]
        public void Protocol_ReadsByte9()
        {
            byte[] datagram = Header(ihlWords: 5, protocol: 47, totalLength: 28);
            Assert.Equal(47, RawIpv4.Protocol(datagram));
        }

        [Fact]
        public void IsFragment_MoreFragmentsFlag_IsTrue()
        {
            byte[] datagram = Header(ihlWords: 5, protocol: 50, totalLength: 28);
            datagram[6] = 0x20; // MF bit (0x2000 over bytes 6-7)
            Assert.True(RawIpv4.IsFragment(datagram));
        }

        [Fact]
        public void IsFragment_NonZeroOffset_IsTrue()
        {
            byte[] datagram = Header(ihlWords: 5, protocol: 50, totalLength: 28);
            datagram[6] = 0x00;
            datagram[7] = 0x10; // fragment offset != 0
            Assert.True(RawIpv4.IsFragment(datagram));
        }

        [Fact]
        public void IsFragment_WholePacket_IsFalse()
        {
            byte[] datagram = Header(ihlWords: 5, protocol: 50, totalLength: 28);
            Assert.False(RawIpv4.IsFragment(datagram));
        }

        [Fact]
        public void SourceAddress_ReadsBytes12To15()
        {
            byte[] datagram = Header(ihlWords: 5, protocol: 50, totalLength: 28);
            new byte[] { 203, 0, 113, 7 }.CopyTo(datagram, 12);
            Assert.Equal(IPAddress.Parse("203.0.113.7"), RawIpv4.SourceAddress(datagram));
        }

        // Builds a syntactically valid IPv4 header (RFC 791) of ihlWords*4 bytes with the given protocol/total length.
        static byte[] Header(int ihlWords, byte protocol, int totalLength)
        {
            byte[] h = new byte[ihlWords * 4];
            h[0] = (byte)(0x40 | (ihlWords & 0x0F)); // version 4 + IHL
            h[2] = (byte)(totalLength >> 8);
            h[3] = (byte)(totalLength & 0xFF);
            h[8] = 64;        // TTL
            h[9] = protocol;
            return h;
        }
    }
}
