using TqkLibrary.VpnClient.Ssh.Channel;
using TqkLibrary.VpnClient.Ssh.Channel.Enums;
using Xunit;

namespace TqkLibrary.VpnClient.Ssh.Tests
{
    /// <summary>
    /// Tests for the tun@openssh.com layer-3 framing (PROTOCOL §2.3): a bare IP packet wraps to
    /// <c>uint32 inner_length || uint32 address_family || ip</c> with <c>inner_length = 4 + ip.Length</c> and the
    /// address family chosen from the IP version nibble (IPv4 = 2, IPv6 = 24). Decapsulation is the inverse, and rejects
    /// truncated / inconsistent framing.
    /// </summary>
    public class SshTunFramingTests
    {
        [Fact]
        public void Encapsulate_Ipv4_HasAfInetAndCorrectInnerLength()
        {
            byte[] ip = new byte[20]; ip[0] = 0x45; // IPv4 version+IHL
            byte[] framed = SshTunFraming.Encapsulate(ip);

            // inner length = 4 (AF field) + 20 (ip) = 24 = 0x18
            Assert.Equal(new byte[] { 0, 0, 0, 24 }, framed.AsSpan(0, 4).ToArray());
            Assert.Equal(new byte[] { 0, 0, 0, (byte)SshTunAddressFamily.Inet }, framed.AsSpan(4, 4).ToArray());
            Assert.Equal(8 + 20, framed.Length);
        }

        [Fact]
        public void Encapsulate_Ipv6_HasAfInet6()
        {
            byte[] ip = new byte[40]; ip[0] = 0x60; // IPv6 version nibble
            byte[] framed = SshTunFraming.Encapsulate(ip);
            Assert.Equal((byte)SshTunAddressFamily.Inet6, framed[7]);
        }

        [Fact]
        public void Encapsulate_Decapsulate_RoundTrips()
        {
            byte[] ip = new byte[60];
            for (int i = 0; i < ip.Length; i++) ip[i] = (byte)(i + 1);
            ip[0] = 0x45;

            byte[] framed = SshTunFraming.Encapsulate(ip);
            Assert.True(SshTunFraming.TryDecapsulate(framed, out var recovered, out var af));
            Assert.Equal(ip, recovered.ToArray());
            Assert.Equal(SshTunAddressFamily.Inet, af);
        }

        [Theory]
        [InlineData(0)]
        [InlineData(4)]
        [InlineData(7)]
        public void Decapsulate_TooShort_ReturnsFalse(int len)
        {
            byte[] tooShort = new byte[len];
            Assert.False(SshTunFraming.TryDecapsulate(tooShort, out _, out _));
        }

        [Fact]
        public void Decapsulate_InnerLengthOverrun_ReturnsFalse()
        {
            // inner length says 4 + 100 but only 8 bytes follow.
            byte[] framed = new byte[8];
            framed[3] = 104; // inner length = 104
            framed[7] = (byte)SshTunAddressFamily.Inet;
            Assert.False(SshTunFraming.TryDecapsulate(framed, out _, out _));
        }
    }
}
