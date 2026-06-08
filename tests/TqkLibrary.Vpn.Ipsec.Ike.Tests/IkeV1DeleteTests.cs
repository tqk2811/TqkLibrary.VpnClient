using TqkLibrary.Vpn.Ipsec.Ike.V1;
using TqkLibrary.Vpn.Ipsec.Ike.V1.Enums;
using Xunit;

namespace TqkLibrary.Vpn.Ipsec.Ike.Tests
{
    public class IkeV1DeleteTests
    {
        [Fact]
        public void EspDeleteBody_HasTheExpectedLayout()
        {
            byte[] spi = { 0xDE, 0xAD, 0xBE, 0xEF };
            byte[] body = IkeV1Delete.BuildEspDeleteBody(spi);

            // DOI(4) | Protocol(1) | SpiSize(1) | #SPIs(2) | SPI(4).
            Assert.Equal((byte)IkeV1Constants.IpsecDoi, body[3]);
            Assert.Equal(IkeV1Constants.Protocol.Esp, body[4]); // the protocol byte ProcessInformational reads
            Assert.Equal(4, body[5]);
            Assert.Equal(1, (body[6] << 8) | body[7]);
            Assert.Equal(spi, body.AsSpan(8, 4).ToArray());
        }

        [Fact]
        public void IsakmpDeleteBody_CarriesBothCookiesAsTheSpi()
        {
            byte[] initiatorCookie = Bytes(0xA0, 8), responderCookie = Bytes(0xB0, 8);
            byte[] body = IkeV1Delete.BuildIsakmpDeleteBody(initiatorCookie, responderCookie);

            Assert.Equal(IkeV1Constants.Protocol.Isakmp, body[4]);
            Assert.Equal(16, body[5]);
            Assert.Equal(1, (body[6] << 8) | body[7]);
            Assert.Equal(initiatorCookie, body.AsSpan(8, 8).ToArray());
            Assert.Equal(responderCookie, body.AsSpan(16, 8).ToArray());
        }

        static byte[] Bytes(byte seed, int length)
        {
            byte[] b = new byte[length];
            for (int i = 0; i < length; i++) b[i] = (byte)(seed + i);
            return b;
        }
    }
}
