using TqkLibrary.Vpn.Ipsec.Ike.V1.Enums;

namespace TqkLibrary.Vpn.Ipsec.Ike.V1
{
    /// <summary>
    /// ISAKMP Delete payload bodies (RFC 2408 §3.15) for a clean teardown: DOI(4)=IPSEC | Protocol(1) | SPI-Size(1) |
    /// #SPIs(2) | SPI(s). An ESP delete names the 4-byte CHILD SPI; an ISAKMP delete names the 16-byte CKY-I‖CKY-R.
    /// </summary>
    public static class IkeV1Delete
    {
        /// <summary>Builds a Delete body for the ESP CHILD SA identified by <paramref name="espSpi"/> (4 bytes).</summary>
        public static byte[] BuildEspDeleteBody(byte[] espSpi)
            => Build(IkeV1Constants.Protocol.Esp, 4, espSpi);

        /// <summary>Builds a Delete body for the ISAKMP SA identified by the two cookies (16-byte SPI).</summary>
        public static byte[] BuildIsakmpDeleteBody(byte[] initiatorCookie, byte[] responderCookie)
        {
            byte[] spi = new byte[16];
            System.Buffer.BlockCopy(initiatorCookie, 0, spi, 0, 8);
            System.Buffer.BlockCopy(responderCookie, 0, spi, 8, 8);
            return Build(IkeV1Constants.Protocol.Isakmp, 16, spi);
        }

        static byte[] Build(byte protocol, byte spiSize, byte[] spi)
        {
            byte[] body = new byte[4 + 1 + 1 + 2 + spiSize];
            int offset = 0;
            body[offset++] = 0; body[offset++] = 0; body[offset++] = 0; body[offset++] = (byte)IkeV1Constants.IpsecDoi;
            body[offset++] = protocol;
            body[offset++] = spiSize;
            body[offset++] = 0; body[offset++] = 1; // exactly one SPI
            System.Buffer.BlockCopy(spi, 0, body, offset, spiSize);
            return body;
        }
    }
}
