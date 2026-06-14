namespace TqkLibrary.VpnClient.Ipsec.Esp
{
    /// <summary>Wire-format constants and helpers for the ESP header (RFC 4303 §2): SPI(4) + Sequence Number(4).</summary>
    public static class EspConstants
    {
        /// <summary>Length of the unencrypted ESP header (SPI + Sequence Number).</summary>
        public const int HeaderSize = 8;

        /// <summary>Common IP protocol numbers used as the ESP Next Header value.</summary>
        public const byte NextHeaderUdp = 17;

        /// <summary>Tunnel-mode Next Header for an encapsulated IPv4 packet (IP protocol 4, "IP-in-IP").</summary>
        public const byte NextHeaderIpv4 = 4;

        /// <summary>Tunnel-mode Next Header for an encapsulated IPv6 packet (IP protocol 41).</summary>
        public const byte NextHeaderIpv6 = 41;

        /// <summary>The "no next header" dummy-packet marker (RFC 4303 §2.6).</summary>
        public const byte NextHeaderNone = 59;

        /// <summary>Reads the 32-bit big-endian SPI from the front of an ESP packet.</summary>
        public static uint ReadSpi(ReadOnlySpan<byte> packet)
            => (uint)((packet[0] << 24) | (packet[1] << 16) | (packet[2] << 8) | packet[3]);

        /// <summary>Reads the 32-bit big-endian Sequence Number that follows the SPI.</summary>
        public static uint ReadSequence(ReadOnlySpan<byte> packet)
            => (uint)((packet[4] << 24) | (packet[5] << 16) | (packet[6] << 8) | packet[7]);

        /// <summary>Writes SPI + Sequence Number (both big-endian) into the first 8 bytes of <paramref name="header"/>.</summary>
        public static void WriteHeader(Span<byte> header, uint spi, uint sequence)
        {
            header[0] = (byte)(spi >> 24); header[1] = (byte)(spi >> 16); header[2] = (byte)(spi >> 8); header[3] = (byte)spi;
            header[4] = (byte)(sequence >> 24); header[5] = (byte)(sequence >> 16); header[6] = (byte)(sequence >> 8); header[7] = (byte)sequence;
        }
    }
}
