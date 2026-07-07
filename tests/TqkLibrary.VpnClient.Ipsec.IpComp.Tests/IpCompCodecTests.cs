using TqkLibrary.VpnClient.Ipsec.IpComp;
using TqkLibrary.VpnClient.Ipsec.IpComp.Enums;
using TqkLibrary.VpnClient.Ipsec.IpComp.Models;
using Xunit;

namespace TqkLibrary.VpnClient.Ipsec.IpComp.Tests
{
    public class IpCompCodecTests
    {
        const byte NextHeaderIpv4 = 4;   // IP-in-IP (RFC 2003)
        const byte NextHeaderIpv6 = 41;  // IPv6-in-IPv4 (RFC 4213)

        static byte[] Repeated(int length, byte value)
        {
            byte[] b = new byte[length];
            for (int i = 0; i < length; i++) b[i] = value;
            return b;
        }

        // Highly compressible: a short cycle repeated (DEFLATE collapses it to well under the original).
        static byte[] Patterned(int length)
        {
            const string cycle = "IPCOMP-RFC3173-"; // 15 chars
            byte[] b = new byte[length];
            for (int i = 0; i < length; i++) b[i] = (byte)cycle[i % cycle.Length];
            return b;
        }

        // Incompressible: pseudo-random bytes (deterministic per seed) that DEFLATE cannot shrink below original.
        static byte[] Incompressible(int length, int seed)
        {
            byte[] b = new byte[length];
            new Random(seed).NextBytes(b);
            return b;
        }

        [Theory]
        [InlineData(64)]
        [InlineData(200)]
        [InlineData(576)]
        [InlineData(1400)]
        [InlineData(4000)]
        public void Compress_ThenDecompress_RecoversRepeatedPayload(int length)
        {
            byte[] payload = Repeated(length, 0xAB);

            Assert.True(IpCompCodec.TryCompress(payload, NextHeaderIpv4, out byte[] datagram));
            byte[] recovered = IpCompCodec.Decompress(datagram, out byte nextHeader);

            Assert.Equal(payload, recovered);
            Assert.Equal(NextHeaderIpv4, nextHeader);
        }

        [Theory]
        [InlineData(60)]
        [InlineData(300)]
        [InlineData(1500)]
        public void Compress_ThenDecompress_RecoversPatternedPayload(int length)
        {
            byte[] payload = Patterned(length);

            Assert.True(IpCompCodec.TryCompress(payload, NextHeaderIpv6, out byte[] datagram));
            byte[] recovered = IpCompCodec.Decompress(datagram, out byte nextHeader);

            Assert.Equal(payload, recovered);
            Assert.Equal(NextHeaderIpv6, nextHeader);
        }

        [Fact]
        public void CompressibleData_ProducesSmallerDatagram_WithDeflateHeader()
        {
            byte[] payload = Repeated(1000, 0x00);

            Assert.True(IpCompCodec.TryCompress(payload, NextHeaderIpv4, out byte[] datagram));

            Assert.True(datagram.Length < payload.Length, "IPComp datagram must be strictly smaller than the payload (RFC 3173 §2.2).");
            IpCompHeader header = IpCompHeader.Parse(datagram);
            Assert.Equal(NextHeaderIpv4, header.NextHeader);
            Assert.Equal((ushort)IpCompTransform.Deflate, header.Cpi);
            Assert.Equal((byte)0, datagram[1]); // Flags reserved (RFC 3173 §3)
        }

        [Theory]
        [InlineData(1)]
        [InlineData(3)]
        [InlineData(200)]
        [InlineData(1400)]
        public void IncompressibleData_TriggersNonExpansion_ReturnsFalse(int length)
        {
            byte[] payload = Incompressible(length, 0x1000 + length);

            Assert.False(IpCompCodec.TryCompress(payload, NextHeaderIpv4, out byte[] datagram));
            Assert.Empty(datagram);
        }

        [Fact]
        public void EmptyPayload_ReturnsFalse()
        {
            Assert.False(IpCompCodec.TryCompress(ReadOnlySpan<byte>.Empty, NextHeaderIpv4, out byte[] datagram));
            Assert.Empty(datagram);
        }

        [Fact]
        public void Decompress_WrongCpi_ThrowsNotSupported()
        {
            // NextHeader=4, Flags=0, CPI=3 (LZS — not supported), then some body bytes.
            byte[] datagram = { NextHeaderIpv4, 0, 0x00, 0x03, 0x01, 0x02, 0x03, 0x04 };
            Assert.Throws<NotSupportedException>(() => IpCompCodec.Decompress(datagram, out _));
        }

        [Theory]
        [InlineData(0)]
        [InlineData(1)]
        [InlineData(3)]
        public void Decompress_TruncatedHeader_ThrowsFormat(int length)
        {
            byte[] datagram = new byte[length];
            Assert.Throws<FormatException>(() => IpCompCodec.Decompress(datagram, out _));
        }

        [Fact]
        public void Parse_TruncatedHeader_ThrowsFormat()
        {
            Assert.Throws<FormatException>(() => IpCompHeader.Parse(new byte[3]));
        }

        [Fact]
        public void Decompress_CorruptDeflateStream_ThrowsFormat()
        {
            // Valid DEFLATE header (CPI=2) but a garbage body: 0xFF => BFINAL=1, BTYPE=11 (reserved) => invalid block.
            byte[] datagram = new byte[12];
            datagram[0] = NextHeaderIpv4;
            datagram[3] = (byte)IpCompTransform.Deflate;
            for (int i = IpCompHeader.Size; i < datagram.Length; i++) datagram[i] = 0xFF;
            Assert.Throws<FormatException>(() => IpCompCodec.Decompress(datagram, out _));
        }

        [Fact]
        public void IpCompHeader_WriteTo_ThenParse_RoundTrips()
        {
            IpCompHeader header = IpCompHeader.Deflate(17); // UDP payload

            byte[] buffer = new byte[IpCompHeader.Size];
            header.WriteTo(buffer);

            Assert.Equal((byte)17, buffer[0]);
            Assert.Equal((byte)0, buffer[1]);   // Flags
            Assert.Equal((byte)0x00, buffer[2]); // CPI high byte
            Assert.Equal((byte)0x02, buffer[3]); // CPI low byte = DEFLATE

            IpCompHeader parsed = IpCompHeader.Parse(buffer);
            Assert.Equal((byte)17, parsed.NextHeader);
            Assert.Equal((ushort)IpCompTransform.Deflate, parsed.Cpi);
        }

        [Fact]
        public void Decompress_PreservesNextHeader_AcrossProtocolValues()
        {
            byte[] payload = Repeated(300, 0x5A);
            foreach (byte nh in new byte[] { 4, 41, 6, 17, 50 })
            {
                Assert.True(IpCompCodec.TryCompress(payload, nh, out byte[] datagram));
                IpCompCodec.Decompress(datagram, out byte recovered);
                Assert.Equal(nh, recovered);
            }
        }
    }
}
