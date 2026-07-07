using System.Buffers.Binary;
using TqkLibrary.VpnClient.Ipsec.IpComp.Enums;

namespace TqkLibrary.VpnClient.Ipsec.IpComp.Models
{
    /// <summary>
    /// The 4-byte IPComp header (RFC 3173 §3): <c>Next Header (1)</c> = the IP protocol number of the payload once it is
    /// decompressed; <c>Flags (1)</c> = reserved, MUST be 0 on transmission and ignored on receipt; <c>CPI (2, big-endian)</c>
    /// = the Compression Parameter Index. For a well-known algorithm the CPI equals its transform id — here DEFLATE = 2
    /// (RFC 2394). This header prefixes the raw DEFLATE (RFC 1951) stream of a compressed datagram.
    /// </summary>
    public readonly struct IpCompHeader
    {
        /// <summary>Length of the IPComp header on the wire, in bytes (RFC 3173 §3).</summary>
        public const int Size = 4;

        /// <summary>The IP protocol number of the payload carried after decompression (e.g. 4 IPv4, 41 IPv6, 6 TCP, 17 UDP).</summary>
        public byte NextHeader { get; }

        /// <summary>The Compression Parameter Index; for a well-known algorithm this is its transform id (DEFLATE = 2).</summary>
        public ushort Cpi { get; }

        /// <summary>Creates a header with an explicit <paramref name="nextHeader"/> and <paramref name="cpi"/>.</summary>
        public IpCompHeader(byte nextHeader, ushort cpi)
        {
            NextHeader = nextHeader;
            Cpi = cpi;
        }

        /// <summary>Creates a DEFLATE (RFC 2394, CPI = 2) header for a payload whose IP protocol is <paramref name="nextHeader"/>.</summary>
        public static IpCompHeader Deflate(byte nextHeader) => new(nextHeader, (ushort)IpCompTransform.Deflate);

        /// <summary>
        /// Serialises the 4-byte header into the front of <paramref name="destination"/> (Flags fixed to 0, CPI big-endian).
        /// </summary>
        public void WriteTo(Span<byte> destination)
        {
            destination[0] = NextHeader;
            destination[1] = 0; // Flags: reserved, MUST be 0 (RFC 3173 §3).
            BinaryPrimitives.WriteUInt16BigEndian(destination.Slice(2), Cpi);
        }

        /// <summary>
        /// Parses the 4-byte IPComp header from the front of <paramref name="datagram"/> (the Flags byte is ignored per
        /// RFC 3173 §3). Throws <see cref="FormatException"/> when fewer than <see cref="Size"/> bytes are present.
        /// </summary>
        public static IpCompHeader Parse(ReadOnlySpan<byte> datagram)
        {
            if (datagram.Length < Size)
                throw new FormatException(
                    $"IPComp datagram is {datagram.Length} bytes, shorter than the {Size}-byte IPComp header (RFC 3173 §3).");
            byte nextHeader = datagram[0];
            ushort cpi = BinaryPrimitives.ReadUInt16BigEndian(datagram.Slice(2));
            return new IpCompHeader(nextHeader, cpi);
        }
    }
}
