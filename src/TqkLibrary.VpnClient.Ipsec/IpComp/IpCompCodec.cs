using System.IO;
using System.IO.Compression;
using TqkLibrary.VpnClient.Ipsec.IpComp.Enums;
using TqkLibrary.VpnClient.Ipsec.IpComp.Models;

namespace TqkLibrary.VpnClient.Ipsec.IpComp
{
    /// <summary>
    /// IP Payload Compression Protocol (IPComp, RFC 3173) with the DEFLATE transform (RFC 2394 = raw DEFLATE, RFC 1951 —
    /// <b>no zlib/gzip wrapper</b>). Compresses an IP payload before it is handed to ESP ("compress-then-encrypt"): each
    /// datagram is compressed independently with no history carried between packets (RFC 2394), so the codec is a pure,
    /// stateless function — reset every packet — and is exposed as static methods.
    /// <para>
    /// Re-implemented from the RFC (clean-room), not copied from any GPL/AGPL source. <see cref="DeflateStream"/> is used
    /// (available on both <c>netstandard2.0</c> and <c>net8.0</c>) and produces exactly the raw DEFLATE stream RFC 2394
    /// requires. The <b>non-expansion policy</b> (RFC 3173 §2.2) is enforced in <see cref="TryCompress"/>: the IPComp
    /// datagram is only produced when it is strictly smaller than the original payload; otherwise the caller sends the
    /// payload uncompressed with its original protocol number (no IPComp header).
    /// </para>
    /// </summary>
    public static class IpCompCodec
    {
        /// <summary>Upper bound on a decompressed IPComp payload; guards <see cref="Decompress"/> against a decompression bomb.</summary>
        public const int MaxDecompressedSize = 256 * 1024;

        /// <summary>
        /// Applies the DEFLATE transform to <paramref name="payload"/> and, when that shrinks the datagram, returns the
        /// IPComp datagram <c>[IPComp header ‖ raw DEFLATE stream]</c> in <paramref name="ipcompDatagram"/> and <c>true</c>.
        /// When compressing would not shrink it (non-expansion policy, RFC 3173 §2.2 — small or incompressible payloads),
        /// returns <c>false</c> and an empty array; the caller then sends <paramref name="payload"/> uncompressed under its
        /// original protocol, so a receiver never sees an IPComp header on such a datagram.
        /// </summary>
        /// <param name="payload">The IP payload to compress.</param>
        /// <param name="nextHeader">The IP protocol number of <paramref name="payload"/>, recorded in the IPComp header.</param>
        /// <param name="ipcompDatagram">The IPComp datagram when <c>true</c> is returned; otherwise an empty array.</param>
        public static bool TryCompress(ReadOnlySpan<byte> payload, byte nextHeader, out byte[] ipcompDatagram)
        {
            byte[] compressed = Deflate(payload);
            // Non-expansion policy (RFC 3173 §2.2): the IPComp datagram (header + compressed) must be STRICTLY smaller
            // than the original payload, otherwise send the payload as-is (uncompressed) — never inflate a datagram.
            if (IpCompHeader.Size + compressed.Length >= payload.Length)
            {
                ipcompDatagram = Array.Empty<byte>();
                return false;
            }

            byte[] datagram = new byte[IpCompHeader.Size + compressed.Length];
            IpCompHeader.Deflate(nextHeader).WriteTo(datagram);
            compressed.CopyTo(datagram.AsSpan(IpCompHeader.Size));
            ipcompDatagram = datagram;
            return true;
        }

        /// <summary>
        /// Reverses <see cref="TryCompress"/>: parses the IPComp header of <paramref name="ipcompDatagram"/>, inflates the
        /// DEFLATE body and returns the original payload; the header's Next Header is returned in <paramref name="nextHeader"/>.
        /// </summary>
        /// <exception cref="FormatException">The datagram is shorter than the header or carries a corrupt DEFLATE stream.</exception>
        /// <exception cref="NotSupportedException">The CPI is not the DEFLATE transform (only DEFLATE is supported).</exception>
        public static byte[] Decompress(ReadOnlySpan<byte> ipcompDatagram, out byte nextHeader)
        {
            IpCompHeader header = IpCompHeader.Parse(ipcompDatagram);
            if (header.Cpi != (ushort)IpCompTransform.Deflate)
                throw new NotSupportedException(
                    $"IPComp CPI 0x{header.Cpi:x4} is not the DEFLATE transform (CPI {(ushort)IpCompTransform.Deflate}, RFC 2394); only DEFLATE is supported.");
            nextHeader = header.NextHeader;
            return Inflate(ipcompDatagram.Slice(IpCompHeader.Size));
        }

        static byte[] Deflate(ReadOnlySpan<byte> data)
        {
            using var output = new MemoryStream();
            using (var deflate = new DeflateStream(output, CompressionMode.Compress, leaveOpen: true))
            {
                byte[] buffer = data.ToArray();
                deflate.Write(buffer, 0, buffer.Length);
            }
            return output.ToArray();
        }

        static byte[] Inflate(ReadOnlySpan<byte> compressed)
        {
            try
            {
                using var input = new MemoryStream(compressed.ToArray(), writable: false);
                using var deflate = new DeflateStream(input, CompressionMode.Decompress);
                using var output = new MemoryStream();
                byte[] buffer = new byte[4096];
                int read;
                while ((read = deflate.Read(buffer, 0, buffer.Length)) > 0)
                {
                    output.Write(buffer, 0, read);
                    if (output.Length > MaxDecompressedSize)
                        throw new FormatException(
                            $"IPComp payload inflates past the {MaxDecompressedSize}-byte limit (RFC 3173).");
                }
                return output.ToArray();
            }
            catch (InvalidDataException ex)
            {
                throw new FormatException("IPComp datagram carries a corrupt DEFLATE stream (RFC 2394/1951).", ex);
            }
        }
    }
}
