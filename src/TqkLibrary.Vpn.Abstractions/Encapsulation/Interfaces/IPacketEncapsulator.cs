using System.Buffers;

namespace TqkLibrary.Vpn.Abstractions.Encapsulation.Interfaces
{
    /// <summary>
    /// Frames a payload onto a transport: length-prefix (Fortinet/CSTP/SSTP), HDLC-async (PPP),
    /// fixed-header datagram (WireGuard/ESP/VXLAN), or TLV. Decoding is incremental over a buffered stream.
    /// </summary>
    public interface IPacketEncapsulator
    {
        /// <summary>Writes the framed form of <paramref name="payload"/> to <paramref name="destination"/>.</summary>
        void Encode(IBufferWriter<byte> destination, ReadOnlySpan<byte> payload);

        /// <summary>
        /// Tries to decode one complete payload from the front of <paramref name="buffer"/>. On success, advances
        /// <paramref name="buffer"/> past the consumed bytes and returns the payload; otherwise returns false.
        /// </summary>
        bool TryDecode(ref ReadOnlySequence<byte> buffer, out ReadOnlyMemory<byte> payload);
    }
}
