using TqkLibrary.VpnClient.OpenConnect.Enums;
using TqkLibrary.VpnClient.OpenConnect.Models;

namespace TqkLibrary.VpnClient.OpenConnect
{
    /// <summary>
    /// CSTP framing for the <b>datagram</b> (DTLS) data path — the UDP/DTLS counterpart of the byte-stream
    /// <see cref="CstpFraming"/>. On DTLS every CSTP packet rides one datagram, so there is no STF magic and no 16-bit
    /// length prefix: the framing is a single leading byte (the <see cref="CstpPacketType"/>) followed by the payload.
    /// One datagram in = exactly one CSTP packet out, so no streaming reassembler is needed (unlike the TLS path).
    /// Re-implemented from the published OpenConnect/AnyConnect wire behaviour (draft-mavrogiannopoulos-openconnect) —
    /// the DTLS CSTP header is the bare type byte — not copied from the GPL source.
    /// </summary>
    public static class CstpDatagramFraming
    {
        /// <summary>The fixed 1-byte datagram CSTP header size (just the type byte).</summary>
        public const int HeaderSize = 1;

        /// <summary>
        /// Frames one outgoing packet as the 1-byte type header followed by <paramref name="payload"/>. Control packets
        /// (DPD/keep-alive/disconnect/terminate) pass an empty payload (a single type byte).
        /// </summary>
        public static byte[] Encode(CstpPacketType type, ReadOnlySpan<byte> payload)
        {
            byte[] framed = new byte[HeaderSize + payload.Length];
            framed[0] = (byte)type;
            payload.CopyTo(framed.AsSpan(HeaderSize));
            return framed;
        }

        /// <summary>
        /// Decodes exactly one CSTP packet from <paramref name="datagram"/> (type byte + the rest as payload). Throws
        /// <see cref="FormatException"/> on an empty datagram (no type byte). One datagram is always one whole packet on
        /// the DTLS path, so there is no partial-read case to handle.
        /// </summary>
        public static CstpPacket Decode(ReadOnlySpan<byte> datagram)
        {
            if (datagram.Length < HeaderSize)
                throw new FormatException("CSTP-over-DTLS datagram is empty (missing the type byte).");
            return new CstpPacket((CstpPacketType)datagram[0], datagram.Slice(HeaderSize).ToArray());
        }
    }
}
