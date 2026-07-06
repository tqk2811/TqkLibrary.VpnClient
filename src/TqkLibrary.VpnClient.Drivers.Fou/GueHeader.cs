using System;

namespace TqkLibrary.VpnClient.Drivers.Fou
{
    /// <summary>
    /// Stateless codec for the GUE (Generic UDP Encapsulation) <b>variant 0</b> header (draft-ietf-intarea-gue). A pure
    /// encode/decode pair holding no tunnel state. The variant-0 header is 4 bytes plus a variable, self-describing block
    /// of extension fields:
    /// <list type="bullet">
    ///   <item>Byte 0 = <c>Ver(2) | C(1) | Hlen(5)</c> — Version (must be 0), Control bit, and the extension-field length
    ///   in 32-bit words.</item>
    ///   <item>Byte 1 = <c>Proto/ctype(8)</c> — the IANA IP protocol number of the payload (4/41 IPIP, 47 GRE, 50 ESP …).</item>
    ///   <item>Bytes 2-3 = Flags(16) — which extension fields follow; ignored here (we emit none and skip any we see).</item>
    ///   <item>Then <c>Hlen*4</c> bytes of extension fields, then the payload.</item>
    /// </list>
    /// This encoder always emits the minimal header (Ver=0, C=0, Hlen=0, Flags=0). The decoder validates Version==0,
    /// drops control messages (C=1, not data) and unknown/short buffers, and <b>skips</b> the extension block by length
    /// without interpreting it — an unrecognised extension is tolerated, per the draft's forward-compatibility rule.
    /// </summary>
    public static class GueHeader
    {
        /// <summary>The fixed length of the variant-0 header, before any extension fields.</summary>
        public const int BaseLength = 4;

        const byte VersionMask = 0xC0;   // byte 0, bits 0-1: Ver (must be 0 for variant 0)
        const byte ControlBit = 0x20;    // byte 0, bit 2: C — 1 = control message (not a data packet)
        const byte HlenMask = 0x1F;      // byte 0, bits 3-7: Hlen — extension length in 32-bit words

        /// <summary>
        /// Encodes a minimal GUE variant-0 datagram: a 4-byte header (Ver=0, C=0, Hlen=0, Flags=0) carrying
        /// <paramref name="protocol"/> as the payload's IP protocol number, followed by <paramref name="payload"/>.
        /// </summary>
        public static byte[] Encode(byte protocol, ReadOnlySpan<byte> payload)
        {
            byte[] buffer = new byte[BaseLength + payload.Length];
            buffer[0] = 0;          // Ver = 0, C = 0, Hlen = 0
            buffer[1] = protocol;   // Proto/ctype
            // buffer[2], buffer[3] = 0 (Flags — no extension fields requested)
            payload.CopyTo(buffer.AsSpan(BaseLength));
            return buffer;
        }

        /// <summary>
        /// Decodes one GUE variant-0 datagram. Returns <c>false</c> (with <paramref name="protocol"/>=0,
        /// <paramref name="payloadOffset"/>=0) on any input that is not a variant-0 data packet: shorter than the base
        /// header, a non-zero Version, a control message (C bit set), or a header whose declared extension block
        /// (<c>Hlen*4</c> bytes) runs past the buffer. On success, <paramref name="protocol"/> is the payload's IP protocol
        /// number and <paramref name="payloadOffset"/> is the index at which the payload begins (the caller takes
        /// <c>datagram[payloadOffset..]</c>; that slice may be empty).
        /// </summary>
        public static bool TryDecode(ReadOnlySpan<byte> datagram, out byte protocol, out int payloadOffset)
        {
            protocol = 0;
            payloadOffset = 0;
            if (datagram.Length < BaseLength) return false;

            byte byte0 = datagram[0];
            if ((byte0 & VersionMask) != 0) return false;   // GUE variant 0 only
            if ((byte0 & ControlBit) != 0) return false;    // control message — not a data packet, drop

            int extensionBytes = (byte0 & HlenMask) * 4;    // Hlen counts 32-bit words
            int headerLength = BaseLength + extensionBytes;
            if (datagram.Length < headerLength) return false; // extension block truncated

            protocol = datagram[1];
            payloadOffset = headerLength;                   // skip the extension fields without interpreting them
            return true;
        }
    }
}
