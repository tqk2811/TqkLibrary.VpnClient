using System.Buffers.Binary;

namespace TqkLibrary.VpnClient.Transport.IpsecTcp
{
    /// <summary>
    /// Stateless wire codec for TCP encapsulation of IKE and ESP (RFC 8229). Re-implemented from the published RFC —
    /// not copied from any GPL implementation.
    /// <para>
    /// §3 <b>Stream prefix</b>: immediately after the TCP connection is established, the initiator (client) sends the
    /// fixed six-byte magic value <c>"IKETCP"</c> (<c>0x49 0x4B 0x45 0x54 0x43 0x50</c>) exactly once, before any
    /// message. The responder (server) does <b>not</b> echo it. §2 <b>Length framing</b>: every encapsulated IKE/ESP
    /// message is preceded by a 16-bit <b>Length</b> field in network byte order that <b>includes the two octets of the
    /// Length field itself</b> — so the smallest valid frame has Length <c>2</c> and carries an empty message. The
    /// receiver uses Length to restore the datagram boundaries the byte stream erased.
    /// </para>
    /// This class only frames/unframes bytes; the IKE-vs-ESP demultiplexing (RFC 3948 non-ESP marker) is the IPsec
    /// NAT-T layer's job, not this adapter's — each message here is opaque.
    /// </summary>
    public static class Rfc8229Framing
    {
        static readonly byte[] _streamPrefix = { 0x49, 0x4B, 0x45, 0x54, 0x43, 0x50 }; // "IKETCP"

        /// <summary>The RFC 8229 §3 stream prefix length: six bytes.</summary>
        public const int StreamPrefixLength = 6;

        /// <summary>The RFC 8229 §2 Length-field size: two octets (16-bit, network byte order).</summary>
        public const int LengthFieldSize = 2;

        /// <summary>
        /// The largest message that fits a 16-bit frame Length: <c>65535 - 2 = 65533</c> bytes
        /// (the Length field counts itself).
        /// </summary>
        public const int MaxMessageLength = ushort.MaxValue - LengthFieldSize;

        /// <summary>The six-byte stream prefix <c>"IKETCP"</c> the initiator sends once after connecting (§3).</summary>
        public static ReadOnlySpan<byte> StreamPrefix => _streamPrefix;

        /// <summary>
        /// Frames one IKE/ESP message: a 16-bit big-endian Length (message length + 2, per §2) followed by the message
        /// bytes. Throws <see cref="ArgumentOutOfRangeException"/> when <paramref name="message"/> exceeds
        /// <see cref="MaxMessageLength"/> (the total would overflow the 16-bit Length).
        /// </summary>
        public static byte[] Frame(ReadOnlySpan<byte> message)
        {
            if (message.Length > MaxMessageLength)
                throw new ArgumentOutOfRangeException(nameof(message),
                    $"RFC 8229 message length {message.Length} exceeds the {MaxMessageLength}-byte maximum for a 16-bit frame length.");

            int total = LengthFieldSize + message.Length;   // the Length field counts itself (§2)
            byte[] frame = new byte[total];
            BinaryPrimitives.WriteUInt16BigEndian(frame.AsSpan(0, LengthFieldSize), (ushort)total);
            message.CopyTo(frame.AsSpan(LengthFieldSize));
            return frame;
        }
    }
}
