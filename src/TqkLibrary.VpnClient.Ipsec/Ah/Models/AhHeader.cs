using System.Buffers.Binary;

namespace TqkLibrary.VpnClient.Ipsec.Ah.Models
{
    /// <summary>
    /// The fixed 12-byte part of the IP Authentication Header (RFC 4302 §2): <c>Next Header (1)</c> ‖
    /// <c>Payload Len (1)</c> ‖ <c>Reserved (2) = 0</c> ‖ <c>SPI (4)</c> ‖ <c>Sequence Number (4)</c>, followed on the
    /// wire by the ICV (Integrity Check Value — a multiple of 4 bytes; e.g. HMAC-SHA-256-128 ⇒ 16, HMAC-SHA1-96 ⇒ 12).
    /// The ICV is not part of this struct: it is written/read by <see cref="AhSession"/> around the fixed part.
    /// <para><b>Payload Len</b> (RFC 4302 §2.2) is the total AH length measured in 4-byte words, minus 2.</para>
    /// </summary>
    public readonly struct AhHeader
    {
        /// <summary>Length in bytes of the fixed part of AH, before the ICV (RFC 4302 §2).</summary>
        public const int FixedSize = 12;

        /// <summary>The IP protocol number that identifies an Authentication Header (RFC 4302 §2).</summary>
        public const byte ProtocolNumber = 51;

        /// <summary>Creates a header from its already-decoded fields.</summary>
        public AhHeader(byte nextHeader, byte payloadLength, uint securityParametersIndex, uint sequenceNumber)
        {
            NextHeader = nextHeader;
            PayloadLength = payloadLength;
            SecurityParametersIndex = securityParametersIndex;
            SequenceNumber = sequenceNumber;
        }

        /// <summary>The IP protocol number of whatever follows AH (upper-layer protocol in transport mode, 4/41 in tunnel mode).</summary>
        public byte NextHeader { get; }

        /// <summary>The Payload Len field: total AH length in 4-byte words minus 2 (RFC 4302 §2.2).</summary>
        public byte PayloadLength { get; }

        /// <summary>The Security Parameters Index identifying the SA (RFC 4302 §2.4).</summary>
        public uint SecurityParametersIndex { get; }

        /// <summary>The anti-replay Sequence Number (RFC 4302 §2.5).</summary>
        public uint SequenceNumber { get; }

        /// <summary>ICV length in bytes implied by <see cref="PayloadLength"/>: <c>(PayloadLen + 2) × 4 − FixedSize</c>.</summary>
        public int IcvLength => (PayloadLength + 2) * 4 - FixedSize;

        /// <summary>Total AH length in bytes (fixed part + ICV) for a given ICV size.</summary>
        public static int TotalLength(int icvLength) => FixedSize + icvLength;

        /// <summary>The Payload Len field value for a given ICV size (RFC 4302 §2.2): total AH in 4-byte words − 2.</summary>
        public static byte PayloadLengthFor(int icvLength) => checked((byte)((FixedSize + icvLength) / 4 - 2));

        /// <summary>Builds a header for the given SPI/sequence carrying an ICV of <paramref name="icvLength"/> bytes.</summary>
        public static AhHeader Create(byte nextHeader, uint securityParametersIndex, uint sequenceNumber, int icvLength)
            => new(nextHeader, PayloadLengthFor(icvLength), securityParametersIndex, sequenceNumber);

        /// <summary>
        /// Serialises the 12 fixed bytes into the front of <paramref name="destination"/> (Reserved = 0, SPI/Seq
        /// big-endian). The ICV region that follows is left untouched (the caller zeroes it before computing the ICV).
        /// </summary>
        public void WriteFixed(Span<byte> destination)
        {
            destination[0] = NextHeader;
            destination[1] = PayloadLength;
            destination[2] = 0; // Reserved (RFC 4302 §2.2: MUST be 0)
            destination[3] = 0;
            BinaryPrimitives.WriteUInt32BigEndian(destination.Slice(4), SecurityParametersIndex);
            BinaryPrimitives.WriteUInt32BigEndian(destination.Slice(8), SequenceNumber);
        }

        /// <summary>
        /// Parses the 12 fixed bytes from the front of <paramref name="authenticationHeader"/> (the ICV that follows
        /// is not read here). Throws <see cref="FormatException"/> when fewer than <see cref="FixedSize"/> bytes exist.
        /// </summary>
        public static AhHeader Parse(ReadOnlySpan<byte> authenticationHeader)
        {
            if (authenticationHeader.Length < FixedSize)
                throw new FormatException(
                    $"Authentication Header is {authenticationHeader.Length} bytes, shorter than the {FixedSize}-byte fixed part (RFC 4302 §2).");
            return new AhHeader(
                authenticationHeader[0],
                authenticationHeader[1],
                BinaryPrimitives.ReadUInt32BigEndian(authenticationHeader.Slice(4)),
                BinaryPrimitives.ReadUInt32BigEndian(authenticationHeader.Slice(8)));
        }
    }
}
