using System.Buffers.Binary;
using TqkLibrary.VpnClient.Crypto.Mppe.Enums;
using TqkLibrary.VpnClient.Pptp.Enums;

namespace TqkLibrary.VpnClient.Pptp.Ccp
{
    /// <summary>
    /// The CCP MPPE configuration option (RFC 2118 §3 / RFC 3078 §3.1): option type 18, length 6, carrying a
    /// 4-byte "supported bits" field. This codec maps between that on-the-wire 4-byte word
    /// (<see cref="MppeSupportedBits"/>) and the things the data plane needs: the negotiated key
    /// <see cref="Strength"/> (<see cref="MppeKeyStrength"/>, reused from the Crypto MPPE layer) and whether
    /// <see cref="Stateless"/> mode was selected.
    /// <para>
    /// The option value is the 4 bytes of the <see cref="MppeSupportedBits"/> word in big-endian; the full TLV is
    /// the 2-byte CCP option header (Type=18, Length=6) followed by those 4 bytes. Only a single encryption bit
    /// should be set in a negotiated value (RFC 3078 §3.1).
    /// </para>
    /// </summary>
    public sealed class MppeConfigOption
    {
        /// <summary>CCP option type for MPPE/MPPC (RFC 2118 §3).</summary>
        public const byte OptionType = (byte)CcpOptionType.MppeMppc;

        /// <summary>TLV length of the option (2-byte header + 4-byte value).</summary>
        public const int OptionLength = 6;

        /// <summary>The raw supported-bits word (the union of flags this option advertises/selects).</summary>
        public MppeSupportedBits Bits { get; set; }

        /// <summary>Creates an empty option (no bits set).</summary>
        public MppeConfigOption() { }

        /// <summary>Creates an option from a raw supported-bits word.</summary>
        public MppeConfigOption(MppeSupportedBits bits) => Bits = bits;

        /// <summary>
        /// Creates an option requesting a single encryption strength and stateless flag — the typical value a
        /// client offers (e.g. 128-bit stateful).
        /// </summary>
        public MppeConfigOption(MppeKeyStrength strength, bool stateless)
        {
            Bits = StrengthBit(strength);
            if (stateless) Bits |= MppeSupportedBits.Stateless;
        }

        /// <summary>True if MPPC compression is advertised (bit C). Not implemented — informational only.</summary>
        public bool Mppc => (Bits & MppeSupportedBits.Mppc) != 0;

        /// <summary>True if stateless mode (per-packet re-key) is set (bit S).</summary>
        public bool Stateless => (Bits & MppeSupportedBits.Stateless) != 0;

        /// <summary>True if any encryption bit (40/56/128) is set.</summary>
        public bool HasEncryption => (Bits & (MppeSupportedBits.Encrypt40Bit | MppeSupportedBits.Encrypt56Bit | MppeSupportedBits.Encrypt128Bit)) != 0;

        /// <summary>
        /// The single negotiated key strength. When multiple bits are set the strongest wins (128 &gt; 56 &gt; 40),
        /// which is also how a peer should reduce an over-broad offer. Throws if no encryption bit is set.
        /// </summary>
        public MppeKeyStrength Strength
        {
            get
            {
                if ((Bits & MppeSupportedBits.Encrypt128Bit) != 0) return MppeKeyStrength.Bits128;
                if ((Bits & MppeSupportedBits.Encrypt56Bit) != 0) return MppeKeyStrength.Bits56;
                if ((Bits & MppeSupportedBits.Encrypt40Bit) != 0) return MppeKeyStrength.Bits40;
                throw new InvalidOperationException("MPPE option carries no encryption strength bit.");
            }
        }

        /// <summary>Encodes the 4-byte option value (the supported-bits word, big-endian).</summary>
        public byte[] EncodeValue()
        {
            byte[] value = new byte[4];
            BinaryPrimitives.WriteUInt32BigEndian(value, (uint)Bits);
            return value;
        }

        /// <summary>Parses a 4-byte option value into an <see cref="MppeConfigOption"/>.</summary>
        public static MppeConfigOption DecodeValue(ReadOnlySpan<byte> value)
        {
            if (value.Length != 4)
                throw new FormatException($"MPPE option value must be 4 bytes (got {value.Length}).");
            return new MppeConfigOption((MppeSupportedBits)BinaryPrimitives.ReadUInt32BigEndian(value));
        }

        /// <summary>The single supported-bits flag for a given key strength.</summary>
        public static MppeSupportedBits StrengthBit(MppeKeyStrength strength) => strength switch
        {
            MppeKeyStrength.Bits40 => MppeSupportedBits.Encrypt40Bit,
            MppeKeyStrength.Bits56 => MppeSupportedBits.Encrypt56Bit,
            MppeKeyStrength.Bits128 => MppeSupportedBits.Encrypt128Bit,
            _ => MppeSupportedBits.None,
        };
    }
}
