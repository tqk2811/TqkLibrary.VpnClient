using System.Buffers.Binary;

namespace TqkLibrary.VpnClient.ZeroTier.Identity.Models
{
    /// <summary>
    /// A ZeroTier node address: a 40-bit (5-byte) identifier derived from a node's public key by the memory-hard
    /// hash (see <c>ZeroTierAddressDerivation</c>). On the wire it is the low 40 bits of a big-endian value and is
    /// printed as 10 lowercase hex digits.
    /// <para>
    /// Reserved values: an address may not be <see cref="Null"/> (all-zero) and its most-significant byte may not be
    /// <c>0xFF</c> (that prefix is reserved for ZeroTier's internal/controller addressing).
    /// </para>
    /// </summary>
    public readonly struct ZeroTierAddress : IEquatable<ZeroTierAddress>
    {
        /// <summary>Address length on the wire (40 bits).</summary>
        public const int SizeInBytes = 5;

        const ulong Mask40 = 0xFF_FFFF_FFFFUL;

        /// <summary>The all-zero (invalid) address.</summary>
        public static readonly ZeroTierAddress Null = new ZeroTierAddress(0);

        /// <summary>The 40-bit value (the upper 24 bits of the underlying ulong are always zero).</summary>
        public ulong Value { get; }

        /// <summary>Wraps a raw 40-bit value (any bits above bit 39 are masked off).</summary>
        public ZeroTierAddress(ulong value) => Value = value & Mask40;

        /// <summary>True if this address satisfies the reserved-value rules (non-zero, MSB != 0xFF).</summary>
        public bool IsValid => Value != 0 && ((Value >> 32) & 0xFF) != 0xFF;

        /// <summary>Reads a 40-bit big-endian address from the first 5 bytes of <paramref name="source"/>.</summary>
        public static ZeroTierAddress Read(ReadOnlySpan<byte> source)
        {
            if (source.Length < SizeInBytes) throw new ArgumentException("need >= 5 bytes", nameof(source));
            ulong v = ((ulong)source[0] << 32) | ((ulong)source[1] << 24) | ((ulong)source[2] << 16)
                    | ((ulong)source[3] << 8) | source[4];
            return new ZeroTierAddress(v);
        }

        /// <summary>Writes this address as 5 big-endian bytes into <paramref name="destination"/>.</summary>
        public void Write(Span<byte> destination)
        {
            if (destination.Length < SizeInBytes) throw new ArgumentException("need >= 5 bytes", nameof(destination));
            destination[0] = (byte)((Value >> 32) & 0xFF);
            destination[1] = (byte)((Value >> 24) & 0xFF);
            destination[2] = (byte)((Value >> 16) & 0xFF);
            destination[3] = (byte)((Value >> 8) & 0xFF);
            destination[4] = (byte)(Value & 0xFF);
        }

        /// <summary>Parses a 10-hex-digit string (case-insensitive, e.g. "8056c2e21c").</summary>
        public static ZeroTierAddress Parse(string hex)
        {
            if (hex is null) throw new ArgumentNullException(nameof(hex));
            if (hex.Length != 10) throw new FormatException("ZeroTier address must be 10 hex digits");
            return new ZeroTierAddress(Convert.ToUInt64(hex, 16));
        }

        /// <inheritdoc/>
        public bool Equals(ZeroTierAddress other) => Value == other.Value;

        /// <inheritdoc/>
        public override bool Equals(object? obj) => obj is ZeroTierAddress a && Equals(a);

        /// <inheritdoc/>
        public override int GetHashCode() => Value.GetHashCode();

        /// <summary>10 lowercase hex digits.</summary>
        public override string ToString() => Value.ToString("x10");
    }
}
