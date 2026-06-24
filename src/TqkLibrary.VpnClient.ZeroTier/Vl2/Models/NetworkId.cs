using System.Buffers.Binary;

namespace TqkLibrary.VpnClient.ZeroTier.Vl2.Models
{
    /// <summary>
    /// A 64-bit ZeroTier virtual-network identifier (VL2). The most-significant 40 bits are the address of the network
    /// controller that issues this network's configuration; the low 24 bits select a network on that controller. It is
    /// printed as 16 lowercase hex digits.
    /// </summary>
    public readonly struct NetworkId : IEquatable<NetworkId>
    {
        /// <summary>Network-id length on the wire (64 bits).</summary>
        public const int SizeInBytes = 8;

        /// <summary>The raw 64-bit value.</summary>
        public ulong Value { get; }

        /// <summary>Wraps a raw 64-bit network id.</summary>
        public NetworkId(ulong value) => Value = value;

        /// <summary>The 40-bit address of the controller that hosts this network (high 40 bits).</summary>
        public ulong ControllerAddress => (Value >> 24) & 0xFF_FFFF_FFFFUL;

        /// <summary>Reads an 8-byte big-endian network id from <paramref name="source"/>.</summary>
        public static NetworkId Read(ReadOnlySpan<byte> source)
        {
            if (source.Length < SizeInBytes) throw new ArgumentException("need >= 8 bytes", nameof(source));
            return new NetworkId(BinaryPrimitives.ReadUInt64BigEndian(source));
        }

        /// <summary>Writes this network id as 8 big-endian bytes into <paramref name="destination"/>.</summary>
        public void Write(Span<byte> destination)
        {
            if (destination.Length < SizeInBytes) throw new ArgumentException("need >= 8 bytes", nameof(destination));
            BinaryPrimitives.WriteUInt64BigEndian(destination, Value);
        }

        /// <summary>Parses a 16-hex-digit string.</summary>
        public static NetworkId Parse(string hex)
        {
            if (hex is null) throw new ArgumentNullException(nameof(hex));
            if (hex.Length != 16) throw new FormatException("network id must be 16 hex digits");
            return new NetworkId(Convert.ToUInt64(hex, 16));
        }

        /// <inheritdoc/>
        public bool Equals(NetworkId other) => Value == other.Value;

        /// <inheritdoc/>
        public override bool Equals(object? obj) => obj is NetworkId n && Equals(n);

        /// <inheritdoc/>
        public override int GetHashCode() => Value.GetHashCode();

        /// <summary>16 lowercase hex digits.</summary>
        public override string ToString() => Value.ToString("x16");
    }
}
