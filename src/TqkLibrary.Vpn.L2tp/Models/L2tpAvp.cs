using System.Text;
using TqkLibrary.Vpn.L2tp.Enums;

namespace TqkLibrary.Vpn.L2tp.Models
{
    /// <summary>
    /// An L2TP Attribute-Value Pair (RFC 2661 §4.1): M|H flags, 10-bit length, Vendor ID, Attribute Type, value.
    /// Only IETF (vendor 0), non-hidden AVPs are produced; hidden AVPs parse but are not decrypted.
    /// </summary>
    public sealed class L2tpAvp
    {
        /// <summary>Mandatory bit — if set and unrecognised, the peer must drop the session.</summary>
        public bool Mandatory { get; set; } = true;

        /// <summary>Hidden bit — value is obscured with the tunnel secret (not used here).</summary>
        public bool Hidden { get; set; }

        /// <summary>Vendor ID (0 for IETF AVPs).</summary>
        public ushort VendorId { get; set; }

        /// <summary>The attribute type.</summary>
        public L2tpAvpType Type { get; set; }

        /// <summary>The raw attribute value.</summary>
        public byte[] Value { get; set; } = Array.Empty<byte>();

        /// <summary>Creates a mandatory IETF AVP with a raw value.</summary>
        public static L2tpAvp Create(L2tpAvpType type, byte[] value, bool mandatory = true)
            => new() { Type = type, Value = value, Mandatory = mandatory };

        /// <summary>Creates an AVP whose value is a single big-endian 16-bit word.</summary>
        public static L2tpAvp UInt16(L2tpAvpType type, ushort value, bool mandatory = true)
            => Create(type, new[] { (byte)(value >> 8), (byte)value }, mandatory);

        /// <summary>Creates an AVP whose value is a big-endian 32-bit word.</summary>
        public static L2tpAvp UInt32(L2tpAvpType type, uint value, bool mandatory = true)
            => Create(type, new[] { (byte)(value >> 24), (byte)(value >> 16), (byte)(value >> 8), (byte)value }, mandatory);

        /// <summary>Creates an AVP whose value is ASCII text.</summary>
        public static L2tpAvp Text(L2tpAvpType type, string value, bool mandatory = true)
            => Create(type, Encoding.ASCII.GetBytes(value), mandatory);

        /// <summary>Reads the value as a big-endian 16-bit word.</summary>
        public ushort AsUInt16() => (ushort)((Value[0] << 8) | Value[1]);

        /// <summary>Reads the value as a big-endian 32-bit word.</summary>
        public uint AsUInt32() => (uint)((Value[0] << 24) | (Value[1] << 16) | (Value[2] << 8) | Value[3]);

        internal void Write(List<byte> output)
        {
            int length = 6 + Value.Length;
            ushort flagsAndLength = (ushort)(length & 0x03FF);
            if (Mandatory) flagsAndLength |= 0x8000;
            if (Hidden) flagsAndLength |= 0x4000;
            output.Add((byte)(flagsAndLength >> 8));
            output.Add((byte)flagsAndLength);
            output.Add((byte)(VendorId >> 8));
            output.Add((byte)VendorId);
            output.Add((byte)((ushort)Type >> 8));
            output.Add((byte)(ushort)Type);
            output.AddRange(Value);
        }

        internal static L2tpAvp Parse(ReadOnlySpan<byte> avp)
        {
            ushort flagsAndLength = (ushort)((avp[0] << 8) | avp[1]);
            int length = flagsAndLength & 0x03FF;
            return new L2tpAvp
            {
                Mandatory = (flagsAndLength & 0x8000) != 0,
                Hidden = (flagsAndLength & 0x4000) != 0,
                VendorId = (ushort)((avp[2] << 8) | avp[3]),
                Type = (L2tpAvpType)((avp[4] << 8) | avp[5]),
                Value = avp.Slice(6, length - 6).ToArray(),
            };
        }

        internal int WireLength => 6 + Value.Length;
    }
}
