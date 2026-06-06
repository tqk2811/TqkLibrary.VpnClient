using TqkLibrary.Vpn.Ipsec.Ike.Enums;

namespace TqkLibrary.Vpn.Ipsec.Ike.Models
{
    /// <summary>A single transform attribute in TV (type/value) form — currently only Key Length (RFC 7296 §3.3.5).</summary>
    public sealed class IkeTransformAttribute
    {
        /// <summary>Attribute type (e.g. <see cref="IkeTransformId.KeyLengthAttribute"/>).</summary>
        public ushort Type { get; set; }

        /// <summary>The 16-bit value (e.g. AES key length in bits).</summary>
        public ushort Value { get; set; }

        /// <summary>Creates a Key Length attribute carrying <paramref name="keyBits"/> bits.</summary>
        public static IkeTransformAttribute KeyLength(ushort keyBits)
            => new() { Type = IkeTransformId.KeyLengthAttribute, Value = keyBits };
    }

    /// <summary>One transform within a proposal: a (type, id) pair plus optional attributes (RFC 7296 §3.3.2).</summary>
    public sealed class IkeTransform
    {
        /// <summary>The transform type (ENCR/PRF/INTEG/D-H/ESN).</summary>
        public IkeTransformType Type { get; set; }

        /// <summary>The transform ID within that type.</summary>
        public ushort Id { get; set; }

        /// <summary>Attached attributes (e.g. AES key length).</summary>
        public List<IkeTransformAttribute> Attributes { get; } = new();

        /// <summary>Creates a transform of the given type/id.</summary>
        public IkeTransform() { }

        /// <summary>Creates a transform of the given type/id.</summary>
        public IkeTransform(IkeTransformType type, ushort id)
        {
            Type = type;
            Id = id;
        }
    }
}
