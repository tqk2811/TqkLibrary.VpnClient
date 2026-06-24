using TqkLibrary.VpnClient.Ipsec.Ike.V1.Enums;
using TqkLibrary.VpnClient.Ipsec.Ike.V1.Models;

namespace TqkLibrary.VpnClient.Ipsec.Ike.V1.Payloads
{
    /// <summary>
    /// An ISAKMP Attribute (Configuration Method) payload (draft-ietf-ipsec-isakmp-mode-cfg-04 §4): a 1-byte
    /// <see cref="CfgType"/>, a 1-byte RESERVED, a 16-bit <see cref="Identifier"/>, then a list of data attributes
    /// encoded exactly like ISAKMP SA attributes (the AF bit selects Type/Value or Type/Length/Value). It carries both
    /// XAUTH (user name / password / status) and Mode-Config (INTERNAL_IP4_ADDRESS / DNS / …) attributes.
    /// </summary>
    public sealed class IsakmpConfigPayload : IsakmpPayload
    {
        /// <inheritdoc/>
        public override IsakmpPayloadType Type => IsakmpPayloadType.Attribute;

        /// <summary>The configuration message type (REQUEST/REPLY/SET/ACK).</summary>
        public IsakmpCfgType CfgType { get; set; } = IsakmpCfgType.Request;

        /// <summary>The 16-bit identifier the originator chooses; the responder echoes it to pair request and reply.</summary>
        public ushort Identifier { get; set; }

        /// <summary>The data attributes (XAUTH or Mode-Config), in order.</summary>
        public List<IsakmpAttribute> Attributes { get; } = new();

        /// <summary>Returns the first attribute of the given type, or null.</summary>
        public IsakmpAttribute? Find(ushort type) => Attributes.FirstOrDefault(a => a.Type == type);

        /// <summary>True if an attribute of the given type is present.</summary>
        public bool Has(ushort type) => Attributes.Any(a => a.Type == type);

        /// <inheritdoc/>
        public override void WriteBody(List<byte> output)
        {
            output.Add((byte)CfgType);
            output.Add(0); // RESERVED
            output.Add((byte)(Identifier >> 8));
            output.Add((byte)Identifier);
            foreach (IsakmpAttribute attribute in Attributes) attribute.Write(output);
        }

        /// <summary>Parses an Attribute payload body (the bytes after the 4-byte generic header).</summary>
        public static IsakmpConfigPayload Parse(ReadOnlySpan<byte> body)
        {
            var payload = new IsakmpConfigPayload();
            if (body.Length < 4) return payload;
            payload.CfgType = (IsakmpCfgType)body[0];
            payload.Identifier = (ushort)((body[2] << 8) | body[3]);
            int offset = 4;
            while (offset + 4 <= body.Length)
            {
                IsakmpAttribute attribute = IsakmpAttribute.Parse(body.Slice(offset), out int consumed);
                if (consumed <= 0 || offset + consumed > body.Length) break;
                payload.Attributes.Add(attribute);
                offset += consumed;
            }
            return payload;
        }
    }
}
