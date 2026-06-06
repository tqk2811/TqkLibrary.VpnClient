using TqkLibrary.Vpn.Ipsec.Ike.Enums;
using TqkLibrary.Vpn.Ipsec.Ike.Models;

namespace TqkLibrary.Vpn.Ipsec.Ike.Payloads
{
    /// <summary>
    /// Security Association payload: a list of proposals, each a list of transforms (RFC 7296 §3.3).
    /// The "more" link flags (Proposal/Transform substructure type 2 vs 0) are derived during encode.
    /// </summary>
    public sealed class SecurityAssociationPayload : IkePayload
    {
        /// <inheritdoc/>
        public override IkePayloadType Type => IkePayloadType.SecurityAssociation;

        /// <summary>The proposals carried by this SA payload.</summary>
        public List<IkeProposal> Proposals { get; } = new();

        /// <inheritdoc/>
        public override void WriteBody(List<byte> output)
        {
            for (int p = 0; p < Proposals.Count; p++)
                WriteProposal(output, Proposals[p], isLast: p == Proposals.Count - 1);
        }

        static void WriteProposal(List<byte> output, IkeProposal proposal, bool isLast)
        {
            int start = output.Count;
            output.Add((byte)(isLast ? 0 : 2)); // 0 = last, 2 = more proposals follow
            output.Add(0);                       // reserved
            IkeBuffer.WriteUInt16(output, 0);    // length placeholder
            output.Add(proposal.Number);
            output.Add((byte)proposal.ProtocolId);
            output.Add((byte)proposal.Spi.Length);
            output.Add((byte)proposal.Transforms.Count);
            output.AddRange(proposal.Spi);

            for (int t = 0; t < proposal.Transforms.Count; t++)
                WriteTransform(output, proposal.Transforms[t], isLast: t == proposal.Transforms.Count - 1);

            int length = output.Count - start;
            output[start + 2] = (byte)(length >> 8);
            output[start + 3] = (byte)length;
        }

        static void WriteTransform(List<byte> output, IkeTransform transform, bool isLast)
        {
            int start = output.Count;
            output.Add((byte)(isLast ? 0 : 3)); // 0 = last, 3 = more transforms follow
            output.Add(0);                       // reserved
            IkeBuffer.WriteUInt16(output, 0);    // length placeholder
            output.Add((byte)transform.Type);
            output.Add(0);                       // reserved
            IkeBuffer.WriteUInt16(output, transform.Id);

            foreach (IkeTransformAttribute attribute in transform.Attributes)
            {
                // TV format: high bit (0x8000) set marks a 2-byte value attribute.
                IkeBuffer.WriteUInt16(output, (ushort)(0x8000 | attribute.Type));
                IkeBuffer.WriteUInt16(output, attribute.Value);
            }

            int length = output.Count - start;
            output[start + 2] = (byte)(length >> 8);
            output[start + 3] = (byte)length;
        }

        internal static SecurityAssociationPayload Parse(ReadOnlySpan<byte> body)
        {
            var sa = new SecurityAssociationPayload();
            int offset = 0;
            while (offset < body.Length)
            {
                byte more = body[offset];
                int propLength = IkeBuffer.ReadUInt16(body, offset + 2);
                if (propLength < 8 || offset + propLength > body.Length) break;
                ReadOnlySpan<byte> prop = body.Slice(offset, propLength);

                var proposal = new IkeProposal
                {
                    Number = prop[4],
                    ProtocolId = (IkeProtocolId)prop[5],
                };
                int spiSize = prop[6];
                int transformCount = prop[7];
                int cursor = 8;
                proposal.Spi = prop.Slice(cursor, spiSize).ToArray();
                cursor += spiSize;

                for (int i = 0; i < transformCount && cursor < prop.Length; i++)
                {
                    int transformLength = IkeBuffer.ReadUInt16(prop, cursor + 2);
                    if (transformLength < 8 || cursor + transformLength > prop.Length) break;
                    var transform = new IkeTransform
                    {
                        Type = (IkeTransformType)prop[cursor + 4],
                        Id = IkeBuffer.ReadUInt16(prop, cursor + 6),
                    };
                    int attrOffset = cursor + 8;
                    while (attrOffset + 4 <= cursor + transformLength)
                    {
                        ushort attrType = IkeBuffer.ReadUInt16(prop, attrOffset);
                        if ((attrType & 0x8000) != 0) // TV form: 2-byte value
                        {
                            transform.Attributes.Add(new IkeTransformAttribute
                            {
                                Type = (ushort)(attrType & 0x7FFF),
                                Value = IkeBuffer.ReadUInt16(prop, attrOffset + 2),
                            });
                            attrOffset += 4;
                        }
                        else // TLV form: skip by declared length
                        {
                            int attrLen = IkeBuffer.ReadUInt16(prop, attrOffset + 2);
                            attrOffset += 4 + attrLen;
                        }
                    }
                    proposal.Transforms.Add(transform);
                    cursor += transformLength;
                }

                sa.Proposals.Add(proposal);
                offset += propLength;
                if (more == 0) break;
            }
            return sa;
        }
    }
}
