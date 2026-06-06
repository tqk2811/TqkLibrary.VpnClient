using TqkLibrary.Vpn.Ipsec.Ike.Enums;

namespace TqkLibrary.Vpn.Ipsec.Ike.Payloads
{
    /// <summary>
    /// A payload whose body is preserved verbatim. Used both for types not yet modelled (IDi, AUTH, TS, CP, CERTREQ…)
    /// and to round-trip anything the decoder does not specialise.
    /// </summary>
    public sealed class RawPayload : IkePayload
    {
        /// <inheritdoc/>
        public override IkePayloadType Type { get; }

        /// <summary>The opaque payload body (everything after the 4-byte generic header).</summary>
        public byte[] Body { get; }

        /// <summary>Creates a raw payload of the given type carrying <paramref name="body"/>.</summary>
        public RawPayload(IkePayloadType type, byte[] body)
        {
            Type = type;
            Body = body;
        }

        /// <inheritdoc/>
        public override void WriteBody(List<byte> output) => output.AddRange(Body);
    }
}
