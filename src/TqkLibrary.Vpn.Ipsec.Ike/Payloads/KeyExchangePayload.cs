using TqkLibrary.Vpn.Ipsec.Ike.Enums;

namespace TqkLibrary.Vpn.Ipsec.Ike.Payloads
{
    /// <summary>Key Exchange payload: a D-H group number plus the public value (RFC 7296 §3.4).</summary>
    public sealed class KeyExchangePayload : IkePayload
    {
        /// <inheritdoc/>
        public override IkePayloadType Type => IkePayloadType.KeyExchange;

        /// <summary>The D-H group of the key data (e.g. 14 for MODP-2048).</summary>
        public ushort DiffieHellmanGroup { get; set; }

        /// <summary>The big-endian public value g^x mod p.</summary>
        public byte[] KeyData { get; set; } = Array.Empty<byte>();

        /// <inheritdoc/>
        public override void WriteBody(List<byte> output)
        {
            IkeBuffer.WriteUInt16(output, DiffieHellmanGroup);
            IkeBuffer.WriteUInt16(output, 0); // reserved
            output.AddRange(KeyData);
        }

        internal static KeyExchangePayload Parse(ReadOnlySpan<byte> body)
            => new()
            {
                DiffieHellmanGroup = IkeBuffer.ReadUInt16(body, 0),
                KeyData = body.Slice(4).ToArray(),
            };
    }
}
