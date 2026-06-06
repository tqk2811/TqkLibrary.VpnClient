using TqkLibrary.Vpn.Ipsec.Ike.Enums;

namespace TqkLibrary.Vpn.Ipsec.Ike.Payloads
{
    /// <summary>Nonce payload: the Ni / Nr random value (RFC 7296 §3.9, 16–256 bytes).</summary>
    public sealed class NoncePayload : IkePayload
    {
        /// <inheritdoc/>
        public override IkePayloadType Type => IkePayloadType.Nonce;

        /// <summary>The nonce bytes.</summary>
        public byte[] Nonce { get; set; } = Array.Empty<byte>();

        /// <inheritdoc/>
        public override void WriteBody(List<byte> output) => output.AddRange(Nonce);

        internal static NoncePayload Parse(ReadOnlySpan<byte> body) => new() { Nonce = body.ToArray() };
    }
}
