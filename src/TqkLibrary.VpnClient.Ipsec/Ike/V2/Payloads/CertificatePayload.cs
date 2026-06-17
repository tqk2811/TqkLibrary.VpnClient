using TqkLibrary.VpnClient.Ipsec.Ike.V2.Enums;

namespace TqkLibrary.VpnClient.Ipsec.Ike.V2.Payloads
{
    /// <summary>
    /// Certificate payload (RFC 7296 §3.6): Cert Encoding(1) | Certificate Data. For the usual
    /// <see cref="IkeCertificateEncoding.X509CertificateSignature"/> the data is one DER-encoded X.509 certificate
    /// whose public key verifies the peer's AUTH signature (RFC 7296 §2.15).
    /// </summary>
    public sealed class CertificatePayload : IkePayload
    {
        /// <inheritdoc/>
        public override IkePayloadType Type => IkePayloadType.Certificate;

        /// <summary>The certificate encoding (4 = a single DER X.509 certificate).</summary>
        public IkeCertificateEncoding Encoding { get; set; } = IkeCertificateEncoding.X509CertificateSignature;

        /// <summary>The certificate data (DER bytes for an X.509 encoding).</summary>
        public byte[] Data { get; set; } = Array.Empty<byte>();

        /// <inheritdoc/>
        public override void WriteBody(List<byte> output)
        {
            output.Add((byte)Encoding);
            output.AddRange(Data);
        }

        internal static CertificatePayload Parse(ReadOnlySpan<byte> body)
            => new()
            {
                Encoding = body.Length > 0 ? (IkeCertificateEncoding)body[0] : IkeCertificateEncoding.None,
                Data = body.Length > 1 ? body.Slice(1).ToArray() : Array.Empty<byte>(),
            };
    }
}
