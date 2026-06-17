using TqkLibrary.VpnClient.Ipsec.Ike.V2.Enums;

namespace TqkLibrary.VpnClient.Ipsec.Ike.V2.Payloads
{
    /// <summary>
    /// Certificate Request payload (RFC 7296 §3.7): Cert Encoding(1) | Certification Authority. For
    /// <see cref="IkeCertificateEncoding.X509CertificateSignature"/> the CA field is a concatenation of 20-byte
    /// SHA-1 hashes of the trusted CA public keys (empty = "any CA you have", which is what we send so the gateway
    /// returns its certificate and we validate it against our own configured trust).
    /// </summary>
    public sealed class CertificateRequestPayload : IkePayload
    {
        /// <inheritdoc/>
        public override IkePayloadType Type => IkePayloadType.CertificateRequest;

        /// <summary>The certificate encoding being requested (4 = a single DER X.509 certificate).</summary>
        public IkeCertificateEncoding Encoding { get; set; } = IkeCertificateEncoding.X509CertificateSignature;

        /// <summary>The Certification Authority field — a concatenation of 20-byte SHA-1 CA-key hashes (may be empty).</summary>
        public byte[] CertificateAuthority { get; set; } = Array.Empty<byte>();

        /// <summary>Builds a CERTREQ asking the peer for an X.509 signature certificate, with no CA restriction.</summary>
        public static CertificateRequestPayload AnyX509()
            => new() { Encoding = IkeCertificateEncoding.X509CertificateSignature, CertificateAuthority = Array.Empty<byte>() };

        /// <inheritdoc/>
        public override void WriteBody(List<byte> output)
        {
            output.Add((byte)Encoding);
            output.AddRange(CertificateAuthority);
        }

        internal static CertificateRequestPayload Parse(ReadOnlySpan<byte> body)
            => new()
            {
                Encoding = body.Length > 0 ? (IkeCertificateEncoding)body[0] : IkeCertificateEncoding.None,
                CertificateAuthority = body.Length > 1 ? body.Slice(1).ToArray() : Array.Empty<byte>(),
            };
    }
}
