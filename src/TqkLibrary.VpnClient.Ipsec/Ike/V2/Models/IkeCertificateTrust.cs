using System.Security.Cryptography.X509Certificates;

namespace TqkLibrary.VpnClient.Ipsec.Ike.V2.Models
{
    /// <summary>
    /// The client's trust anchor for verifying a responder that authenticates with a digital signature
    /// (RFC 7296 §2.15 method 1/9/14). Either pin the gateway's leaf certificate(s) directly, or supply the
    /// trusted CA certificate(s) the gateway's leaf must chain to. A responder certificate is accepted when it
    /// equals a pinned leaf or builds a chain rooted in one of the trusted CAs.
    /// </summary>
    public sealed class IkeCertificateTrust
    {
        readonly X509Certificate2[] _trustedCertificates;
        readonly bool _pinLeaf;

        /// <summary>
        /// Creates a trust anchor over <paramref name="trustedCertificates"/>. When <paramref name="pinLeaf"/> is true
        /// the responder certificate must <em>equal</em> one of them (certificate pinning); otherwise they are treated
        /// as trusted CA roots/intermediates the responder's leaf must chain to.
        /// </summary>
        public IkeCertificateTrust(IEnumerable<X509Certificate2> trustedCertificates, bool pinLeaf = false)
        {
            _trustedCertificates = trustedCertificates?.ToArray() ?? throw new ArgumentNullException(nameof(trustedCertificates));
            if (_trustedCertificates.Length == 0)
                throw new ArgumentException("At least one trusted certificate is required.", nameof(trustedCertificates));
            _pinLeaf = pinLeaf;
        }

        /// <summary>Pins the responder's leaf certificate(s): only an exact match is accepted.</summary>
        public static IkeCertificateTrust PinLeaf(params X509Certificate2[] leafCertificates)
            => new(leafCertificates, pinLeaf: true);

        /// <summary>Trusts the given CA certificate(s): a responder leaf chaining to one of them is accepted.</summary>
        public static IkeCertificateTrust TrustCa(params X509Certificate2[] caCertificates)
            => new(caCertificates, pinLeaf: false);

        /// <summary>
        /// Returns true if <paramref name="responderCertificate"/> is trusted: it equals a pinned leaf, or its chain
        /// terminates in one of the configured CA certificates. Chain building is offline (no AIA/OCSP/CRL fetch) and
        /// rooted strictly in the supplied CAs — the OS trust store is not consulted.
        /// </summary>
        public bool IsTrusted(X509Certificate2 responderCertificate)
        {
            if (responderCertificate is null) return false;

            if (_pinLeaf)
                return _trustedCertificates.Any(c => c.RawData.AsSpan().SequenceEqual(responderCertificate.RawData));

            using var chain = new X509Chain();
            chain.ChainPolicy.RevocationMode = X509RevocationMode.NoCheck;
            chain.ChainPolicy.VerificationFlags = X509VerificationFlags.AllowUnknownCertificateAuthority;
            foreach (X509Certificate2 ca in _trustedCertificates)
                chain.ChainPolicy.ExtraStore.Add(ca);

            bool built = chain.Build(responderCertificate);
            // The chain root must be one of OUR trusted CAs (AllowUnknownCertificateAuthority lets Build() succeed
            // without the OS store, so we explicitly require the terminal element to be a configured CA).
            X509ChainElement[] elements = chain.ChainElements.Cast<X509ChainElement>().ToArray();
            if (elements.Length == 0) return false;
            X509Certificate2 root = elements[elements.Length - 1].Certificate;
            bool rootTrusted = _trustedCertificates.Any(c => c.RawData.AsSpan().SequenceEqual(root.RawData));
            return rootTrusted && built;
        }
    }
}
