using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using TqkLibrary.VpnClient.Crypto.Abstractions.Interfaces;
using TqkLibrary.VpnClient.Ipsec.Ike.V2.Enums;

namespace TqkLibrary.VpnClient.Ipsec.Ike.V2
{
    /// <summary>
    /// Digital-signature AUTH verification (RFC 7296 §2.15): the responder signs its
    /// <see cref="IkePskAuth.ComputeSignedOctets"/> octets with the private key of the certificate it sends in the
    /// CERT payload, and we verify that signature with the certificate's public key. Supports the RSA digital
    /// signature method (1, RSASSA-PKCS1-v1.5) and ECDSA methods (9/10/11). The signed octets are the same as the PSK
    /// path; only the final "sign vs. prf" step differs, so this reuses <see cref="IkePskAuth.ComputeSignedOctets"/>.
    /// </summary>
    public static class IkeSignatureAuth
    {
        /// <summary>
        /// Verifies the responder's digital signature over its signed octets. Returns true on a valid signature with a
        /// supported method/key. <paramref name="realMessage2"/> is the IKE_SA_INIT response bytes, <paramref name="nonceInitiator"/>
        /// our Ni, <paramref name="skPr"/> SK_pr, <paramref name="restOfIdResponder"/> the IDr body.
        /// </summary>
        public static bool VerifyResponderSignature(
            IPrf prf, IkeAuthMethod method, X509Certificate2 certificate, byte[] signature,
            byte[] realMessage2, byte[] nonceInitiator, byte[] skPr, byte[] restOfIdResponder)
        {
            byte[] signedOctets = IkePskAuth.ComputeSignedOctets(prf, realMessage2, nonceInitiator, skPr, restOfIdResponder);
            return Verify(method, certificate, signedOctets, signature);
        }

        static bool Verify(IkeAuthMethod method, X509Certificate2 certificate, byte[] signedOctets, byte[] signature)
        {
            switch (method)
            {
                case IkeAuthMethod.RsaSignature:
                    // RFC 7296 method 1: RSASSA-PKCS1-v1.5. The hash is unstated in the payload; SHA-1 is the historic
                    // default (RFC 4306), but newer gateways sign with SHA-256/384/512 — try each.
                    return VerifyRsa(certificate, signedOctets, signature);

#if NET5_0_OR_GREATER
                // ECDSA (methods 9/10/11, RFC 4754): the raw r‖s concatenation needs the DSASignatureFormat overload,
                // which exists from .NET 5 only. On netstandard2.0 these methods are reported unsupported.
                case IkeAuthMethod.EcdsaSha256:
                    return VerifyEcdsa(certificate, signedOctets, signature, HashAlgorithmName.SHA256);
                case IkeAuthMethod.EcdsaSha384:
                    return VerifyEcdsa(certificate, signedOctets, signature, HashAlgorithmName.SHA384);
                case IkeAuthMethod.EcdsaSha512:
                    return VerifyEcdsa(certificate, signedOctets, signature, HashAlgorithmName.SHA512);
#endif

                default:
                    return false;
            }
        }

        static bool VerifyRsa(X509Certificate2 certificate, byte[] signedOctets, byte[] signature)
        {
            using RSA? rsa = certificate.GetRSAPublicKey();
            if (rsa is null) return false;
            foreach (HashAlgorithmName hash in new[] { HashAlgorithmName.SHA1, HashAlgorithmName.SHA256, HashAlgorithmName.SHA384, HashAlgorithmName.SHA512 })
            {
                try
                {
                    if (rsa.VerifyData(signedOctets, signature, hash, RSASignaturePadding.Pkcs1)) return true;
                }
                catch (CryptographicException) { /* wrong key size / padding for this hash — try the next */ }
            }
            return false;
        }

#if NET5_0_OR_GREATER
        static bool VerifyEcdsa(X509Certificate2 certificate, byte[] signedOctets, byte[] signature, HashAlgorithmName hash)
        {
            using ECDsa? ecdsa = certificate.GetECDsaPublicKey();
            if (ecdsa is null) return false;
            try
            {
                // IKEv2 carries ECDSA signatures as the raw r‖s concatenation (RFC 4754), which is the IEEE-P1363 form.
                return ecdsa.VerifyData(signedOctets, signature, hash, DSASignatureFormat.IeeeP1363FixedFieldConcatenation);
            }
            catch (CryptographicException) { return false; }
        }
#endif
    }
}
