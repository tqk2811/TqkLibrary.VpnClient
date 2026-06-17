namespace TqkLibrary.VpnClient.Ipsec.Ike.V2.Enums
{
    /// <summary>Certificate encodings for the CERT / CERTREQ payloads (RFC 7296 §3.6, IANA registry).</summary>
    public enum IkeCertificateEncoding : byte
    {
        /// <summary>No certificate (reserved).</summary>
        None = 0,

        /// <summary>PKCS#7 wrapped X.509 certificate.</summary>
        Pkcs7WrappedX509 = 1,

        /// <summary>PGP certificate.</summary>
        PgpCertificate = 2,

        /// <summary>DNS signed key.</summary>
        DnsSignedKey = 3,

        /// <summary>A single DER-encoded X.509 certificate used to verify a signature (the common case).</summary>
        X509CertificateSignature = 4,

        /// <summary>Kerberos token.</summary>
        KerberosToken = 6,

        /// <summary>Certificate Revocation List.</summary>
        CertificateRevocationList = 7,

        /// <summary>Raw RSA key.</summary>
        RawRsaKey = 11,

        /// <summary>Hash and URL of an X.509 certificate.</summary>
        HashAndUrlX509Certificate = 12,
    }
}
