namespace TqkLibrary.VpnClient.Ipsec.Ike.V2.Enums
{
    /// <summary>Authentication methods in the AUTH payload (RFC 7296 §3.8).</summary>
    public enum IkeAuthMethod : byte
    {
        /// <summary>RSA digital signature.</summary>
        RsaSignature = 1,

        /// <summary>Shared Key Message Integrity Code (pre-shared key).</summary>
        SharedKey = 2,

        /// <summary>DSS digital signature.</summary>
        DssSignature = 3,

        /// <summary>ECDSA with SHA-256 on the P-256 curve (RFC 4754).</summary>
        EcdsaSha256 = 9,

        /// <summary>ECDSA with SHA-384 on the P-384 curve (RFC 4754).</summary>
        EcdsaSha384 = 10,

        /// <summary>ECDSA with SHA-512 on the P-521 curve (RFC 4754).</summary>
        EcdsaSha512 = 11,

        /// <summary>Generic "Digital Signature" with the algorithm carried in the AUTH data (RFC 7427).</summary>
        DigitalSignature = 14,
    }
}
