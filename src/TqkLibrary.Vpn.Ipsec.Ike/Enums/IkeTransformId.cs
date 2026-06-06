namespace TqkLibrary.Vpn.Ipsec.Ike.Enums
{
    /// <summary>
    /// Transform IDs, namespaced by transform type (RFC 7296 §3.3.2, IANA "IKEv2 Parameters").
    /// IDs repeat across types, so they are grouped rather than flattened into one enum.
    /// </summary>
    public static class IkeTransformId
    {
        /// <summary>Encryption (ENCR) transform IDs.</summary>
        public static class Encryption
        {
            /// <summary>ENCR_3DES.</summary>
            public const ushort TripleDes = 3;

            /// <summary>ENCR_AES_CBC (key length carried as attribute).</summary>
            public const ushort AesCbc = 12;

            /// <summary>ENCR_AES_GCM with a 16-octet ICV.</summary>
            public const ushort AesGcm16 = 20;
        }

        /// <summary>Pseudo-random function (PRF) transform IDs.</summary>
        public static class Prf
        {
            /// <summary>PRF_HMAC_SHA1.</summary>
            public const ushort HmacSha1 = 2;

            /// <summary>PRF_HMAC_SHA2_256.</summary>
            public const ushort HmacSha2_256 = 5;
        }

        /// <summary>Integrity (INTEG) transform IDs.</summary>
        public static class Integrity
        {
            /// <summary>AUTH_HMAC_SHA1_96.</summary>
            public const ushort HmacSha1_96 = 2;

            /// <summary>AUTH_HMAC_SHA2_256_128.</summary>
            public const ushort HmacSha2_256_128 = 12;

            /// <summary>NONE (used with AEAD ciphers).</summary>
            public const ushort None = 0;
        }

        /// <summary>Diffie-Hellman group transform IDs (same numbers as IKE group numbers).</summary>
        public static class DiffieHellman
        {
            /// <summary>1024-bit MODP (group 2).</summary>
            public const ushort Modp1024 = 2;

            /// <summary>2048-bit MODP (group 14).</summary>
            public const ushort Modp2048 = 14;
        }

        /// <summary>Extended Sequence Number transform IDs.</summary>
        public static class Esn
        {
            /// <summary>No Extended Sequence Numbers (32-bit).</summary>
            public const ushort None = 0;

            /// <summary>Extended (64-bit) Sequence Numbers.</summary>
            public const ushort Extended = 1;
        }

        /// <summary>The transform attribute type for a variable key length (RFC 7296 §3.3.5).</summary>
        public const ushort KeyLengthAttribute = 14;
    }
}
