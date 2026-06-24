namespace TqkLibrary.VpnClient.Ipsec.Ike.V1.Enums
{
    /// <summary>ISAKMP payload types for IKEv1 (RFC 2408 §3.1, plus NAT-T from RFC 3947).</summary>
    public enum IsakmpPayloadType : byte
    {
        /// <summary>No next payload.</summary>
        None = 0,

        /// <summary>Security Association (carries DOI + Situation + proposals).</summary>
        SecurityAssociation = 1,

        /// <summary>Proposal.</summary>
        Proposal = 2,

        /// <summary>Transform.</summary>
        Transform = 3,

        /// <summary>Key Exchange (D-H public value).</summary>
        KeyExchange = 4,

        /// <summary>Identification.</summary>
        Identification = 5,

        /// <summary>Certificate.</summary>
        Certificate = 6,

        /// <summary>Certificate Request.</summary>
        CertificateRequest = 7,

        /// <summary>Hash.</summary>
        Hash = 8,

        /// <summary>Signature.</summary>
        Signature = 9,

        /// <summary>Nonce.</summary>
        Nonce = 10,

        /// <summary>Notification.</summary>
        Notification = 11,

        /// <summary>Delete.</summary>
        Delete = 12,

        /// <summary>Vendor ID.</summary>
        VendorId = 13,

        /// <summary>
        /// Attribute / ISAKMP Configuration payload (draft-ietf-ipsec-isakmp-mode-cfg-04 §4) — the payload that carries
        /// the configuration method (CfgType + Identifier + data attributes) for XAUTH and Mode-Config.
        /// </summary>
        Attribute = 14,

        /// <summary>NAT-Discovery hash (RFC 3947).</summary>
        NatDiscovery = 20,

        /// <summary>NAT Original Address (RFC 3947).</summary>
        NatOriginalAddress = 21,
    }
}
