namespace TqkLibrary.Vpn.Ipsec.Ike.Enums
{
    /// <summary>IKEv2 payload types — the "Next Payload" chain values (RFC 7296 §3.2).</summary>
    public enum IkePayloadType : byte
    {
        /// <summary>No next payload (chain terminator).</summary>
        None = 0,

        /// <summary>Security Association (proposals/transforms).</summary>
        SecurityAssociation = 33,

        /// <summary>Key Exchange (D-H public value).</summary>
        KeyExchange = 34,

        /// <summary>Identification – Initiator.</summary>
        IdInitiator = 35,

        /// <summary>Identification – Responder.</summary>
        IdResponder = 36,

        /// <summary>Certificate.</summary>
        Certificate = 37,

        /// <summary>Certificate Request.</summary>
        CertificateRequest = 38,

        /// <summary>Authentication.</summary>
        Authentication = 39,

        /// <summary>Nonce (Ni / Nr).</summary>
        Nonce = 40,

        /// <summary>Notify.</summary>
        Notify = 41,

        /// <summary>Delete.</summary>
        Delete = 42,

        /// <summary>Vendor ID.</summary>
        VendorId = 43,

        /// <summary>Traffic Selector – Initiator.</summary>
        TrafficSelectorInitiator = 44,

        /// <summary>Traffic Selector – Responder.</summary>
        TrafficSelectorResponder = 45,

        /// <summary>Encrypted and Authenticated (SK).</summary>
        Encrypted = 46,

        /// <summary>Configuration (CP) – pulls IP/DNS via CFG.</summary>
        Configuration = 47,

        /// <summary>Extensible Authentication (EAP).</summary>
        Eap = 48,
    }
}
