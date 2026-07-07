namespace TqkLibrary.VpnClient.Ipsec.Ike.V2.Enums
{
    /// <summary>Selected IKEv2 Notify message types (RFC 7296 §3.10.1, IANA registry).</summary>
    public enum IkeNotifyMessageType : ushort
    {
        /// <summary>Crypto proposal not accepted (error).</summary>
        NoProposalChosen = 14,

        /// <summary>Authentication failed (error).</summary>
        AuthenticationFailed = 24,

        /// <summary>This is the initiator's only/first SA (status).</summary>
        InitialContact = 16384,

        /// <summary>Hash of initiator's IP+port for NAT detection.</summary>
        NatDetectionSourceIp = 16388,

        /// <summary>Hash of responder's IP+port for NAT detection.</summary>
        NatDetectionDestinationIp = 16389,

        /// <summary>Request ESP transport mode rather than tunnel mode.</summary>
        UseTransportMode = 16391,

        /// <summary>Responder echoes the SPI it selected for rekey (status).</summary>
        RekeySa = 16393,

        /// <summary>ESP packets may be sent over UDP (status).</summary>
        EspTfcPaddingNotSupported = 16394,

        /// <summary>
        /// The sender supports mixing a Post-quantum Preshared Key (PPK) into the IKE keys (RFC 8784 §4, status,
        /// no data). The initiator sends it in IKE_SA_INIT; a responder that also supports PPK echoes it back.
        /// </summary>
        UsePpk = 16435,

        /// <summary>
        /// Names the PPK the initiator selected (RFC 8784 §4/§4.1): data = PPK_ID (octet 0 = PPK_ID Type,
        /// 1 = PPK_ID_OPAQUE; the rest is the identifier value). Sent in the IKE_AUTH request when a PPK is used.
        /// </summary>
        PpkIdentity = 16436,

        /// <summary>
        /// Carries the initiator's AUTH computed with the <em>unmixed</em> SK_pi (RFC 8784 §4): lets a responder that
        /// has no PPK for this peer still authenticate the initiator when the PPK is optional. Sent in IKE_AUTH.
        /// </summary>
        NoPpkAuth = 16437,
    }
}
