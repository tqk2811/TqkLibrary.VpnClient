namespace TqkLibrary.Vpn.Ipsec.Ike.Enums
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
    }
}
