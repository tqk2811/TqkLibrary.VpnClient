namespace TqkLibrary.Vpn.Ipsec.Ike.V1.Enums
{
    /// <summary>The classified content of an inbound IKEv1 Informational exchange (RFC 2408 §4.8, RFC 3706 DPD).</summary>
    public enum IkeV1InformationalKind
    {
        /// <summary>An Informational message that carried nothing we act on.</summary>
        Unknown = 0,

        /// <summary>A DPD R-U-THERE (the peer is probing us; we should answer with an ACK).</summary>
        DpdRequest = 1,

        /// <summary>A DPD R-U-THERE-ACK (the peer answered our probe; it is alive).</summary>
        DpdAck = 2,

        /// <summary>A Delete payload for the ESP CHILD SA (the peer is tearing the data SA down).</summary>
        DeleteEsp = 3,

        /// <summary>A Delete payload for the ISAKMP SA (the peer is tearing the whole tunnel down).</summary>
        DeleteIsakmp = 4,
    }
}
