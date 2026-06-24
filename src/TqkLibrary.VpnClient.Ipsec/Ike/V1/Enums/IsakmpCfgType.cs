namespace TqkLibrary.VpnClient.Ipsec.Ike.V1.Enums
{
    /// <summary>
    /// The configuration-method message type carried in the first byte of an Attribute payload
    /// (draft-ietf-ipsec-isakmp-mode-cfg-04 §4.2). XAUTH and Mode-Config both flow as a REQUEST/REPLY pair (the
    /// gateway pulls credentials or the client pulls its virtual IP) and XAUTH ends with a SET/ACK status round.
    /// </summary>
    public enum IsakmpCfgType : byte
    {
        /// <summary>The peer asks for the listed attributes (their values are empty in a request).</summary>
        Request = 1,

        /// <summary>The peer answers a request, filling in the attribute values.</summary>
        Reply = 2,

        /// <summary>The peer pushes attribute values unsolicited (XAUTH status, server-initiated Mode-Config).</summary>
        Set = 3,

        /// <summary>The peer acknowledges a SET.</summary>
        Ack = 4,
    }
}
