namespace TqkLibrary.Vpn.Ipsec.Ike.Enums
{
    /// <summary>IKEv2 Protocol IDs used in SA proposals, Notify, and Delete (RFC 7296 §3.3.1).</summary>
    public enum IkeProtocolId : byte
    {
        /// <summary>Reserved / not applicable.</summary>
        None = 0,

        /// <summary>The IKE SA itself.</summary>
        Ike = 1,

        /// <summary>Authentication Header.</summary>
        Ah = 2,

        /// <summary>Encapsulating Security Payload.</summary>
        Esp = 3,
    }
}
