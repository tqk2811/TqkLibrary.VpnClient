namespace TqkLibrary.Vpn.Ipsec.Ike.Enums
{
    /// <summary>Flag bits in the IKEv2 header (RFC 7296 §3.1).</summary>
    [Flags]
    public enum IkeHeaderFlags : byte
    {
        /// <summary>No flags.</summary>
        None = 0,

        /// <summary>Initiator (I): message originates from the SA initiator.</summary>
        Initiator = 0x08,

        /// <summary>Version (V): sender can speak a higher major version.</summary>
        Version = 0x10,

        /// <summary>Response (R): message is a response to a request with the same Message ID.</summary>
        Response = 0x20,
    }
}
