namespace TqkLibrary.Vpn.Ipsec.Ike.Enums
{
    /// <summary>IKEv2 exchange types (RFC 7296 §3.1).</summary>
    public enum IkeExchangeType : byte
    {
        /// <summary>IKE_SA_INIT: negotiate crypto, exchange D-H and nonces.</summary>
        IkeSaInit = 34,

        /// <summary>IKE_AUTH: authenticate and set up the first CHILD_SA.</summary>
        IkeAuth = 35,

        /// <summary>CREATE_CHILD_SA: create or rekey a CHILD_SA / the IKE SA.</summary>
        CreateChildSa = 36,

        /// <summary>INFORMATIONAL: notifications, deletes, keepalives.</summary>
        Informational = 37,
    }
}
