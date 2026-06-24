namespace TqkLibrary.VpnClient.Ipsec.Ike.V1.Enums
{
    /// <summary>IKEv1 exchange types (RFC 2408 §3.1, RFC 2409).</summary>
    public enum IsakmpExchangeType : byte
    {
        /// <summary>Base exchange.</summary>
        Base = 1,

        /// <summary>Identity Protection — Main Mode (Phase 1).</summary>
        MainMode = 2,

        /// <summary>Authentication Only.</summary>
        AuthenticationOnly = 3,

        /// <summary>Aggressive Mode (Phase 1).</summary>
        Aggressive = 4,

        /// <summary>Informational.</summary>
        Informational = 5,

        /// <summary>
        /// Transaction (ISAKMP Configuration Method) — carries the Attribute payload for XAUTH and Mode-Config
        /// (draft-ietf-ipsec-isakmp-mode-cfg-04 §3.2). Protected like Quick Mode: HASH then the Attribute payload,
        /// each exchange under its own random non-zero Message ID with the derived Quick Mode IV.
        /// </summary>
        Transaction = 6,

        /// <summary>Quick Mode (Phase 2).</summary>
        QuickMode = 32,

        /// <summary>New Group Mode.</summary>
        NewGroup = 33,
    }
}
