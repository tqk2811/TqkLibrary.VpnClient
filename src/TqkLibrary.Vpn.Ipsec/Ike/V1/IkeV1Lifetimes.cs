namespace TqkLibrary.Vpn.Ipsec.Ike.V1
{
    /// <summary>The SA lifetimes (seconds) IKEv1 proposes, exposed so the driver can rekey before they expire.</summary>
    public static class IkeV1Lifetimes
    {
        /// <summary>Phase 1 (ISAKMP SA) lifetime — 8 hours.</summary>
        public const uint Phase1Seconds = 28800;

        /// <summary>Phase 2 (ESP CHILD SA) lifetime — 1 hour.</summary>
        public const uint Phase2Seconds = 3600;
    }
}
