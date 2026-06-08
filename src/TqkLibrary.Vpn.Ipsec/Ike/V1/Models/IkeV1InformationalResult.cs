using TqkLibrary.Vpn.Ipsec.Ike.V1.Enums;

namespace TqkLibrary.Vpn.Ipsec.Ike.V1.Models
{
    /// <summary>The outcome of parsing an inbound IKEv1 Informational exchange: what it was and, for DPD, its sequence.</summary>
    public sealed class IkeV1InformationalResult
    {
        /// <summary>Creates a result of the given kind and DPD sequence (0 for non-DPD kinds).</summary>
        public IkeV1InformationalResult(IkeV1InformationalKind kind, uint sequence)
        {
            Kind = kind;
            Sequence = sequence;
        }

        /// <summary>What the Informational message carried.</summary>
        public IkeV1InformationalKind Kind { get; }

        /// <summary>The DPD sequence number (R-U-THERE / R-U-THERE-ACK); 0 for Delete/Unknown.</summary>
        public uint Sequence { get; }
    }
}
