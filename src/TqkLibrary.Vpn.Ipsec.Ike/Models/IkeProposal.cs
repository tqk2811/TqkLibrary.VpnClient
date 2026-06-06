using TqkLibrary.Vpn.Ipsec.Ike.Enums;

namespace TqkLibrary.Vpn.Ipsec.Ike.Models
{
    /// <summary>One proposal in an SA payload: a protocol + optional SPI + an ordered set of transforms (RFC 7296 §3.3.1).</summary>
    public sealed class IkeProposal
    {
        /// <summary>Proposal number (1-based; proposals in one SA share a contiguous numbering).</summary>
        public byte Number { get; set; } = 1;

        /// <summary>The protocol this proposal applies to (IKE/AH/ESP).</summary>
        public IkeProtocolId ProtocolId { get; set; }

        /// <summary>The SPI (empty for an IKE_SA_INIT IKE proposal; 4 bytes for an ESP CHILD_SA).</summary>
        public byte[] Spi { get; set; } = Array.Empty<byte>();

        /// <summary>The transforms offered/selected.</summary>
        public List<IkeTransform> Transforms { get; } = new();
    }
}
