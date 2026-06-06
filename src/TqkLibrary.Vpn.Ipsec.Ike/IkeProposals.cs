using TqkLibrary.Vpn.Ipsec.Ike.Enums;
using TqkLibrary.Vpn.Ipsec.Ike.Models;

namespace TqkLibrary.Vpn.Ipsec.Ike
{
    /// <summary>The project's fixed crypto proposals: AES-CBC-256, HMAC-SHA-256, MODP-2048 (no PFS on the CHILD_SA).</summary>
    public static class IkeProposals
    {
        /// <summary>The IKE SA proposal offered in IKE_SA_INIT (ENCR=AES-CBC-256, PRF/INTEG=SHA-256, D-H=group 14).</summary>
        public static IkeProposal DefaultIke()
        {
            var proposal = new IkeProposal { Number = 1, ProtocolId = IkeProtocolId.Ike };
            var encryption = new IkeTransform(IkeTransformType.Encryption, IkeTransformId.Encryption.AesCbc);
            encryption.Attributes.Add(IkeTransformAttribute.KeyLength(256));
            proposal.Transforms.Add(encryption);
            proposal.Transforms.Add(new IkeTransform(IkeTransformType.Prf, IkeTransformId.Prf.HmacSha2_256));
            proposal.Transforms.Add(new IkeTransform(IkeTransformType.Integrity, IkeTransformId.Integrity.HmacSha2_256_128));
            proposal.Transforms.Add(new IkeTransform(IkeTransformType.DiffieHellman, IkeTransformId.DiffieHellman.Modp2048));
            return proposal;
        }

        /// <summary>The ESP CHILD_SA proposal offered in IKE_AUTH (AES-CBC-256 + HMAC-SHA-256-128, no ESN).</summary>
        public static IkeProposal DefaultEsp(byte[] spi)
        {
            var proposal = new IkeProposal { Number = 1, ProtocolId = IkeProtocolId.Esp, Spi = spi };
            var encryption = new IkeTransform(IkeTransformType.Encryption, IkeTransformId.Encryption.AesCbc);
            encryption.Attributes.Add(IkeTransformAttribute.KeyLength(256));
            proposal.Transforms.Add(encryption);
            proposal.Transforms.Add(new IkeTransform(IkeTransformType.Integrity, IkeTransformId.Integrity.HmacSha2_256_128));
            proposal.Transforms.Add(new IkeTransform(IkeTransformType.ExtendedSequenceNumbers, IkeTransformId.Esn.None));
            return proposal;
        }
    }
}
