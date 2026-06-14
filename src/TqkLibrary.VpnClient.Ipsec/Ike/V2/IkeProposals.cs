using System.Collections.Generic;
using TqkLibrary.VpnClient.Ipsec.Ike.V2.Enums;
using TqkLibrary.VpnClient.Ipsec.Ike.V2.Models;

namespace TqkLibrary.VpnClient.Ipsec.Ike.V2
{
    /// <summary>
    /// The project's crypto proposals: IKE SA = AES-CBC-256 + HMAC-SHA-256 + MODP-2048; the ESP CHILD_SA offers
    /// AES-CBC-256 + HMAC-SHA-256-128 (proposal #1) and AES-GCM-16-256 (proposal #2). No PFS on the CHILD_SA.
    /// </summary>
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

        /// <summary>
        /// The IKE SA proposal offered in a CREATE_CHILD_SA that rekeys the IKE SA — the same suite as
        /// <see cref="DefaultIke"/> but carrying the new initiator IKE SPI in the proposal (RFC 7296 §1.3.2/§3.3.1).
        /// </summary>
        public static IkeProposal RekeyIke(byte[] spi)
        {
            IkeProposal proposal = DefaultIke();
            proposal.Spi = spi;
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

        /// <summary>The AES-GCM-16-256 ESP CHILD_SA proposal (combined-mode AEAD: no INTEG transform, no ESN).</summary>
        public static IkeProposal GcmEsp(byte[] spi)
        {
            var proposal = new IkeProposal { Number = 1, ProtocolId = IkeProtocolId.Esp, Spi = spi };
            var encryption = new IkeTransform(IkeTransformType.Encryption, IkeTransformId.Encryption.AesGcm16);
            encryption.Attributes.Add(IkeTransformAttribute.KeyLength(256));
            proposal.Transforms.Add(encryption);
            proposal.Transforms.Add(new IkeTransform(IkeTransformType.ExtendedSequenceNumbers, IkeTransformId.Esn.None));
            return proposal;
        }

        /// <summary>
        /// The ESP CHILD_SA proposals offered in IKE_AUTH, in preference order: AES-CBC-256 (#1, broad interop)
        /// then AES-GCM-16-256 (#2). The responder selects one; the client builds the matching suite.
        /// </summary>
        public static IReadOnlyList<IkeProposal> EspProposals(byte[] spi)
        {
            IkeProposal gcm = GcmEsp(spi);
            gcm.Number = 2;
            return new[] { DefaultEsp(spi), gcm };
        }
    }
}
