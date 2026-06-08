using TqkLibrary.Vpn.Ipsec.Ike.V1.Enums;
using TqkLibrary.Vpn.Ipsec.Ike.V1.Models;
using TqkLibrary.Vpn.Ipsec.Ike.V1.Payloads;

namespace TqkLibrary.Vpn.Ipsec.Ike.V1
{
    /// <summary>
    /// Default IKEv1 proposals tuned for broad L2TP/IPsec interop (SoftEther/VPN Gate, Windows RRAS):
    /// Phase 1 offers AES-CBC + SHA1 + PSK over MODP groups 2/14; Phase 2 offers AES-256 + HMAC-SHA1 ESP in
    /// UDP-encapsulated transport mode.
    /// </summary>
    public static class IkeV1Proposals
    {
        const uint Phase1Lifetime = IkeV1Lifetimes.Phase1Seconds;
        const uint Phase2Lifetime = IkeV1Lifetimes.Phase2Seconds;

        /// <summary>Builds the Phase 1 (ISAKMP) SA payload offering several common AES-CBC/SHA1/PSK transforms.</summary>
        public static IsakmpSaPayload Phase1()
        {
            var sa = new IsakmpSaPayload();
            var proposal = new IsakmpProposal { Number = 1, ProtocolId = IkeV1Constants.Protocol.Isakmp };
            byte n = 1;
            proposal.Transforms.Add(Phase1Transform(n++, 256, IkeV1Constants.Group.Modp2048));
            proposal.Transforms.Add(Phase1Transform(n++, 256, IkeV1Constants.Group.Modp1024));
            proposal.Transforms.Add(Phase1Transform(n++, 128, IkeV1Constants.Group.Modp2048));
            proposal.Transforms.Add(Phase1Transform(n, 128, IkeV1Constants.Group.Modp1024));
            sa.Proposals.Add(proposal);
            return sa;
        }

        static IsakmpTransform Phase1Transform(byte number, ushort keyBits, ushort group)
            => new IsakmpTransform(number, IkeV1Constants.TransformKeyIke)
                .With(IsakmpAttribute.Tv(IkeV1Constants.Phase1Attribute.Encryption, IkeV1Constants.Phase1Encryption.AesCbc))
                .With(IsakmpAttribute.Tv(IkeV1Constants.Phase1Attribute.KeyLength, keyBits))
                .With(IsakmpAttribute.Tv(IkeV1Constants.Phase1Attribute.Hash, IkeV1Constants.HashAlgorithm.Sha1))
                .With(IsakmpAttribute.Tv(IkeV1Constants.Phase1Attribute.AuthMethod, IkeV1Constants.AuthMethod.PreSharedKey))
                .With(IsakmpAttribute.Tv(IkeV1Constants.Phase1Attribute.Group, group))
                .With(IsakmpAttribute.Tv(IkeV1Constants.Phase1Attribute.LifeType, IkeV1Constants.LifeType.Seconds))
                .With(IsakmpAttribute.Tlv32(IkeV1Constants.Phase1Attribute.LifeDuration, Phase1Lifetime));

        /// <summary>Builds the Phase 2 (ESP) SA payload for AES-256 + HMAC-SHA1 in UDP-encapsulated transport mode.</summary>
        public static IsakmpSaPayload Phase2(byte[] spi)
        {
            var sa = new IsakmpSaPayload();
            var proposal = new IsakmpProposal { Number = 1, ProtocolId = IkeV1Constants.Protocol.Esp, Spi = spi };
            proposal.Transforms.Add(Phase2Transform(1, IkeV1Constants.EncapsulationMode.UdpTransport));
            proposal.Transforms.Add(Phase2Transform(2, IkeV1Constants.EncapsulationMode.Transport));
            sa.Proposals.Add(proposal);
            return sa;
        }

        static IsakmpTransform Phase2Transform(byte number, ushort encapMode)
            => new IsakmpTransform(number, IkeV1Constants.EspTransform.Aes)
                .With(IsakmpAttribute.Tv(IkeV1Constants.Phase2Attribute.KeyLength, 256))
                .With(IsakmpAttribute.Tv(IkeV1Constants.Phase2Attribute.AuthAlgorithm, IkeV1Constants.AuthAlgorithm.HmacSha1))
                .With(IsakmpAttribute.Tv(IkeV1Constants.Phase2Attribute.EncapsulationMode, encapMode))
                .With(IsakmpAttribute.Tv(IkeV1Constants.Phase2Attribute.LifeType, IkeV1Constants.LifeType.Seconds))
                .With(IsakmpAttribute.Tlv32(IkeV1Constants.Phase2Attribute.LifeDuration, Phase2Lifetime));
    }
}
