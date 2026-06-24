using TqkLibrary.VpnClient.Ipsec.Ike.V1.Enums;
using TqkLibrary.VpnClient.Ipsec.Ike.V1.Models;
using TqkLibrary.VpnClient.Ipsec.Ike.V1.Payloads;

namespace TqkLibrary.VpnClient.Ipsec.Ike.V1
{
    /// <summary>
    /// Default IKEv1 proposals tuned for broad L2TP/IPsec interop (SoftEther/VPN Gate, Windows RRAS):
    /// Phase 1 offers AES-CBC + SHA1 + PSK over MODP groups 2/14; Phase 2 offers AES-256 + HMAC-SHA1 ESP in
    /// UDP-encapsulated transport mode, with AES-GCM-256 appended as an additional (preferred-by-GCM-servers)
    /// option. The responder picks one transform; the client builds the matching suite (see <c>ProcessQuickMode2</c>).
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
            proposal.Transforms.Add(Phase1Transform(n++, 256, IkeV1Constants.Group.Modp2048, IkeV1Constants.AuthMethod.PreSharedKey));
            proposal.Transforms.Add(Phase1Transform(n++, 256, IkeV1Constants.Group.Modp1024, IkeV1Constants.AuthMethod.PreSharedKey));
            proposal.Transforms.Add(Phase1Transform(n++, 128, IkeV1Constants.Group.Modp2048, IkeV1Constants.AuthMethod.PreSharedKey));
            proposal.Transforms.Add(Phase1Transform(n, 128, IkeV1Constants.Group.Modp1024, IkeV1Constants.AuthMethod.PreSharedKey));
            sa.Proposals.Add(proposal);
            return sa;
        }

        /// <summary>
        /// Builds the Aggressive Mode Phase 1 SA for Cisco IPsec / EzVPN: the same AES-CBC/SHA1 transforms but with the
        /// XAUTHInitPreShared authentication method, so the gateway knows an XAUTH exchange follows the PSK hash. A
        /// single MODP group is offered because Aggressive Mode message 1 already carries one KE value for that group.
        /// </summary>
        public static IsakmpSaPayload Phase1Aggressive(ushort group = IkeV1Constants.Group.Modp1024)
        {
            var sa = new IsakmpSaPayload();
            var proposal = new IsakmpProposal { Number = 1, ProtocolId = IkeV1Constants.Protocol.Isakmp };
            byte n = 1;
            proposal.Transforms.Add(Phase1Transform(n++, 256, group, IkeV1Constants.AuthMethod.XAuthInitPreShared));
            proposal.Transforms.Add(Phase1Transform(n, 128, group, IkeV1Constants.AuthMethod.XAuthInitPreShared));
            sa.Proposals.Add(proposal);
            return sa;
        }

        static IsakmpTransform Phase1Transform(byte number, ushort keyBits, ushort group, ushort authMethod)
            => new IsakmpTransform(number, IkeV1Constants.TransformKeyIke)
                .With(IsakmpAttribute.Tv(IkeV1Constants.Phase1Attribute.Encryption, IkeV1Constants.Phase1Encryption.AesCbc))
                .With(IsakmpAttribute.Tv(IkeV1Constants.Phase1Attribute.KeyLength, keyBits))
                .With(IsakmpAttribute.Tv(IkeV1Constants.Phase1Attribute.Hash, IkeV1Constants.HashAlgorithm.Sha1))
                .With(IsakmpAttribute.Tv(IkeV1Constants.Phase1Attribute.AuthMethod, authMethod))
                .With(IsakmpAttribute.Tv(IkeV1Constants.Phase1Attribute.Group, group))
                .With(IsakmpAttribute.Tv(IkeV1Constants.Phase1Attribute.LifeType, IkeV1Constants.LifeType.Seconds))
                .With(IsakmpAttribute.Tlv32(IkeV1Constants.Phase1Attribute.LifeDuration, Phase1Lifetime));

        /// <summary>
        /// Builds the Phase 2 (ESP) SA payload. AES-CBC-256 + HMAC-SHA1 transforms come first (the broad-interop
        /// default the live path relies on); AES-GCM-256 transforms are appended so a GCM-capable gateway can
        /// select them. Each cipher is offered in two encapsulation modes; <paramref name="preferTransport"/> decides
        /// the order — plain transport first for a native (proto-50) ESP carrier, UDP-encapsulated transport first
        /// for forced NAT-T. The gateway selects the first acceptable transform, so the order decides the
        /// encapsulation it installs (Transport ⇒ native SA, UDP-Encapsulated-Transport ⇒ espinudp SA).
        /// </summary>
        public static IsakmpSaPayload Phase2(byte[] spi, bool preferTransport = false)
        {
            var sa = new IsakmpSaPayload();
            var proposal = new IsakmpProposal { Number = 1, ProtocolId = IkeV1Constants.Protocol.Esp, Spi = spi };
            byte n = 1;
            ushort first = preferTransport ? IkeV1Constants.EncapsulationMode.Transport : IkeV1Constants.EncapsulationMode.UdpTransport;
            ushort second = preferTransport ? IkeV1Constants.EncapsulationMode.UdpTransport : IkeV1Constants.EncapsulationMode.Transport;
            proposal.Transforms.Add(CbcTransform(n++, first));
            proposal.Transforms.Add(CbcTransform(n++, second));
            proposal.Transforms.Add(GcmTransform(n++, first));
            proposal.Transforms.Add(GcmTransform(n, second));
            sa.Proposals.Add(proposal);
            return sa;
        }

        /// <summary>
        /// Builds the Phase 2 (ESP) SA payload for an IKEv1 remote-access tunnel (Cisco IPsec / EzVPN): AES-CBC-256 +
        /// HMAC-SHA1 then AES-GCM-256, each in tunnel mode — UDP-Encapsulated-Tunnel first for forced NAT-T (the live
        /// remote-access path), then plain Tunnel. Tunnel mode (not transport) means the gateway de-encapsulates a whole
        /// inner IP packet, which the <see cref="Esp.EspTunnelChannel"/> data plane carries straight to the IP stack.
        /// </summary>
        public static IsakmpSaPayload Phase2Tunnel(byte[] spi)
        {
            var sa = new IsakmpSaPayload();
            var proposal = new IsakmpProposal { Number = 1, ProtocolId = IkeV1Constants.Protocol.Esp, Spi = spi };
            byte n = 1;
            proposal.Transforms.Add(CbcTransform(n++, IkeV1Constants.EncapsulationMode.UdpTunnel));
            proposal.Transforms.Add(CbcTransform(n++, IkeV1Constants.EncapsulationMode.Tunnel));
            proposal.Transforms.Add(GcmTransform(n++, IkeV1Constants.EncapsulationMode.UdpTunnel));
            proposal.Transforms.Add(GcmTransform(n, IkeV1Constants.EncapsulationMode.Tunnel));
            sa.Proposals.Add(proposal);
            return sa;
        }

        // ESP_AES (CBC-256) + HMAC-SHA1-96 authentication.
        static IsakmpTransform CbcTransform(byte number, ushort encapMode)
            => new IsakmpTransform(number, IkeV1Constants.EspTransform.Aes)
                .With(IsakmpAttribute.Tv(IkeV1Constants.Phase2Attribute.KeyLength, 256))
                .With(IsakmpAttribute.Tv(IkeV1Constants.Phase2Attribute.AuthAlgorithm, IkeV1Constants.AuthAlgorithm.HmacSha1))
                .With(IsakmpAttribute.Tv(IkeV1Constants.Phase2Attribute.EncapsulationMode, encapMode))
                .With(IsakmpAttribute.Tv(IkeV1Constants.Phase2Attribute.LifeType, IkeV1Constants.LifeType.Seconds))
                .With(IsakmpAttribute.Tlv32(IkeV1Constants.Phase2Attribute.LifeDuration, Phase2Lifetime));

        // ESP_AES_GCM_16 (combined-mode AEAD): AES-256 with no separate authentication algorithm.
        static IsakmpTransform GcmTransform(byte number, ushort encapMode)
            => new IsakmpTransform(number, IkeV1Constants.EspTransform.AesGcm16)
                .With(IsakmpAttribute.Tv(IkeV1Constants.Phase2Attribute.KeyLength, 256))
                .With(IsakmpAttribute.Tv(IkeV1Constants.Phase2Attribute.EncapsulationMode, encapMode))
                .With(IsakmpAttribute.Tv(IkeV1Constants.Phase2Attribute.LifeType, IkeV1Constants.LifeType.Seconds))
                .With(IsakmpAttribute.Tlv32(IkeV1Constants.Phase2Attribute.LifeDuration, Phase2Lifetime));
    }
}
