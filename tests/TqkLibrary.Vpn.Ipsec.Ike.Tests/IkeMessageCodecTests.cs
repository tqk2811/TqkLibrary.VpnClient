using System.Net;
using TqkLibrary.Vpn.Ipsec.Ike;
using TqkLibrary.Vpn.Ipsec.Ike.Enums;
using TqkLibrary.Vpn.Ipsec.Ike.Models;
using TqkLibrary.Vpn.Ipsec.Ike.Payloads;
using Xunit;

namespace TqkLibrary.Vpn.Ipsec.Ike.Tests
{
    public class IkeMessageCodecTests
    {
        [Fact]
        public void IkeSaInit_Request_RoundTrips()
        {
            var initiator = new IkeSaInitiator();
            IkeMessage request = initiator.BuildInitRequest(IPAddress.Loopback, 12345, IPAddress.Parse("203.0.113.5"), 500);

            byte[] wire = request.Encode();
            IkeMessage decoded = IkeMessage.Decode(wire);

            Assert.Equal(IkeExchangeType.IkeSaInit, decoded.ExchangeType);
            Assert.Equal(IkeHeaderFlags.Initiator, decoded.Flags);
            Assert.Equal(0u, decoded.MessageId);
            Assert.Equal(initiator.InitiatorSpi, decoded.InitiatorSpi);
            Assert.True(IsAllZero(decoded.ResponderSpi));

            Assert.NotNull(decoded.Find<SecurityAssociationPayload>());
            Assert.NotNull(decoded.Find<NoncePayload>());

            KeyExchangePayload ke = decoded.Find<KeyExchangePayload>()!;
            Assert.Equal(IkeTransformId.DiffieHellman.Modp2048, ke.DiffieHellmanGroup);
            Assert.Equal(initiator.PublicKey, ke.KeyData);
            Assert.Equal(256, ke.KeyData.Length); // MODP-2048 public value

            NoncePayload nonce = decoded.Find<NoncePayload>()!;
            Assert.Equal(initiator.Nonce, nonce.Nonce);

            List<NotifyPayload> notifies = decoded.Notifies().ToList();
            Assert.Equal(2, notifies.Count);
            Assert.Equal(IkeNotifyMessageType.NatDetectionSourceIp, notifies[0].KnownType);
            Assert.Equal(IkeNotifyMessageType.NatDetectionDestinationIp, notifies[1].KnownType);
            Assert.Equal(20, notifies[0].Data.Length); // SHA-1 hash
        }

        [Fact]
        public void SaProposal_Transforms_RoundTrip()
        {
            var sa = new SecurityAssociationPayload();
            sa.Proposals.Add(IkeProposals.DefaultIke());
            var message = new IkeMessage { ExchangeType = IkeExchangeType.IkeSaInit };
            message.Payloads.Add(sa);

            IkeMessage decoded = IkeMessage.Decode(message.Encode());
            IkeProposal proposal = decoded.Find<SecurityAssociationPayload>()!.Proposals.Single();

            Assert.Equal(IkeProtocolId.Ike, proposal.ProtocolId);
            Assert.Equal(4, proposal.Transforms.Count);

            IkeTransform encryption = proposal.Transforms[0];
            Assert.Equal(IkeTransformType.Encryption, encryption.Type);
            Assert.Equal(IkeTransformId.Encryption.AesCbc, encryption.Id);
            Assert.Equal(256, encryption.Attributes.Single().Value);

            Assert.Equal(IkeTransformId.Prf.HmacSha2_256, proposal.Transforms[1].Id);
            Assert.Equal(IkeTransformId.Integrity.HmacSha2_256_128, proposal.Transforms[2].Id);
            Assert.Equal(IkeTransformType.DiffieHellman, proposal.Transforms[3].Type);
            Assert.Equal(IkeTransformId.DiffieHellman.Modp2048, proposal.Transforms[3].Id);
        }

        [Fact]
        public void EspProposal_WithSpi_RoundTrips()
        {
            byte[] spi = { 0xDE, 0xAD, 0xBE, 0xEF };
            var sa = new SecurityAssociationPayload();
            sa.Proposals.Add(IkeProposals.DefaultEsp(spi));
            var message = new IkeMessage { ExchangeType = IkeExchangeType.IkeAuth };
            message.Payloads.Add(sa);

            IkeProposal proposal = IkeMessage.Decode(message.Encode()).Find<SecurityAssociationPayload>()!.Proposals.Single();
            Assert.Equal(IkeProtocolId.Esp, proposal.ProtocolId);
            Assert.Equal(spi, proposal.Spi);
            Assert.Equal(3, proposal.Transforms.Count);
        }

        [Fact]
        public void Decode_RejectsTruncatedHeader()
        {
            Assert.Throws<ArgumentException>(() => IkeMessage.Decode(new byte[10]));
        }

        [Fact]
        public void Decode_RejectsLengthBeyondBuffer()
        {
            var message = new IkeMessage { ExchangeType = IkeExchangeType.Informational };
            byte[] wire = message.Encode();
            wire[27] = 0xFF; // declared length now exceeds the buffer
            Assert.Throws<ArgumentException>(() => IkeMessage.Decode(wire));
        }

        static bool IsAllZero(byte[] data)
        {
            foreach (byte b in data) if (b != 0) return false;
            return true;
        }
    }
}
