using System.Net;
using System.Security.Cryptography;
using TqkLibrary.Vpn.Crypto;
using TqkLibrary.Vpn.Crypto.Abstractions.Interfaces;
using TqkLibrary.Vpn.Ipsec.Ike.Enums;
using TqkLibrary.Vpn.Ipsec.Ike.Payloads;

namespace TqkLibrary.Vpn.Ipsec.Ike
{
    /// <summary>
    /// Drives the initiator half of IKE_SA_INIT: picks the SPI, D-H keypair and nonce, builds the request,
    /// and on the response computes the shared secret and the SK_* key set. The exact request/response bytes
    /// are retained because the IKE_AUTH signature is taken over them (RFC 7296 §2.15).
    /// </summary>
    public sealed class IkeSaInitiator
    {
        const int NonceSize = 32;

        readonly IDhGroup _dhGroup = ModpDhGroup.Group14();
        readonly byte[] _privateKey;

        /// <summary>Creates an initiator, optionally with a caller-supplied 8-byte initiator SPI (else random non-zero).</summary>
        public IkeSaInitiator(byte[]? initiatorSpi = null)
        {
            InitiatorSpi = initiatorSpi ?? RandomNonZeroSpi();
            _privateKey = _dhGroup.GeneratePrivateKey();
            PublicKey = _dhGroup.DerivePublicValue(_privateKey);
            Nonce = RandomBytes(NonceSize);
        }

        /// <summary>Our 8-byte initiator SPI.</summary>
        public byte[] InitiatorSpi { get; }

        /// <summary>Our D-H public value (KEi).</summary>
        public byte[] PublicKey { get; }

        /// <summary>Our nonce (Ni).</summary>
        public byte[] Nonce { get; }

        /// <summary>The responder's 8-byte SPI (valid after <see cref="ProcessInitResponse"/>).</summary>
        public byte[] ResponderSpi { get; private set; } = new byte[8];

        /// <summary>The responder's nonce (Nr), available after processing the response.</summary>
        public byte[] PeerNonce { get; private set; } = Array.Empty<byte>();

        /// <summary>The D-H shared secret g^ir, available after processing the response.</summary>
        public byte[] SharedSecret { get; private set; } = Array.Empty<byte>();

        /// <summary>The derived SK_* key material, available after processing the response.</summary>
        public IkeKeyMaterial? Keys { get; private set; }

        /// <summary>The exact bytes of the IKE_SA_INIT request we sent (signed by IKE_AUTH).</summary>
        public byte[] InitRequestBytes { get; private set; } = Array.Empty<byte>();

        /// <summary>The exact bytes of the IKE_SA_INIT response we received (signed by IKE_AUTH).</summary>
        public byte[] InitResponseBytes { get; private set; } = Array.Empty<byte>();

        /// <summary>
        /// Builds the IKE_SA_INIT request (SAi1, KEi, Ni, NAT-detection notifies) and caches its encoded bytes.
        /// </summary>
        public IkeMessage BuildInitRequest(IPAddress localIp, ushort localPort, IPAddress remoteIp, ushort remotePort)
        {
            var message = new IkeMessage
            {
                InitiatorSpi = InitiatorSpi,
                ResponderSpi = new byte[8],
                ExchangeType = IkeExchangeType.IkeSaInit,
                Flags = IkeHeaderFlags.Initiator,
                MessageId = 0,
            };

            var sa = new SecurityAssociationPayload();
            sa.Proposals.Add(IkeProposals.DefaultIke());
            message.Payloads.Add(sa);
            message.Payloads.Add(new KeyExchangePayload
            {
                DiffieHellmanGroup = IkeTransformId.DiffieHellman.Modp2048,
                KeyData = PublicKey,
            });
            message.Payloads.Add(new NoncePayload { Nonce = Nonce });

            byte[] zeroResponderSpi = new byte[8];
            message.Payloads.Add(NotifyPayload.Create(
                IkeNotifyMessageType.NatDetectionSourceIp,
                NatDetection.ComputeHash(InitiatorSpi, zeroResponderSpi, localIp, localPort)));
            message.Payloads.Add(NotifyPayload.Create(
                IkeNotifyMessageType.NatDetectionDestinationIp,
                NatDetection.ComputeHash(InitiatorSpi, zeroResponderSpi, remoteIp, remotePort)));

            InitRequestBytes = message.Encode();
            return message;
        }

        /// <summary>
        /// Processes the IKE_SA_INIT response: records the responder SPI/nonce/raw bytes, computes the shared
        /// secret from KEr, and derives the SK_* key set. Throws if the required payloads are missing.
        /// </summary>
        public IkeKeyMaterial ProcessInitResponse(IkeMessage response)
        {
            InitResponseBytes = response.Encode();
            ResponderSpi = response.ResponderSpi;

            KeyExchangePayload ke = response.Find<KeyExchangePayload>()
                ?? throw new InvalidOperationException("IKE_SA_INIT response has no Key Exchange payload.");
            NoncePayload nonce = response.Find<NoncePayload>()
                ?? throw new InvalidOperationException("IKE_SA_INIT response has no Nonce payload.");

            PeerNonce = nonce.Nonce;
            SharedSecret = _dhGroup.DeriveSharedSecret(_privateKey, ke.KeyData);
            Keys = IkeKeyMaterial.DeriveDefault(Nonce, PeerNonce, SharedSecret, InitiatorSpi, ResponderSpi);
            return Keys;
        }

        static byte[] RandomBytes(int length)
        {
            byte[] buffer = new byte[length];
            using var rng = RandomNumberGenerator.Create();
            rng.GetBytes(buffer);
            return buffer;
        }

        static byte[] RandomNonZeroSpi()
        {
            byte[] spi = RandomBytes(8);
            bool allZero = true;
            foreach (byte b in spi) if (b != 0) { allZero = false; break; }
            if (allZero) spi[0] = 1;
            return spi;
        }
    }
}
