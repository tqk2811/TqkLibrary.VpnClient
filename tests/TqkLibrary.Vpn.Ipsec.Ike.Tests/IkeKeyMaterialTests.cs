using System.Security.Cryptography;
using TqkLibrary.Vpn.Crypto;
using TqkLibrary.Vpn.Ipsec.Ike;
using TqkLibrary.Vpn.Ipsec.Ike.Enums;
using TqkLibrary.Vpn.Ipsec.Ike.Payloads;
using Xunit;

namespace TqkLibrary.Vpn.Ipsec.Ike.Tests
{
    public class IkeKeyMaterialTests
    {
        [Fact]
        public void PrfPlus_MatchesManualIteration()
        {
            byte[] key = Enumerable.Range(0, 32).Select(i => (byte)i).ToArray();
            byte[] seed = Enumerable.Range(0, 20).Select(i => (byte)(0x40 + i)).ToArray();

            byte[] output = PrfPlus.Expand(HmacPrf.Sha256(), key, seed, 80);

            byte[] t1 = Hmac(key, Concat(seed, new byte[] { 1 }));
            byte[] t2 = Hmac(key, Concat(t1, seed, new byte[] { 2 }));
            byte[] t3 = Hmac(key, Concat(t2, seed, new byte[] { 3 }));

            Assert.Equal(t1, output[..32]);
            Assert.Equal(t2, output[32..64]);
            Assert.Equal(t3[..16], output[64..80]);
        }

        [Fact]
        public void Derive_IsDeterministic_AndNonceSensitive()
        {
            byte[] ni = Bytes(0x11, 32), nr = Bytes(0x22, 32), secret = Bytes(0x33, 256);
            byte[] spiI = Bytes(0xA0, 8), spiR = Bytes(0xB0, 8);

            IkeKeyMaterial a = IkeKeyMaterial.DeriveDefault(ni, nr, secret, spiI, spiR);
            IkeKeyMaterial b = IkeKeyMaterial.DeriveDefault(ni, nr, secret, spiI, spiR);
            Assert.Equal(a.SkeySeed, b.SkeySeed);
            Assert.Equal(a.SkEi, b.SkEi);

            byte[] niDifferent = Bytes(0x99, 32);
            IkeKeyMaterial c = IkeKeyMaterial.DeriveDefault(niDifferent, nr, secret, spiI, spiR);
            Assert.NotEqual(a.SkEi, c.SkEi);
        }

        [Fact]
        public void Derive_ProducesCorrectKeyLengths()
        {
            IkeKeyMaterial keys = IkeKeyMaterial.DeriveDefault(Bytes(1, 32), Bytes(2, 32), Bytes(3, 256), Bytes(4, 8), Bytes(5, 8));
            Assert.Equal(32, keys.SkD.Length);
            Assert.Equal(32, keys.SkAi.Length);
            Assert.Equal(32, keys.SkAr.Length);
            Assert.Equal(32, keys.SkEi.Length);
            Assert.Equal(32, keys.SkEr.Length);
            Assert.Equal(32, keys.SkPi.Length);
            Assert.Equal(32, keys.SkPr.Length);
        }

        [Fact]
        public void IkeSaInit_TwoParties_DeriveIdenticalKeys()
        {
            // Initiator builds the request.
            var initiator = new IkeSaInitiator();
            _ = initiator.BuildInitRequest(System.Net.IPAddress.Loopback, 1000, System.Net.IPAddress.Loopback, 500);

            // Responder picks its own D-H keypair, SPI and nonce, and replies.
            var dh = ModpDhGroup.Group14();
            byte[] responderPrivate = dh.GeneratePrivateKey();
            byte[] responderPublic = dh.DerivePublicValue(responderPrivate);
            byte[] responderSpi = Bytes(0x5A, 8);
            byte[] responderNonce = Bytes(0x6B, 32);

            var response = new IkeMessage
            {
                InitiatorSpi = initiator.InitiatorSpi,
                ResponderSpi = responderSpi,
                ExchangeType = IkeExchangeType.IkeSaInit,
                Flags = IkeHeaderFlags.Response,
            };
            var sa = new SecurityAssociationPayload();
            sa.Proposals.Add(IkeProposals.DefaultIke());
            response.Payloads.Add(sa);
            response.Payloads.Add(new KeyExchangePayload
            {
                DiffieHellmanGroup = IkeTransformId.DiffieHellman.Modp2048,
                KeyData = responderPublic,
            });
            response.Payloads.Add(new NoncePayload { Nonce = responderNonce });

            // Initiator processes the (re-decoded) response and derives keys.
            IkeMessage onWire = IkeMessage.Decode(response.Encode());
            IkeKeyMaterial initiatorKeys = initiator.ProcessInitResponse(onWire);

            // Responder derives keys from its own view; the two must match.
            byte[] sharedOnResponder = dh.DeriveSharedSecret(responderPrivate, initiator.PublicKey);
            IkeKeyMaterial responderKeys = IkeKeyMaterial.DeriveDefault(
                initiator.Nonce, responderNonce, sharedOnResponder, initiator.InitiatorSpi, responderSpi);

            Assert.Equal(initiator.SharedSecret, sharedOnResponder);
            Assert.Equal(initiatorKeys.SkeySeed, responderKeys.SkeySeed);
            Assert.Equal(initiatorKeys.SkEi, responderKeys.SkEi);
            Assert.Equal(initiatorKeys.SkAr, responderKeys.SkAr);
            Assert.Equal(initiatorKeys.SkPi, responderKeys.SkPi);
            Assert.Equal(initiatorKeys.SkD, responderKeys.SkD);
        }

        static byte[] Hmac(byte[] key, byte[] data)
        {
            using var h = new HMACSHA256(key);
            return h.ComputeHash(data);
        }

        static byte[] Bytes(byte seed, int length)
        {
            byte[] b = new byte[length];
            for (int i = 0; i < length; i++) b[i] = (byte)(seed + i);
            return b;
        }

        static byte[] Concat(params byte[][] parts)
        {
            var list = new List<byte>();
            foreach (byte[] p in parts) list.AddRange(p);
            return list.ToArray();
        }
    }
}
