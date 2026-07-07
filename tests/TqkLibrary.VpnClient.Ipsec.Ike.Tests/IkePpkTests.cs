using System.Net;
using System.Security.Cryptography;
using TqkLibrary.VpnClient.Abstractions.Drivers;
using TqkLibrary.VpnClient.Crypto;
using TqkLibrary.VpnClient.Ipsec.Ike.V2;
using TqkLibrary.VpnClient.Ipsec.Ike.V2.Enums;
using TqkLibrary.VpnClient.Ipsec.Ike.V2.Models;
using TqkLibrary.VpnClient.Ipsec.Ike.V2.Payloads;
using Xunit;

namespace TqkLibrary.VpnClient.Ipsec.Ike.Tests
{
    /// <summary>
    /// RFC 8784 (mixing a Post-quantum Preshared Key into IKEv2) on the initiator: the three PPK notifies round-trip,
    /// <see cref="IkeKeyMaterial.WithPpk(byte[])"/> mixes exactly SK_d/SK_pi/SK_pr, the USE_PPK negotiation makes the
    /// right decision (use PPK / fall back with NO_PPK_AUTH / abort), and a PPK-mixed handshake authenticates end to end.
    /// </summary>
    public class IkePpkTests
    {
        static readonly byte[] Psk = System.Text.Encoding.ASCII.GetBytes("vpn");
        static readonly byte[] PpkSecret = Bytes(0x70, 32);
        static readonly byte[] PpkIdValue = { 0xAB, 0xCD, 0xEF };

        // ---- (a) notify round-trips ----

        [Fact]
        public void UsePpk_Notify_RoundTripsWithoutData()
        {
            NotifyPayload decoded = RoundTripNotify(
                NotifyPayload.Create(IkeNotifyMessageType.UsePpk, Array.Empty<byte>()));

            Assert.Equal(IkeNotifyMessageType.UsePpk, decoded.KnownType);
            Assert.Empty(decoded.Data);
        }

        [Fact]
        public void PpkIdentity_Notify_RoundTripsWithPpkIdTypeOctet()
        {
            var ppk = new PpkConfiguration { PpkId = PpkIdValue, Ppk = PpkSecret };
            NotifyPayload decoded = RoundTripNotify(
                NotifyPayload.Create(IkeNotifyMessageType.PpkIdentity, ppk.ToWirePpkId()));

            Assert.Equal(IkeNotifyMessageType.PpkIdentity, decoded.KnownType);
            Assert.Equal((byte)1, decoded.Data[0]);                    // PPK_ID_OPAQUE type octet (RFC 8784 §4.1)
            Assert.Equal(PpkIdValue, decoded.Data.AsSpan(1).ToArray()); // identifier value follows
        }

        [Fact]
        public void NoPpkAuth_Notify_RoundTripsWithAuthData()
        {
            byte[] authData = Bytes(0x33, 32);
            NotifyPayload decoded = RoundTripNotify(
                NotifyPayload.Create(IkeNotifyMessageType.NoPpkAuth, authData));

            Assert.Equal(IkeNotifyMessageType.NoPpkAuth, decoded.KnownType);
            Assert.Equal(authData, decoded.Data);
        }

        [Fact]
        public void PpkConfiguration_ToWirePpkId_PrependsTypeOctet()
        {
            var ppk = new PpkConfiguration { PpkId = PpkIdValue, Ppk = PpkSecret };
            byte[] wire = ppk.ToWirePpkId();

            Assert.Equal(PpkIdValue.Length + 1, wire.Length);
            Assert.Equal((byte)1, wire[0]);
            Assert.Equal(PpkIdValue, wire.AsSpan(1).ToArray());
        }

        // ---- (b) key mixing ----

        [Fact]
        public void WithPpk_MixesDerivedKeys_AndPreservesTheRest()
        {
            IkeKeyMaterial keys = IkeKeyMaterial.DeriveDefault(
                Bytes(0x11, 32), Bytes(0x22, 32), Bytes(0x33, 256), Bytes(0x44, 8), Bytes(0x55, 8));

            IkeKeyMaterial mixed = keys.WithPpk(PpkSecret);

            // Only SK_d / SK_pi / SK_pr change, each to prf(PPK, original) — computed independently here.
            Assert.Equal(Hmac(PpkSecret, keys.SkD), mixed.SkD);
            Assert.Equal(Hmac(PpkSecret, keys.SkPi), mixed.SkPi);
            Assert.Equal(Hmac(PpkSecret, keys.SkPr), mixed.SkPr);

            // Everything else is untouched (so a message already encrypted with SK_ei/SK_er stays readable).
            Assert.Equal(keys.SkeySeed, mixed.SkeySeed);
            Assert.Equal(keys.SkAi, mixed.SkAi);
            Assert.Equal(keys.SkAr, mixed.SkAr);
            Assert.Equal(keys.SkEi, mixed.SkEi);
            Assert.Equal(keys.SkEr, mixed.SkEr);

            // And it did not mutate the original.
            Assert.NotEqual(keys.SkD, mixed.SkD);
        }

        [Fact]
        public void WithPpk_IsDeterministic()
        {
            IkeKeyMaterial keys = IkeKeyMaterial.DeriveDefault(
                Bytes(1, 32), Bytes(2, 32), Bytes(3, 256), Bytes(4, 8), Bytes(5, 8));

            IkeKeyMaterial a = keys.WithPpk(PpkSecret);
            IkeKeyMaterial b = keys.WithPpk(PpkSecret);

            Assert.Equal(a.SkD, b.SkD);
            Assert.Equal(a.SkPi, b.SkPi);
            Assert.Equal(a.SkPr, b.SkPr);
        }

        // ---- (c) USE_PPK negotiation decision ----

        [Fact]
        public void EchoedUsePpk_UsesPpk_AndSendsPpkIdentity()
        {
            IkeClient client = NewClient(mandatory: true);
            var responder = new PpkResponder(Psk, supportsPpk: true, PpkIdValue, PpkSecret);
            client.ProcessInitResponse(IkeMessage.Decode(
                responder.HandleInit(client.BuildInitRequest(IPAddress.Loopback, 4500, IPAddress.Loopback, 4500).Encode())));

            Assert.True(client.PpkInUse);

            IkeMessage auth = responder.Decrypt(client.BuildAuthRequest());
            NotifyPayload ppkId = Assert.Single(auth.Notifies(), n => n.KnownType == IkeNotifyMessageType.PpkIdentity);
            Assert.Equal(new PpkConfiguration { PpkId = PpkIdValue, Ppk = PpkSecret }.ToWirePpkId(), ppkId.Data);
            Assert.DoesNotContain(auth.Notifies(), n => n.KnownType == IkeNotifyMessageType.NoPpkAuth);
        }

        [Fact]
        public void OptionalPpk_Echoed_UsesPpk()
        {
            IkeClient client = NewClient(mandatory: false);
            var responder = new PpkResponder(Psk, supportsPpk: true, PpkIdValue, PpkSecret);
            client.ProcessInitResponse(IkeMessage.Decode(
                responder.HandleInit(client.BuildInitRequest(IPAddress.Loopback, 4500, IPAddress.Loopback, 4500).Encode())));

            Assert.True(client.PpkInUse);
            IkeMessage auth = responder.Decrypt(client.BuildAuthRequest());
            Assert.Contains(auth.Notifies(), n => n.KnownType == IkeNotifyMessageType.PpkIdentity);
        }

        [Fact]
        public void OptionalPpk_NotEchoed_FallsBackWithNoPpkAuth()
        {
            IkeClient client = NewClient(mandatory: false);
            var responder = new PpkResponder(Psk, supportsPpk: false);
            client.ProcessInitResponse(IkeMessage.Decode(
                responder.HandleInit(client.BuildInitRequest(IPAddress.Loopback, 4500, IPAddress.Loopback, 4500).Encode())));

            Assert.False(client.PpkInUse);

            IkeMessage auth = responder.Decrypt(client.BuildAuthRequest());
            NotifyPayload noPpk = Assert.Single(auth.Notifies(), n => n.KnownType == IkeNotifyMessageType.NoPpkAuth);
            Assert.NotEmpty(noPpk.Data);
            Assert.DoesNotContain(auth.Notifies(), n => n.KnownType == IkeNotifyMessageType.PpkIdentity);
        }

        [Fact]
        public void MandatoryPpk_NotEchoed_Aborts()
        {
            IkeClient client = NewClient(mandatory: true);
            var responder = new PpkResponder(Psk, supportsPpk: false);
            byte[] initResponse = responder.HandleInit(
                client.BuildInitRequest(IPAddress.Loopback, 4500, IPAddress.Loopback, 4500).Encode());

            Assert.Throws<VpnServerRejectedException>(() => client.ProcessInitResponse(IkeMessage.Decode(initResponse)));
        }

        // ---- (d) full round-trips ----

        [Fact]
        public void FullHandshake_WithPpk_BothMix_AuthVerifies()
        {
            IkeClient client = NewClient(mandatory: true);
            var responder = new PpkResponder(Psk, supportsPpk: true, PpkIdValue, PpkSecret);

            client.ProcessInitResponse(IkeMessage.Decode(
                responder.HandleInit(client.BuildInitRequest(IPAddress.Loopback, 4500, IPAddress.Loopback, 4500).Encode())));
            Assert.True(client.PpkInUse);

            // Both sides mixed the PPK into SK_pi/SK_pr, so the AUTH exchange verifies in both directions.
            bool authenticated = client.ProcessAuthResponse(responder.HandleAuth(client.BuildAuthRequest()));
            Assert.True(authenticated);
            Assert.NotNull(client.ChildKeys);
        }

        [Fact]
        public void FullHandshake_OptionalPpk_ResponderWithoutPpk_FallbackAuthVerifies()
        {
            IkeClient client = NewClient(mandatory: false);
            var responder = new PpkResponder(Psk, supportsPpk: false);

            client.ProcessInitResponse(IkeMessage.Decode(
                responder.HandleInit(client.BuildInitRequest(IPAddress.Loopback, 4500, IPAddress.Loopback, 4500).Encode())));
            Assert.False(client.PpkInUse);

            // The initiator authenticated with the unmixed SK_pi (also carried in NO_PPK_AUTH); the PPK-less responder verifies it.
            bool authenticated = client.ProcessAuthResponse(responder.HandleAuth(client.BuildAuthRequest()));
            Assert.True(authenticated);
            Assert.NotNull(client.ChildKeys);
        }

        // ---- helpers ----

        static IkeClient NewClient(bool mandatory)
        {
            var id = new IdentificationPayload { IsInitiator = true, IdType = IkeIdType.Ipv4Address, Data = new byte[] { 0, 0, 0, 0 } };
            var ppk = new PpkConfiguration { PpkId = PpkIdValue, Ppk = PpkSecret, Mandatory = mandatory };
            return new IkeClient(Psk, id, ppk: ppk);
        }

        static NotifyPayload RoundTripNotify(NotifyPayload notify)
        {
            var message = new IkeMessage
            {
                InitiatorSpi = new byte[8],
                ResponderSpi = new byte[8],
                ExchangeType = IkeExchangeType.IkeSaInit,
                Flags = IkeHeaderFlags.Initiator,
                MessageId = 0,
            };
            message.Payloads.Add(notify);
            return Assert.Single(IkeMessage.Decode(message.Encode()).Notifies());
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

        /// <summary>
        /// A minimal in-process IKEv2 responder that speaks RFC 8784: it echoes USE_PPK when it supports PPK, and at
        /// IKE_AUTH mixes the PPK it recognises (by PPK_ID) into SK_pi/SK_pr before verifying/producing the AUTH.
        /// </summary>
        sealed class PpkResponder
        {
            readonly HmacPrf _prf = HmacPrf.Sha256();
            readonly ModpDhGroup _dh = ModpDhGroup.Group14();
            readonly byte[] _psk;
            readonly bool _supportsPpk;
            readonly byte[]? _ppkIdRaw;   // the identifier value (no type octet) this responder recognises
            readonly byte[]? _ppk;        // the PPK it maps that identifier to
            readonly byte[] _privateKey;
            readonly byte[] _publicKey;
            readonly byte[] _spi = new byte[8];
            readonly byte[] _nonce;

            byte[] _initRequestWire = Array.Empty<byte>();
            byte[] _initResponseWire = Array.Empty<byte>();
            byte[] _initiatorNonce = Array.Empty<byte>();
            byte[] _initiatorSpi = new byte[8];
            IkeKeyMaterial? _keys;
            IkeCipher? _cipher;

            public PpkResponder(byte[] psk, bool supportsPpk, byte[]? ppkIdRaw = null, byte[]? ppk = null)
            {
                _psk = psk;
                _supportsPpk = supportsPpk;
                _ppkIdRaw = ppkIdRaw;
                _ppk = ppk;
                _privateKey = _dh.GeneratePrivateKey();
                _publicKey = _dh.DerivePublicValue(_privateKey);
                for (int i = 0; i < 8; i++) _spi[i] = (byte)(0x90 + i);
                _nonce = new byte[32];
                for (int i = 0; i < 32; i++) _nonce[i] = (byte)(0xC0 + i);
                ChildInboundSpi = new byte[] { 0x77, 0x66, 0x55, 0x44 };
            }

            public byte[] ChildInboundSpi { get; }

            public IkeMessage Decrypt(byte[] wire) => _cipher!.DecryptMessage(wire)!;

            public byte[] HandleInit(byte[] requestWire)
            {
                _initRequestWire = requestWire;
                IkeMessage request = IkeMessage.Decode(requestWire);
                _initiatorSpi = request.InitiatorSpi;
                _initiatorNonce = request.Find<NoncePayload>()!.Nonce;
                byte[] initiatorPublic = request.Find<KeyExchangePayload>()!.KeyData;
                bool clientOfferedPpk = request.Notifies().Any(n => n.KnownType == IkeNotifyMessageType.UsePpk);

                var response = new IkeMessage
                {
                    InitiatorSpi = _initiatorSpi,
                    ResponderSpi = _spi,
                    ExchangeType = IkeExchangeType.IkeSaInit,
                    Flags = IkeHeaderFlags.Response,
                };
                var sa = new SecurityAssociationPayload();
                sa.Proposals.Add(IkeProposals.DefaultIke());
                response.Payloads.Add(sa);
                response.Payloads.Add(new KeyExchangePayload
                {
                    DiffieHellmanGroup = IkeTransformId.DiffieHellman.Modp2048,
                    KeyData = _publicKey,
                });
                response.Payloads.Add(new NoncePayload { Nonce = _nonce });
                if (_supportsPpk && clientOfferedPpk)
                    response.Payloads.Add(NotifyPayload.Create(IkeNotifyMessageType.UsePpk, Array.Empty<byte>()));

                _initResponseWire = response.Encode();
                byte[] shared = _dh.DeriveSharedSecret(_privateKey, initiatorPublic);
                _keys = IkeKeyMaterial.DeriveDefault(_initiatorNonce, _nonce, shared, _initiatorSpi, _spi);
                _cipher = IkeCipher.ForResponder(_keys);
                return _initResponseWire;
            }

            public byte[] HandleAuth(byte[] requestWire)
            {
                IkeMessage request = _cipher!.DecryptMessage(requestWire)!;
                IdentificationPayload idI = request.Payloads.OfType<IdentificationPayload>().Single(p => p.IsInitiator);
                AuthenticationPayload auth = request.Find<AuthenticationPayload>()!;

                // RFC 8784 §4: if the initiator named a PPK we recognise, mix it; otherwise authenticate normally.
                IkeKeyMaterial authKeys = _keys!;
                NotifyPayload? ppkId = request.Notifies().FirstOrDefault(n => n.KnownType == IkeNotifyMessageType.PpkIdentity);
                if (ppkId is not null && _ppk is not null && _ppkIdRaw is not null
                    && ppkId.Data.Length >= 1 && ppkId.Data.AsSpan(1).SequenceEqual(_ppkIdRaw))
                {
                    authKeys = _keys!.WithPpk(_ppk);
                }

                byte[] expected = IkePskAuth.ComputeInitiatorAuth(
                    _prf, _psk, _initRequestWire, _nonce, authKeys.SkPi, idI.BodyBytes());
                Assert.Equal(expected, auth.Data); // the initiator's AUTH verifies with the (possibly mixed) SK_pi

                var idR = new IdentificationPayload { IsInitiator = false, IdType = IkeIdType.Ipv4Address, Data = new byte[] { 10, 0, 0, 1 } };
                byte[] responderAuth = IkePskAuth.ComputeResponderAuth(
                    _prf, _psk, _initResponseWire, _initiatorNonce, authKeys.SkPr, idR.BodyBytes());

                var response = new IkeMessage
                {
                    InitiatorSpi = _initiatorSpi,
                    ResponderSpi = _spi,
                    ExchangeType = IkeExchangeType.IkeAuth,
                    Flags = IkeHeaderFlags.Response,
                    MessageId = 1,
                };
                response.Payloads.Add(idR);
                response.Payloads.Add(new AuthenticationPayload { Method = IkeAuthMethod.SharedKey, Data = responderAuth });
                var sar = new SecurityAssociationPayload();
                sar.Proposals.Add(IkeProposals.DefaultEsp(ChildInboundSpi));
                response.Payloads.Add(sar);
                response.Payloads.Add(TrafficSelectorPayload.AnyIpv4(isInitiator: true));
                response.Payloads.Add(TrafficSelectorPayload.AnyIpv4(isInitiator: false));
                response.Payloads.Add(NotifyPayload.Create(IkeNotifyMessageType.UseTransportMode, Array.Empty<byte>()));
                return _cipher.EncryptMessage(response);
            }
        }
    }
}
