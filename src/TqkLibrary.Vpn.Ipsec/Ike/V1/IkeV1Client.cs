using System.Net;
using System.Security.Cryptography;
using TqkLibrary.Vpn.Crypto;
using TqkLibrary.Vpn.Crypto.Abstractions.Interfaces;
using TqkLibrary.Vpn.Ipsec.Ike.V1.Enums;
using TqkLibrary.Vpn.Ipsec.Ike.V1.Models;
using TqkLibrary.Vpn.Ipsec.Ike.V1.Payloads;

namespace TqkLibrary.Vpn.Ipsec.Ike.V1
{
    /// <summary>
    /// The initiator-side IKEv1 client for L2TP/IPsec: Main Mode (PSK) over six messages then Quick Mode over three,
    /// producing the ESP CHILD SA keys. Pure protocol logic exposed as build/process steps; the orchestrator owns the
    /// UDP transport and the port-500→4500 switch that NAT-T triggers. Crypto pieces are unit-verified separately.
    /// </summary>
    public sealed class IkeV1Client
    {
        const byte IdTypeIpv4 = 1;

        readonly byte[] _preSharedKey;
        readonly IPAddress _localIdentity;
        readonly IPAddress _remoteIdentity;

        HashAlgorithmName _hash = HashAlgorithmName.SHA1;
        HmacPrf _prf = new(HashAlgorithmName.SHA1);
        ModpDhGroup _dhGroup = ModpDhGroup.Group2();
        int _cipherKeyLength = 32;

        byte[] _privateKey = Array.Empty<byte>();
        byte[] _keInitiator = Array.Empty<byte>();
        byte[] _keResponder = Array.Empty<byte>();
        byte[] _nonceInitiator;
        byte[] _nonceResponder = Array.Empty<byte>();
        byte[] _saInitiatorBody = Array.Empty<byte>();
        byte[] _idInitiatorBody = Array.Empty<byte>();

        IkeV1KeyMaterial? _keys;
        IkeV1Cipher? _phase1Cipher;
        byte[] _phase1LastIv = Array.Empty<byte>();
        uint _quickModeId;
        byte[] _quickModeNonce;
        byte[] _quickModeMessageAfterHash = Array.Empty<byte>();

        // Quick Mode rekey state (kept separate from the primary exchange above so a rekey never clobbers it).
        uint _rekeyMessageId;
        byte[] _rekeyNonceInitiator = Array.Empty<byte>();
        byte[] _rekeyNonceResponder = Array.Empty<byte>();
        byte[] _rekeyChildInboundSpi = Array.Empty<byte>();
        byte[] _rekeyChildOutboundSpi = Array.Empty<byte>();
        IkeV1Cipher? _rekeyCipher;

        /// <summary>Creates a client with the PSK and the IPv4 identities to assert for Phase 1 / traffic selectors.</summary>
        public IkeV1Client(byte[] preSharedKey, IPAddress localIdentity, IPAddress remoteIdentity, byte[]? initiatorCookie = null)
        {
            _preSharedKey = preSharedKey;
            _localIdentity = localIdentity;
            _remoteIdentity = remoteIdentity;
            InitiatorCookie = initiatorCookie ?? RandomNonZero(8);
            _nonceInitiator = RandomBytes(16);
            _quickModeNonce = RandomBytes(16);
            ChildInboundSpi = RandomBytes(4);
        }

        /// <summary>Our 8-byte initiator cookie (Phase 1 SPI).</summary>
        public byte[] InitiatorCookie { get; }

        /// <summary>The responder cookie, learned in MM2.</summary>
        public byte[] ResponderCookie { get; private set; } = new byte[8];

        /// <summary>The ESP SPI we chose (the peer sends to us on it).</summary>
        public byte[] ChildInboundSpi { get; }

        /// <summary>The ESP SPI the responder chose (we send to it on it).</summary>
        public byte[] ChildOutboundSpi { get; private set; } = Array.Empty<byte>();

        /// <summary>The NAT-D payload type to use (RFC 3947 = 20, or the draft = 130), set from the responder's VID.</summary>
        public IsakmpPayloadType NatDiscoveryType { get; private set; } = IsakmpPayloadType.NatDiscovery;

        /// <summary>The negotiated Phase 1 hash (for NAT-D and Quick Mode IV).</summary>
        public HashAlgorithmName NegotiatedHash => _hash;

        // ---- Main Mode ----

        /// <summary>MM1: SA proposal + NAT-T Vendor IDs.</summary>
        public byte[] BuildMainMode1()
        {
            IsakmpSaPayload sa = IkeV1Proposals.Phase1();
            _saInitiatorBody = sa.BodyBytes();

            var message = NewMessage(IsakmpExchangeType.MainMode);
            message.Payloads.Add(sa);
            message.Payloads.Add(new IsakmpRawPayload(IsakmpPayloadType.VendorId, IkeV1NatDetection.VendorIdRfc3947));
            message.Payloads.Add(new IsakmpRawPayload(IsakmpPayloadType.VendorId, IkeV1NatDetection.VendorIdDraft02));
            message.Payloads.Add(new IsakmpRawPayload(IsakmpPayloadType.VendorId, IkeV1NatDetection.VendorIdDraft03));
            return message.Encode();
        }

        /// <summary>MM2: read the responder cookie, the chosen transform, and which NAT-T flavour was accepted.</summary>
        public void ProcessMainMode2(byte[] wire)
        {
            IsakmpMessage message = IsakmpMessage.Decode(wire);
            ResponderCookie = message.ResponderCookie;

            IsakmpTransform chosen = message.Find<IsakmpSaPayload>()!.Proposals[0].Transforms[0];
            ushort keyBits = (ushort)AttributeOr(chosen, IkeV1Constants.Phase1Attribute.KeyLength, 256);
            ushort hashId = (ushort)AttributeOr(chosen, IkeV1Constants.Phase1Attribute.Hash, IkeV1Constants.HashAlgorithm.Sha1);
            ushort groupId = (ushort)AttributeOr(chosen, IkeV1Constants.Phase1Attribute.Group, IkeV1Constants.Group.Modp1024);

            _cipherKeyLength = keyBits / 8;
            _hash = hashId == IkeV1Constants.HashAlgorithm.Sha2_256 ? HashAlgorithmName.SHA256 : HashAlgorithmName.SHA1;
            _prf = new HmacPrf(_hash);
            _dhGroup = groupId == IkeV1Constants.Group.Modp2048 ? ModpDhGroup.Group14() : ModpDhGroup.Group2();

            foreach (IsakmpRawPayload vid in message.Payloads.OfType<IsakmpRawPayload>().Where(p => p.Type == IsakmpPayloadType.VendorId))
            {
                if (Equal(vid.Body, IkeV1NatDetection.VendorIdDraft02) || Equal(vid.Body, IkeV1NatDetection.VendorIdDraft03))
                    NatDiscoveryType = (IsakmpPayloadType)130; // draft NAT-D payload number
            }

            _privateKey = _dhGroup.GeneratePrivateKey();
            _keInitiator = _dhGroup.DerivePublicValue(_privateKey);
        }

        /// <summary>MM3: KE + Ni + the two NAT-D payloads (source claims port 500 to force NAT-T).</summary>
        public byte[] BuildMainMode3(IPAddress localIp, IPAddress remoteIp)
        {
            var message = NewMessage(IsakmpExchangeType.MainMode);
            message.Payloads.Add(new IsakmpRawPayload(IsakmpPayloadType.KeyExchange, _keInitiator));
            message.Payloads.Add(new IsakmpRawPayload(IsakmpPayloadType.Nonce, _nonceInitiator));
            // NAT-D #1 = destination (responder); #2 = source (initiator), claiming the IKE port to provoke NAT-T.
            message.Payloads.Add(new IsakmpRawPayload(NatDiscoveryType,
                IkeV1NatDetection.ComputeHash(_hash, InitiatorCookie, ResponderCookie, remoteIp, 500)));
            message.Payloads.Add(new IsakmpRawPayload(NatDiscoveryType,
                IkeV1NatDetection.ComputeHash(_hash, InitiatorCookie, ResponderCookie, localIp, 500)));
            return message.Encode();
        }

        /// <summary>MM4: read KEr + Nr, then derive SKEYID and the rest of the key set.</summary>
        public void ProcessMainMode4(byte[] wire)
        {
            IsakmpMessage message = IsakmpMessage.Decode(wire);
            _keResponder = message.FindRaw(IsakmpPayloadType.KeyExchange)!.Body;
            _nonceResponder = message.FindRaw(IsakmpPayloadType.Nonce)!.Body;

            byte[] shared = _dhGroup.DeriveSharedSecret(_privateKey, _keResponder);
            _keys = IkeV1KeyMaterial.DeriveMainMode(
                _hash, _preSharedKey, _nonceInitiator, _nonceResponder, shared,
                InitiatorCookie, ResponderCookie, _keInitiator, _keResponder, _cipherKeyLength, blockSize: 16);
            _phase1Cipher = new IkeV1Cipher(_keys.CipherKey, _keys.InitialIv);
        }

        /// <summary>MM5: encrypted IDi + HASH_I.</summary>
        public byte[] BuildMainMode5()
        {
            _idInitiatorBody = IdBody(IdTypeIpv4, 0, 0, _localIdentity.GetAddressBytes());
            byte[] hashI = IkeV1Auth.ComputeHashI(_prf, _keys!.Skeyid, _keInitiator, _keResponder,
                InitiatorCookie, ResponderCookie, _saInitiatorBody, _idInitiatorBody);

            var inner = new List<IsakmpPayload>
            {
                new IsakmpRawPayload(IsakmpPayloadType.Identification, _idInitiatorBody),
                new IsakmpRawPayload(IsakmpPayloadType.Hash, hashI),
            };
            return EncryptMessage(IsakmpExchangeType.MainMode, 0, inner);
        }

        /// <summary>MM6: decrypt, then verify HASH_R against the responder's identity.</summary>
        public bool ProcessMainMode6(byte[] wire)
        {
            List<IsakmpPayload> payloads = DecryptMessage(wire, out _);
            IsakmpRawPayload? idR = payloads.OfType<IsakmpRawPayload>().FirstOrDefault(p => p.Type == IsakmpPayloadType.Identification);
            IsakmpRawPayload? hashR = payloads.OfType<IsakmpRawPayload>().FirstOrDefault(p => p.Type == IsakmpPayloadType.Hash);
            if (idR is null || hashR is null) return false;

            byte[] expected = IkeV1Auth.ComputeHashR(_prf, _keys!.Skeyid, _keInitiator, _keResponder,
                InitiatorCookie, ResponderCookie, _saInitiatorBody, idR.Body);
            _phase1LastIv = _phase1Cipher!.CurrentIv;
            return FixedTimeEquals(expected, hashR.Body);
        }

        // ---- Quick Mode ----

        /// <summary>QM1: encrypted HASH(1) + ESP SA + Ni + IDci + IDcr.</summary>
        public byte[] BuildQuickMode1()
        {
            _quickModeId = RandomNonZeroUInt32();
            var afterHash = new List<IsakmpPayload>
            {
                IkeV1Proposals.Phase2(ChildInboundSpi),
                new IsakmpRawPayload(IsakmpPayloadType.Nonce, _quickModeNonce),
                new IsakmpRawPayload(IsakmpPayloadType.Identification, IdBody(IdTypeIpv4, 17, 1701, _localIdentity.GetAddressBytes())),
                new IsakmpRawPayload(IsakmpPayloadType.Identification, IdBody(IdTypeIpv4, 17, 1701, _remoteIdentity.GetAddressBytes())),
            };
            var afterHashBytes = new List<byte>();
            IsakmpMessage.EncodePayloadChain(afterHashBytes, afterHash);
            _quickModeMessageAfterHash = afterHashBytes.ToArray();

            byte[] hash1 = IkeV1QuickMode.ComputeHash1(_prf, _keys!.SkeyidA, _quickModeId, _quickModeMessageAfterHash);

            var inner = new List<IsakmpPayload> { new IsakmpRawPayload(IsakmpPayloadType.Hash, hash1) };
            inner.AddRange(afterHash);
            return EncryptMessage(IsakmpExchangeType.QuickMode, _quickModeId, inner, useQuickModeIv: true);
        }

        /// <summary>QM2: decrypt, verify HASH(2), and capture the responder's ESP SPI + nonce.</summary>
        public bool ProcessQuickMode2(byte[] wire)
        {
            List<IsakmpPayload> payloads = DecryptMessage(wire, out _);
            IsakmpSaPayload? sa = payloads.OfType<IsakmpSaPayload>().FirstOrDefault();
            IsakmpRawPayload? nr = payloads.OfType<IsakmpRawPayload>().FirstOrDefault(p => p.Type == IsakmpPayloadType.Nonce);
            if (sa is null || nr is null || sa.Proposals.Count == 0) return false;

            ChildOutboundSpi = sa.Proposals[0].Spi;
            _nonceResponder = nr.Body;
            return ChildOutboundSpi.Length == 4;
        }

        /// <summary>QM3: encrypted HASH(3).</summary>
        public byte[] BuildQuickMode3()
        {
            byte[] hash3 = IkeV1QuickMode.ComputeHash3(_prf, _keys!.SkeyidA, _quickModeId, _quickModeNonce, _nonceResponder);
            var inner = new List<IsakmpPayload> { new IsakmpRawPayload(IsakmpPayloadType.Hash, hash3) };
            return EncryptMessage(IsakmpExchangeType.QuickMode, _quickModeId, inner, useQuickModeIv: false);
        }

        /// <summary>Derives the ESP CHILD SA keys (AES-256 + HMAC-SHA1) once Quick Mode completes.</summary>
        public IkeV1Phase2Keys CreatePhase2Keys()
            => IkeV1Phase2Keys.Derive(_prf, _keys!.SkeyidD, IkeV1Constants.Protocol.Esp,
                ChildInboundSpi, ChildOutboundSpi, _quickModeNonce, _nonceResponder, encryptionKeyLength: 32, integrityKeyLength: 20);

        // ---- Quick Mode rekey (Phase 2 / CHILD SA refresh on the live IKE SA) ----

        /// <summary>The fresh ESP SPI we chose for the rekeyed CHILD SA (the peer sends to us on it).</summary>
        public byte[] RekeyChildInboundSpi => _rekeyChildInboundSpi;

        /// <summary>The ESP SPI the responder chose for the rekeyed CHILD SA (we send to it on it).</summary>
        public byte[] RekeyChildOutboundSpi => _rekeyChildOutboundSpi;

        /// <summary>Rekey QM1: a brand-new Quick Mode (fresh nonce, SPI, message id) negotiating a replacement ESP SA.</summary>
        public byte[] BuildRekeyQuickMode1()
        {
            _rekeyMessageId = RandomNonZeroUInt32();
            _rekeyNonceInitiator = RandomBytes(16);
            _rekeyChildInboundSpi = RandomBytes(4);
            _rekeyCipher = NewDerivedIvCipher(_rekeyMessageId);

            var afterHash = new List<IsakmpPayload>
            {
                IkeV1Proposals.Phase2(_rekeyChildInboundSpi),
                new IsakmpRawPayload(IsakmpPayloadType.Nonce, _rekeyNonceInitiator),
                new IsakmpRawPayload(IsakmpPayloadType.Identification, IdBody(IdTypeIpv4, 17, 1701, _localIdentity.GetAddressBytes())),
                new IsakmpRawPayload(IsakmpPayloadType.Identification, IdBody(IdTypeIpv4, 17, 1701, _remoteIdentity.GetAddressBytes())),
            };
            var afterHashBytes = new List<byte>();
            IsakmpMessage.EncodePayloadChain(afterHashBytes, afterHash);

            byte[] hash1 = IkeV1QuickMode.ComputeHash1(_prf, _keys!.SkeyidA, _rekeyMessageId, afterHashBytes.ToArray());
            var inner = new List<IsakmpPayload> { new IsakmpRawPayload(IsakmpPayloadType.Hash, hash1) };
            inner.AddRange(afterHash);
            return EncodeEncrypted(_rekeyCipher, IsakmpExchangeType.QuickMode, _rekeyMessageId, inner);
        }

        /// <summary>Rekey QM2: capture the responder's replacement ESP SPI and nonce.</summary>
        public bool ProcessRekeyQuickMode2(byte[] wire)
        {
            List<IsakmpPayload> payloads = DecryptWith(_rekeyCipher!, wire);
            IsakmpSaPayload? sa = payloads.OfType<IsakmpSaPayload>().FirstOrDefault();
            IsakmpRawPayload? nr = payloads.OfType<IsakmpRawPayload>().FirstOrDefault(p => p.Type == IsakmpPayloadType.Nonce);
            if (sa is null || nr is null || sa.Proposals.Count == 0) return false;

            _rekeyChildOutboundSpi = sa.Proposals[0].Spi;
            _rekeyNonceResponder = nr.Body;
            return _rekeyChildOutboundSpi.Length == 4;
        }

        /// <summary>Rekey QM3: the final HASH(3) confirming the rekey.</summary>
        public byte[] BuildRekeyQuickMode3()
        {
            byte[] hash3 = IkeV1QuickMode.ComputeHash3(_prf, _keys!.SkeyidA, _rekeyMessageId, _rekeyNonceInitiator, _rekeyNonceResponder);
            var inner = new List<IsakmpPayload> { new IsakmpRawPayload(IsakmpPayloadType.Hash, hash3) };
            return EncodeEncrypted(_rekeyCipher!, IsakmpExchangeType.QuickMode, _rekeyMessageId, inner);
        }

        /// <summary>Derives the rekeyed ESP CHILD SA keys.</summary>
        public IkeV1Phase2Keys CreateRekeyPhase2Keys()
            => IkeV1Phase2Keys.Derive(_prf, _keys!.SkeyidD, IkeV1Constants.Protocol.Esp,
                _rekeyChildInboundSpi, _rekeyChildOutboundSpi, _rekeyNonceInitiator, _rekeyNonceResponder, encryptionKeyLength: 32, integrityKeyLength: 20);

        /// <summary>True if <paramref name="wire"/> is the Quick Mode reply for the rekey exchange currently in flight.</summary>
        public bool IsRekeyReply(byte[] wire)
        {
            if (_rekeyMessageId == 0) return false;
            IsakmpMessage header = IsakmpMessage.ReadHeader(wire, out _);
            return header.ExchangeType == IsakmpExchangeType.QuickMode && header.MessageId == _rekeyMessageId;
        }

        // ---- Teardown: Delete payloads ----

        /// <summary>Builds an encrypted Informational+Delete for the current ESP CHILD SA (the latest inbound SPI).</summary>
        public byte[] BuildDeleteEsp()
        {
            byte[] spi = _rekeyChildInboundSpi.Length == 4 ? _rekeyChildInboundSpi : ChildInboundSpi;
            var delete = new IsakmpRawPayload(IsakmpPayloadType.Delete, IkeV1Delete.BuildEspDeleteBody(spi));
            return BuildInformational(new List<IsakmpPayload> { delete });
        }

        /// <summary>Builds an encrypted Informational+Delete for the ISAKMP SA (tearing the whole tunnel down).</summary>
        public byte[] BuildDeleteIsakmp()
        {
            var delete = new IsakmpRawPayload(IsakmpPayloadType.Delete, IkeV1Delete.BuildIsakmpDeleteBody(InitiatorCookie, ResponderCookie));
            return BuildInformational(new List<IsakmpPayload> { delete });
        }

        // ---- Informational exchange (DPD keepalive; Delete for teardown) ----

        /// <summary>Builds an encrypted DPD R-U-THERE probe (RFC 3706) carrying <paramref name="sequence"/>.</summary>
        public byte[] BuildDpdRUThere(uint sequence) => BuildDpdNotify(IkeV1Dpd.RUThere, sequence);

        /// <summary>Builds an encrypted DPD R-U-THERE-ACK answering a peer probe with its <paramref name="sequence"/>.</summary>
        public byte[] BuildDpdAck(uint sequence) => BuildDpdNotify(IkeV1Dpd.RUThereAck, sequence);

        byte[] BuildDpdNotify(ushort notifyType, uint sequence)
        {
            byte[] notifyBody = IkeV1Dpd.BuildNotifyBody(InitiatorCookie, ResponderCookie, notifyType, sequence);
            var afterHash = new List<IsakmpPayload> { new IsakmpRawPayload(IsakmpPayloadType.Notification, notifyBody) };
            return BuildInformational(afterHash);
        }

        /// <summary>
        /// Decrypts an inbound Informational exchange and classifies it (DPD request/ack or a Delete). Returns
        /// <see cref="IkeV1InformationalKind.Unknown"/> for any non-Informational message, so the caller can route
        /// every post-handshake IKE datagram here without inspecting the header itself.
        /// </summary>
        public IkeV1InformationalResult ProcessInformational(byte[] wire)
        {
            IsakmpMessage peek = IsakmpMessage.ReadHeader(wire, out _);
            if (peek.ExchangeType != IsakmpExchangeType.Informational)
                return new IkeV1InformationalResult(IkeV1InformationalKind.Unknown, 0);

            List<IsakmpPayload> payloads = DecryptWith(NewDerivedIvCipher(peek.MessageId), wire);

            foreach (IsakmpRawPayload payload in payloads.OfType<IsakmpRawPayload>())
            {
                if (payload.Type == IsakmpPayloadType.Notification
                    && IkeV1Dpd.TryParseNotify(payload.Body, out ushort notifyType, out uint sequence))
                {
                    if (notifyType == IkeV1Dpd.RUThere) return new IkeV1InformationalResult(IkeV1InformationalKind.DpdRequest, sequence);
                    if (notifyType == IkeV1Dpd.RUThereAck) return new IkeV1InformationalResult(IkeV1InformationalKind.DpdAck, sequence);
                }
                else if (payload.Type == IsakmpPayloadType.Delete && payload.Body.Length >= 5)
                {
                    byte protocol = payload.Body[4]; // Delete body: DOI(4) | Protocol(1) | …
                    if (protocol == IkeV1Constants.Protocol.Esp) return new IkeV1InformationalResult(IkeV1InformationalKind.DeleteEsp, 0);
                    if (protocol == IkeV1Constants.Protocol.Isakmp) return new IkeV1InformationalResult(IkeV1InformationalKind.DeleteIsakmp, 0);
                }
            }
            return new IkeV1InformationalResult(IkeV1InformationalKind.Unknown, 0);
        }

        /// <summary>Wraps <paramref name="afterHash"/> in a HASH(1)-prefixed Informational message under a fresh message id.</summary>
        byte[] BuildInformational(List<IsakmpPayload> afterHash)
        {
            uint messageId = RandomNonZeroUInt32();

            var afterHashBytes = new List<byte>();
            IsakmpMessage.EncodePayloadChain(afterHashBytes, afterHash);
            byte[] hash = IkeV1QuickMode.ComputeHash1(_prf, _keys!.SkeyidA, messageId, afterHashBytes.ToArray());

            var inner = new List<IsakmpPayload> { new IsakmpRawPayload(IsakmpPayloadType.Hash, hash) };
            inner.AddRange(afterHash);
            return EncodeEncrypted(NewDerivedIvCipher(messageId), IsakmpExchangeType.Informational, messageId, inner);
        }

        List<IsakmpPayload> DecryptWith(IkeV1Cipher cipher, byte[] wire)
        {
            IsakmpMessage.ReadHeader(wire, out IsakmpPayloadType first);
            byte[] ciphertext = new byte[wire.Length - IsakmpMessage.HeaderSize];
            Buffer.BlockCopy(wire, IsakmpMessage.HeaderSize, ciphertext, 0, ciphertext.Length);
            byte[] plain = cipher.Decrypt(ciphertext);

            var payloads = new List<IsakmpPayload>();
            IsakmpMessage.ParsePayloadChain(plain, first, payloads);
            return payloads;
        }

        // A Quick Mode or Informational message derives its IV from the last Phase 1 IV and its message id
        // (RFC 2409 §5.5), independent of the Phase 1 cipher chain. Single-message exchanges (DPD, Delete) make a
        // fresh one each time; a multi-message rekey reuses one instance so its IV chains across QM1→QM2→QM3.
        IkeV1Cipher NewDerivedIvCipher(uint messageId)
            => new IkeV1Cipher(_keys!.CipherKey, IkeV1Cipher.QuickModeIv(_hash, _phase1LastIv, messageId));

        // ---- helpers ----

        IsakmpMessage NewMessage(IsakmpExchangeType exchange) => new()
        {
            InitiatorCookie = InitiatorCookie,
            ResponderCookie = ResponderCookie,
            ExchangeType = exchange,
            MessageId = 0,
        };

        byte[] EncryptMessage(IsakmpExchangeType exchange, uint messageId, List<IsakmpPayload> payloads, bool useQuickModeIv = false)
        {
            IkeV1Cipher cipher = exchange == IsakmpExchangeType.QuickMode
                ? QuickModeCipher(messageId, useQuickModeIv)
                : _phase1Cipher!;
            return EncodeEncrypted(cipher, exchange, messageId, payloads);
        }

        byte[] EncodeEncrypted(IkeV1Cipher cipher, IsakmpExchangeType exchange, uint messageId, List<IsakmpPayload> payloads)
        {
            var chain = new List<byte>();
            IsakmpMessage.EncodePayloadChain(chain, payloads);
            byte[] ciphertext = cipher.Encrypt(chain.ToArray());

            var output = new List<byte>(IsakmpMessage.HeaderSize + ciphertext.Length);
            var header = new IsakmpMessage
            {
                InitiatorCookie = InitiatorCookie,
                ResponderCookie = ResponderCookie,
                ExchangeType = exchange,
                Flags = IsakmpFlags.Encryption,
                MessageId = messageId,
            };
            IsakmpMessage.WriteHeader(output, header, payloads[0].Type, IsakmpMessage.HeaderSize + ciphertext.Length);
            output.AddRange(ciphertext);
            return output.ToArray();
        }

        IkeV1Cipher? _quickModeCipher;
        uint _quickModeCipherId;

        IkeV1Cipher QuickModeCipher(uint messageId, bool create)
        {
            if (create || _quickModeCipher is null || _quickModeCipherId != messageId)
            {
                byte[] iv = IkeV1Cipher.QuickModeIv(_hash, _phase1LastIv, messageId);
                _quickModeCipher = new IkeV1Cipher(_keys!.CipherKey, iv);
                _quickModeCipherId = messageId;
            }
            return _quickModeCipher;
        }

        List<IsakmpPayload> DecryptMessage(byte[] wire, out IsakmpMessage header)
        {
            header = IsakmpMessage.ReadHeader(wire, out IsakmpPayloadType first);
            IkeV1Cipher cipher = header.ExchangeType == IsakmpExchangeType.QuickMode
                ? QuickModeCipher(header.MessageId, create: false)
                : _phase1Cipher!;

            byte[] ciphertext = new byte[wire.Length - IsakmpMessage.HeaderSize];
            Buffer.BlockCopy(wire, IsakmpMessage.HeaderSize, ciphertext, 0, ciphertext.Length);
            byte[] plain = cipher.Decrypt(ciphertext);

            var payloads = new List<IsakmpPayload>();
            IsakmpMessage.ParsePayloadChain(plain, first, payloads);
            return payloads;
        }

        static byte[] IdBody(byte idType, byte protocol, ushort port, byte[] address)
        {
            byte[] body = new byte[4 + address.Length];
            body[0] = idType;
            body[1] = protocol;
            body[2] = (byte)(port >> 8);
            body[3] = (byte)port;
            Buffer.BlockCopy(address, 0, body, 4, address.Length);
            return body;
        }

        static uint AttributeOr(IsakmpTransform transform, ushort type, uint fallback)
        {
            foreach (IsakmpAttribute attribute in transform.Attributes)
                if (attribute.Type == type) return attribute.NumericValue;
            return fallback;
        }

        static bool Equal(byte[] a, byte[] b)
        {
            if (a.Length != b.Length) return false;
            for (int i = 0; i < a.Length; i++) if (a[i] != b[i]) return false;
            return true;
        }

        static bool FixedTimeEquals(byte[] a, byte[] b)
        {
            if (a.Length != b.Length) return false;
            int diff = 0;
            for (int i = 0; i < a.Length; i++) diff |= a[i] ^ b[i];
            return diff == 0;
        }

        static byte[] RandomBytes(int length)
        {
            byte[] buffer = new byte[length];
            using var rng = RandomNumberGenerator.Create();
            rng.GetBytes(buffer);
            return buffer;
        }

        static byte[] RandomNonZero(int length)
        {
            byte[] buffer = RandomBytes(length);
            bool allZero = true;
            foreach (byte b in buffer) if (b != 0) { allZero = false; break; }
            if (allZero) buffer[0] = 1;
            return buffer;
        }

        static uint RandomNonZeroUInt32()
        {
            byte[] b = RandomBytes(4);
            uint value = (uint)((b[0] << 24) | (b[1] << 16) | (b[2] << 8) | b[3]);
            return value == 0 ? 1u : value;
        }
    }
}
