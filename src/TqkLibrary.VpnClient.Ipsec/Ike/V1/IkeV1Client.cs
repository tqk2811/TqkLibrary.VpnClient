using System.Net;
using System.Security.Cryptography;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;
using TqkLibrary.VpnClient.Abstractions.Diagnostics.Extensions;
using TqkLibrary.VpnClient.Abstractions.Drivers;
using TqkLibrary.VpnClient.Crypto;
using TqkLibrary.VpnClient.Crypto.Abstractions.Interfaces;
using TqkLibrary.VpnClient.Ipsec.Esp;
using TqkLibrary.VpnClient.Ipsec.Ike.V1.Enums;
using TqkLibrary.VpnClient.Ipsec.Ike.V1.Models;
using TqkLibrary.VpnClient.Ipsec.Ike.V1.Payloads;

namespace TqkLibrary.VpnClient.Ipsec.Ike.V1
{
    /// <summary>
    /// The initiator-side IKEv1 client for L2TP/IPsec: Main Mode (PSK) over six messages then Quick Mode over three,
    /// producing the ESP CHILD SA keys. Pure protocol logic exposed as build/process steps; the orchestrator owns the
    /// UDP transport and the port-500→4500 switch that NAT-T triggers. Crypto pieces are unit-verified separately.
    /// </summary>
    public sealed class IkeV1Client
    {
        const byte IdTypeIpv4 = 1;
        const string Layer = "ike.v1";

        readonly byte[] _preSharedKey;
        readonly IPAddress _localIdentity;
        readonly IPAddress _remoteIdentity;
        readonly ILogger _logger;

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
        byte[][] _responderNatD = Array.Empty<byte[]>();

        IkeV1KeyMaterial? _keys;
        IkeV1Cipher? _phase1Cipher;
        byte[] _phase1LastIv = Array.Empty<byte>();

        // Aggressive Mode state: the group identity asserted in message 1 (cleartext) and the responder identity read
        // from message 2. Both feed HASH_I / HASH_R the same way Main Mode's IDi / IDr do.
        byte _aggressiveIdType = IdTypeIpv4;
        byte[] _aggressiveIdBody = Array.Empty<byte>();
        byte[] _idResponderBody = Array.Empty<byte>();

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

        /// <summary>
        /// Creates a client with the PSK and the IPv4 identities to assert for Phase 1 / traffic selectors.
        /// <paramref name="logger"/> receives fine-grained Main/Quick Mode / NAT-D / rekey traces at
        /// <see cref="LogLevel.Trace"/>; null logs to a no-op logger (no behaviour change).
        /// </summary>
        public IkeV1Client(byte[] preSharedKey, IPAddress localIdentity, IPAddress remoteIdentity, byte[]? initiatorCookie = null,
            ILogger? logger = null)
        {
            _preSharedKey = preSharedKey;
            _localIdentity = localIdentity;
            _remoteIdentity = remoteIdentity;
            _logger = logger ?? NullLogger.Instance;
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

        /// <summary>The ESP suite the responder selected in Quick Mode (defaults to AES-CBC + HMAC-SHA1 until QM2).</summary>
        public EspSuiteSelection NegotiatedEsp { get; private set; } = EspSuiteSelection.AesCbcHmacSha1();

        /// <summary>The ESP suite the responder selected for the rekeyed CHILD SA (defaults to AES-CBC + HMAC-SHA1).</summary>
        public EspSuiteSelection RekeyNegotiatedEsp { get; private set; } = EspSuiteSelection.AesCbcHmacSha1();

        /// <summary>The NAT-D payload type to use (RFC 3947 = 20, or the draft = 130), set from the responder's VID.</summary>
        public IsakmpPayloadType NatDiscoveryType { get; private set; } = IsakmpPayloadType.NatDiscovery;

        /// <summary>The negotiated Phase 1 hash (for NAT-D and Quick Mode IV).</summary>
        public HashAlgorithmName NegotiatedHash => _hash;

        /// <summary>
        /// When set, Quick Mode offers plain Transport encapsulation before UDP-Encapsulated-Transport so a no-NAT
        /// gateway installs a native (IP proto-50) ESP SA instead of an espinudp one. The driver sets it when it
        /// carries ESP natively (honest-first with no NAT); left false for forced NAT-T (ESP over UDP/4500).
        /// </summary>
        public bool PreferNativeTransport { get; set; }

        /// <summary>
        /// When set, Quick Mode offers ESP <b>tunnel</b> mode (UDP-Encapsulated-Tunnel + plain Tunnel) instead of the
        /// transport-mode proposal L2TP/IPsec uses. The Cisco IPsec / EzVPN driver sets it so the gateway installs a
        /// tunnel-mode CHILD SA whose decapsulated inner IP packets ride the <see cref="Esp.EspTunnelChannel"/> straight
        /// to the IP stack (no L2TP/PPP). Left false for L2TP/IPsec (transport mode).
        /// </summary>
        public bool PreferTunnelMode { get; set; }

        /// <summary>
        /// Sets the identity asserted in Aggressive Mode message 1 (the group identity for Cisco IPsec / EzVPN). The
        /// gateway selects the group PSK by this value, so it must match the gateway's configured group name.
        /// <paramref name="idType"/> is the ISAKMP ID type (e.g. <c>11</c> = KEY_ID, <c>2</c> = FQDN, <c>1</c> = IPv4).
        /// </summary>
        public void SetAggressiveIdentity(byte idType, byte[] idData)
        {
            _aggressiveIdType = idType;
            _aggressiveIdBody = IdBody(idType, 0, 0, idData);
        }

        // ---- Aggressive Mode (Cisco IPsec / EzVPN Phase 1: three messages with the group identity in the clear) ----

        /// <summary>
        /// AG1: the cleartext Aggressive Mode message 1 (RFC 2409 §5.4) — SA + KE + Ni + IDii. The group identity is
        /// sent in the clear (the cost of Aggressive Mode), so the gateway can pick the group PSK before deriving keys.
        /// <para><b>Security note:</b> Aggressive Mode + group PSK is known weak — the responder's HASH_R is computable
        /// offline from a captured exchange, exposing the group PSK to an offline dictionary attack. It exists only for
        /// interop with legacy Cisco-compatible gateways; never use it where Main Mode (or IKEv2) is available.</para>
        /// </summary>
        public byte[] BuildAggressive1()
        {
            IsakmpSaPayload sa = IkeV1Proposals.Phase1Aggressive(IkeV1Constants.Group.Modp1024);
            _saInitiatorBody = sa.BodyBytes();
            _dhGroup = ModpDhGroup.Group2(); // the single group offered in AG1
            _privateKey = _dhGroup.GeneratePrivateKey();
            _keInitiator = _dhGroup.DerivePublicValue(_privateKey);
            if (_aggressiveIdBody.Length == 0)
                _aggressiveIdBody = IdBody(_aggressiveIdType, 0, 0, _localIdentity.GetAddressBytes());

            var message = NewMessage(IsakmpExchangeType.Aggressive);
            message.Payloads.Add(sa);
            message.Payloads.Add(new IsakmpRawPayload(IsakmpPayloadType.KeyExchange, _keInitiator));
            message.Payloads.Add(new IsakmpRawPayload(IsakmpPayloadType.Nonce, _nonceInitiator));
            message.Payloads.Add(new IsakmpRawPayload(IsakmpPayloadType.Identification, _aggressiveIdBody));
            // The two NAT-T Vendor IDs let the gateway float us to UDP/4500 (forced NAT-T) just as Main Mode does.
            message.Payloads.Add(new IsakmpRawPayload(IsakmpPayloadType.VendorId, IkeV1NatDetection.VendorIdRfc3947));
            message.Payloads.Add(new IsakmpRawPayload(IsakmpPayloadType.VendorId, IkeV1NatDetection.VendorIdDraft02));
            // XAUTH Vendor ID (RFC draft) so the gateway knows the client speaks XAUTH.
            message.Payloads.Add(new IsakmpRawPayload(IsakmpPayloadType.VendorId, IkeV1NatDetection.VendorIdXAuth));
            return message.Encode();
        }

        /// <summary>
        /// AG2: read the responder cookie, the chosen transform, KEr, Nr and IDir, derive the key set, and verify the
        /// responder's HASH_R (RFC 2409 §5.4). Returns false on a HASH_R mismatch (wrong group PSK / tampered reply).
        /// </summary>
        public bool ProcessAggressive2(byte[] wire)
        {
            IsakmpMessage message = IsakmpMessage.Decode(wire);
            ResponderCookie = message.ResponderCookie;

            IsakmpTransform chosen = message.Find<IsakmpSaPayload>()!.Proposals[0].Transforms[0];
            ushort keyBits = (ushort)AttributeOr(chosen, IkeV1Constants.Phase1Attribute.KeyLength, 256);
            ushort hashId = (ushort)AttributeOr(chosen, IkeV1Constants.Phase1Attribute.Hash, IkeV1Constants.HashAlgorithm.Sha1);
            _cipherKeyLength = keyBits / 8;
            _hash = hashId == IkeV1Constants.HashAlgorithm.Sha2_256 ? HashAlgorithmName.SHA256 : HashAlgorithmName.SHA1;
            _prf = new HmacPrf(_hash);

            foreach (IsakmpRawPayload vid in message.Payloads.OfType<IsakmpRawPayload>().Where(p => p.Type == IsakmpPayloadType.VendorId))
            {
                if (Equal(vid.Body, IkeV1NatDetection.VendorIdDraft02) || Equal(vid.Body, IkeV1NatDetection.VendorIdDraft03))
                    NatDiscoveryType = (IsakmpPayloadType)130;
            }

            _keResponder = message.FindRaw(IsakmpPayloadType.KeyExchange)!.Body;
            _nonceResponder = message.FindRaw(IsakmpPayloadType.Nonce)!.Body;
            _idResponderBody = message.FindRaw(IsakmpPayloadType.Identification)!.Body;
            _responderNatD = message.Payloads.OfType<IsakmpRawPayload>()
                .Where(p => p.Type == NatDiscoveryType).Select(p => p.Body).ToArray();

            byte[] shared = _dhGroup.DeriveSharedSecret(_privateKey, _keResponder);
            _keys = IkeV1KeyMaterial.DeriveMainMode(
                _hash, _preSharedKey, _nonceInitiator, _nonceResponder, shared,
                InitiatorCookie, ResponderCookie, _keInitiator, _keResponder, _cipherKeyLength, blockSize: 16);
            _phase1Cipher = new IkeV1Cipher(_keys.CipherKey, _keys.InitialIv);

            byte[] expected = IkeV1Auth.ComputeHashR(_prf, _keys.Skeyid, _keInitiator, _keResponder,
                InitiatorCookie, ResponderCookie, _saInitiatorBody, _idResponderBody);
            byte[] hashR = message.FindRaw(IsakmpPayloadType.Hash)?.Body ?? Array.Empty<byte>();
            bool ok = hashR.Length > 0 && FixedTimeEquals(expected, hashR);
            _logger.LogProtocolStep(Layer, ok
                ? "AG2: SKEYID* derived, responder HASH_R verified — Aggressive Mode Phase 1 established"
                : "AG2: responder HASH_R mismatch (wrong group PSK or tampered reply)");
            return ok;
        }

        /// <summary>
        /// AG3: the encrypted Aggressive Mode message 3 — HASH_I authenticating the exchange (RFC 2409 §5.4). After this
        /// message the Phase 1 SA is established and the cipher's last IV seeds every later derived-IV exchange
        /// (Transaction / Quick Mode / Informational).
        /// </summary>
        public byte[] BuildAggressive3()
        {
            byte[] hashI = IkeV1Auth.ComputeHashI(_prf, _keys!.Skeyid, _keInitiator, _keResponder,
                InitiatorCookie, ResponderCookie, _saInitiatorBody, _aggressiveIdBody);
            var inner = new List<IsakmpPayload> { new IsakmpRawPayload(IsakmpPayloadType.Hash, hashI) };
            byte[] wire = EncryptMessage(IsakmpExchangeType.Aggressive, 0, inner);
            _phase1LastIv = _phase1Cipher!.CurrentIv; // seeds the Transaction / Quick Mode / Informational derived IVs
            _logger.LogProtocolStep(Layer, "AG3: HASH_I sent — Phase 1 (Aggressive Mode) complete");
            return wire;
        }

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

            if (_logger.IsEnabled(LogLevel.Trace))
                _logger.LogProtocolStep(Layer,
                    $"MM2: responder cookie learned; chose hash={_hash.Name}, keyLen={_cipherKeyLength * 8}b, " +
                    $"DH={(groupId == IkeV1Constants.Group.Modp2048 ? "modp2048" : "modp1024")}, NAT-D type={(int)NatDiscoveryType}");
        }

        /// <summary>
        /// MM3 (forced NAT-T): KE + Ni + the two NAT-D payloads claiming source port 500 while the socket actually
        /// sends from an ephemeral port, so the gateway concludes there is a NAT and floats to UDP/4500.
        /// </summary>
        public byte[] BuildMainMode3(IPAddress localIp, IPAddress remoteIp)
            => BuildMainMode3(localIp, 500, remoteIp, 500);

        /// <summary>
        /// MM3 (general): KE + Ni + NAT-D #1 (destination = <paramref name="remoteIp"/>:<paramref name="remotePort"/>)
        /// and NAT-D #2 (source = <paramref name="localIp"/>:<paramref name="localPort"/>). Pass the real bound address
        /// and port for an honest handshake, or the spoofed <c>(Any, 500)</c> source to force NAT-T.
        /// </summary>
        public byte[] BuildMainMode3(IPAddress localIp, ushort localPort, IPAddress remoteIp, ushort remotePort)
        {
            var message = NewMessage(IsakmpExchangeType.MainMode);
            message.Payloads.Add(new IsakmpRawPayload(IsakmpPayloadType.KeyExchange, _keInitiator));
            message.Payloads.Add(new IsakmpRawPayload(IsakmpPayloadType.Nonce, _nonceInitiator));
            // NAT-D #1 = destination (responder); #2 = source (initiator). RFC 3947: HASH(CKY-I | CKY-R | IP | Port).
            message.Payloads.Add(new IsakmpRawPayload(NatDiscoveryType,
                IkeV1NatDetection.ComputeHash(_hash, InitiatorCookie, ResponderCookie, remoteIp, remotePort)));
            message.Payloads.Add(new IsakmpRawPayload(NatDiscoveryType,
                IkeV1NatDetection.ComputeHash(_hash, InitiatorCookie, ResponderCookie, localIp, localPort)));
            return message.Encode();
        }

        /// <summary>MM4: read KEr + Nr, then derive SKEYID and the rest of the key set.</summary>
        public void ProcessMainMode4(byte[] wire)
        {
            IsakmpMessage message = IsakmpMessage.Decode(wire);
            _keResponder = message.FindRaw(IsakmpPayloadType.KeyExchange)!.Body;
            _nonceResponder = message.FindRaw(IsakmpPayloadType.Nonce)!.Body;
            // Keep the responder's NAT-D hashes so an honest handshake can read its NAT verdict (see DetectNat).
            _responderNatD = message.Payloads.OfType<IsakmpRawPayload>()
                .Where(p => p.Type == NatDiscoveryType).Select(p => p.Body).ToArray();

            byte[] shared = _dhGroup.DeriveSharedSecret(_privateKey, _keResponder);
            _keys = IkeV1KeyMaterial.DeriveMainMode(
                _hash, _preSharedKey, _nonceInitiator, _nonceResponder, shared,
                InitiatorCookie, ResponderCookie, _keInitiator, _keResponder, _cipherKeyLength, blockSize: 16);
            _phase1Cipher = new IkeV1Cipher(_keys.CipherKey, _keys.InitialIv);
            _logger.LogProtocolStep(Layer, "MM4: KEr/Nr consumed, SKEYID* derived, Phase 1 cipher armed");
        }

        /// <summary>
        /// Reads the NAT-Traversal verdict from the responder's MM4 NAT-D payloads (RFC 3947). Compares the hashes we
        /// expect for our own bound address and for the gateway against what the gateway actually sent: a miss for our
        /// address means a NAT sits in front of us (an honest handshake should float to UDP/4500), a hit means none
        /// (the gateway saw us directly and expects native ESP). Pass the real bound
        /// <paramref name="localIp"/>/<paramref name="localPort"/> and the gateway endpoint. Only meaningful after
        /// <see cref="ProcessMainMode4"/>; returns <c>ServerSentNatD = false</c> if the gateway sent no NAT-D at all.
        /// </summary>
        public IkeV1NatDetectionResult DetectNat(IPAddress localIp, ushort localPort, IPAddress remoteIp, ushort remotePort)
        {
            if (_responderNatD.Length == 0)
                return new IkeV1NatDetectionResult(serverSentNatD: false, localBehindNat: false, remoteBehindNat: false);

            byte[] expectedLocal = IkeV1NatDetection.ComputeHash(_hash, InitiatorCookie, ResponderCookie, localIp, localPort);
            byte[] expectedRemote = IkeV1NatDetection.ComputeHash(_hash, InitiatorCookie, ResponderCookie, remoteIp, remotePort);
            bool localBehindNat = !IkeV1NatDetection.MatchesAny(_responderNatD, expectedLocal);
            bool remoteBehindNat = !IkeV1NatDetection.MatchesAny(_responderNatD, expectedRemote);
            if (_logger.IsEnabled(LogLevel.Trace))
                _logger.LogProtocolStep(Layer, $"NAT-D verdict: localBehindNat={localBehindNat}, remoteBehindNat={remoteBehindNat}");
            return new IkeV1NatDetectionResult(serverSentNatD: true, localBehindNat, remoteBehindNat);
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
            List<IsakmpPayload> payloads = DecryptMessage(wire, out _, out _);
            IsakmpRawPayload? idR = payloads.OfType<IsakmpRawPayload>().FirstOrDefault(p => p.Type == IsakmpPayloadType.Identification);
            IsakmpRawPayload? hashR = payloads.OfType<IsakmpRawPayload>().FirstOrDefault(p => p.Type == IsakmpPayloadType.Hash);
            if (idR is null || hashR is null) return false;

            byte[] expected = IkeV1Auth.ComputeHashR(_prf, _keys!.Skeyid, _keInitiator, _keResponder,
                InitiatorCookie, ResponderCookie, _saInitiatorBody, idR.Body);
            _phase1LastIv = _phase1Cipher!.CurrentIv;
            bool ok = FixedTimeEquals(expected, hashR.Body);
            _logger.LogProtocolStep(Layer, ok
                ? "MM6: responder HASH_R verified — Phase 1 (Main Mode) established"
                : "MM6: responder HASH_R mismatch (wrong PSK or tampered reply)");
            return ok;
        }

        // ---- Quick Mode ----

        /// <summary>QM1: encrypted HASH(1) + ESP SA + Ni + IDci + IDcr.</summary>
        public byte[] BuildQuickMode1()
        {
            _quickModeId = RandomNonZeroUInt32();
            var afterHash = new List<IsakmpPayload>
            {
                PreferTunnelMode ? IkeV1Proposals.Phase2Tunnel(ChildInboundSpi) : IkeV1Proposals.Phase2(ChildInboundSpi, PreferNativeTransport),
                new IsakmpRawPayload(IsakmpPayloadType.Nonce, _quickModeNonce),
                QuickModeIdentity(local: true),
                QuickModeIdentity(local: false),
            };
            var afterHashBytes = new List<byte>();
            IsakmpMessage.EncodePayloadChain(afterHashBytes, afterHash);
            _quickModeMessageAfterHash = afterHashBytes.ToArray();

            byte[] hash1 = IkeV1QuickMode.ComputeHash1(_prf, _keys!.SkeyidA, _quickModeId, _quickModeMessageAfterHash);

            var inner = new List<IsakmpPayload> { new IsakmpRawPayload(IsakmpPayloadType.Hash, hash1) };
            inner.AddRange(afterHash);
            return EncryptMessage(IsakmpExchangeType.QuickMode, _quickModeId, inner, useQuickModeIv: true);
        }

        /// <summary>
        /// QM2: decrypt, authenticate the responder's HASH(2) (RFC 2409 §5.5 — throws
        /// <see cref="VpnServerRejectedException"/> on mismatch), then capture its ESP SPI, nonce, and selected
        /// transform (which sets <see cref="NegotiatedEsp"/>).
        /// </summary>
        public bool ProcessQuickMode2(byte[] wire)
        {
            List<IsakmpPayload> payloads = DecryptMessage(wire, out _, out byte[] plaintext);
            VerifyQuickModeHash2(plaintext, payloads, _quickModeId, _quickModeNonce);

            IsakmpSaPayload? sa = payloads.OfType<IsakmpSaPayload>().FirstOrDefault();
            IsakmpRawPayload? nr = payloads.OfType<IsakmpRawPayload>().FirstOrDefault(p => p.Type == IsakmpPayloadType.Nonce);
            if (sa is null || nr is null || sa.Proposals.Count == 0 || sa.Proposals[0].Transforms.Count == 0) return false;

            EspSuiteSelection? selection = ParseEspSelection(sa.Proposals[0].Transforms[0]);
            if (selection is null) return false;

            ChildOutboundSpi = sa.Proposals[0].Spi;
            _nonceResponder = nr.Body;
            NegotiatedEsp = selection;
            if (_logger.IsEnabled(LogLevel.Trace))
                _logger.LogProtocolStep(Layer,
                    $"QM2: HASH(2) verified, ESP CHILD SA negotiated ({selection.Algorithm}, key {selection.EncryptionKeyLengthBytes * 8}b); outbound SPI captured");
            return ChildOutboundSpi.Length == 4;
        }

        /// <summary>
        /// Maps the responder's selected ESP transform to the suite we will build. AES-GCM only when the transform
        /// id says so; everything else falls back to AES-CBC with the key length / authentication read from the
        /// attributes (defaulting to 256-bit / HMAC-SHA1-96, the live path's behaviour). Returns null if unusable.
        /// </summary>
        static EspSuiteSelection? ParseEspSelection(IsakmpTransform transform)
        {
            int keyBytes = (int)AttributeOr(transform, IkeV1Constants.Phase2Attribute.KeyLength, 256) / 8;
            if (keyBytes != 16 && keyBytes != 24 && keyBytes != 32) return null;

            if (transform.TransformId == IkeV1Constants.EspTransform.AesGcm16)
                return EspSuiteSelection.AesGcm16(keyBytes);

            uint auth = AttributeOr(transform, IkeV1Constants.Phase2Attribute.AuthAlgorithm, IkeV1Constants.AuthAlgorithm.HmacSha1);
            return auth == IkeV1Constants.AuthAlgorithm.HmacSha2_256
                ? EspSuiteSelection.AesCbcHmacSha256(keyBytes)
                : EspSuiteSelection.AesCbcHmacSha1(keyBytes);
        }

        /// <summary>QM3: encrypted HASH(3).</summary>
        public byte[] BuildQuickMode3()
        {
            byte[] hash3 = IkeV1QuickMode.ComputeHash3(_prf, _keys!.SkeyidA, _quickModeId, _quickModeNonce, _nonceResponder);
            var inner = new List<IsakmpPayload> { new IsakmpRawPayload(IsakmpPayloadType.Hash, hash3) };
            return EncryptMessage(IsakmpExchangeType.QuickMode, _quickModeId, inner, useQuickModeIv: false);
        }

        /// <summary>
        /// Derives the ESP CHILD SA keying material once Quick Mode completes, sized to the negotiated suite
        /// (<see cref="NegotiatedEsp"/>): the encryption key followed by the integrity key (CBC) or salt (GCM).
        /// </summary>
        public IkeV1Phase2Keys CreatePhase2Keys()
            => IkeV1Phase2Keys.Derive(_prf, _keys!.SkeyidD, IkeV1Constants.Protocol.Esp,
                ChildInboundSpi, ChildOutboundSpi, _quickModeNonce, _nonceResponder,
                NegotiatedEsp.EncryptionKeyLengthBytes, NegotiatedEsp.SecondSliceLengthBytes);

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
                IkeV1Proposals.Phase2(_rekeyChildInboundSpi, PreferNativeTransport),
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

        /// <summary>
        /// Rekey QM2: authenticate the responder's HASH(2) (RFC 2409 §5.5 — throws
        /// <see cref="VpnServerRejectedException"/> on mismatch), then capture its replacement ESP SPI, nonce,
        /// and selected transform.
        /// </summary>
        public bool ProcessRekeyQuickMode2(byte[] wire)
        {
            List<IsakmpPayload> payloads = DecryptWith(_rekeyCipher!, wire, out byte[] plaintext);
            VerifyQuickModeHash2(plaintext, payloads, _rekeyMessageId, _rekeyNonceInitiator);

            IsakmpSaPayload? sa = payloads.OfType<IsakmpSaPayload>().FirstOrDefault();
            IsakmpRawPayload? nr = payloads.OfType<IsakmpRawPayload>().FirstOrDefault(p => p.Type == IsakmpPayloadType.Nonce);
            if (sa is null || nr is null || sa.Proposals.Count == 0 || sa.Proposals[0].Transforms.Count == 0) return false;

            EspSuiteSelection? selection = ParseEspSelection(sa.Proposals[0].Transforms[0]);
            if (selection is null) return false;

            _rekeyChildOutboundSpi = sa.Proposals[0].Spi;
            _rekeyNonceResponder = nr.Body;
            RekeyNegotiatedEsp = selection;
            if (_logger.IsEnabled(LogLevel.Trace))
                _logger.LogProtocolStep(Layer,
                    $"rekey QM2: replacement ESP CHILD SA negotiated ({selection.Algorithm}, key {selection.EncryptionKeyLengthBytes * 8}b)");
            return _rekeyChildOutboundSpi.Length == 4;
        }

        /// <summary>Rekey QM3: the final HASH(3) confirming the rekey.</summary>
        public byte[] BuildRekeyQuickMode3()
        {
            byte[] hash3 = IkeV1QuickMode.ComputeHash3(_prf, _keys!.SkeyidA, _rekeyMessageId, _rekeyNonceInitiator, _rekeyNonceResponder);
            var inner = new List<IsakmpPayload> { new IsakmpRawPayload(IsakmpPayloadType.Hash, hash3) };
            return EncodeEncrypted(_rekeyCipher!, IsakmpExchangeType.QuickMode, _rekeyMessageId, inner);
        }

        /// <summary>Derives the rekeyed ESP CHILD SA keying material, sized to <see cref="RekeyNegotiatedEsp"/>.</summary>
        public IkeV1Phase2Keys CreateRekeyPhase2Keys()
            => IkeV1Phase2Keys.Derive(_prf, _keys!.SkeyidD, IkeV1Constants.Protocol.Esp,
                _rekeyChildInboundSpi, _rekeyChildOutboundSpi, _rekeyNonceInitiator, _rekeyNonceResponder,
                RekeyNegotiatedEsp.EncryptionKeyLengthBytes, RekeyNegotiatedEsp.SecondSliceLengthBytes);

        /// <summary>True if <paramref name="wire"/> is the Quick Mode reply for the rekey exchange currently in flight.</summary>
        public bool IsRekeyReply(byte[] wire)
        {
            if (_rekeyMessageId == 0) return false;
            IsakmpMessage header = IsakmpMessage.ReadHeader(wire, out _);
            return header.ExchangeType == IsakmpExchangeType.QuickMode && header.MessageId == _rekeyMessageId;
        }

        /// <summary>
        /// True if <paramref name="wire"/> is an ISAKMP message belonging to this SA — its initiator cookie (the first
        /// eight bytes, always in the clear even for an encrypted message) equals ours. A Phase 1 rekey runs a full Main
        /// Mode under a fresh client whose cookie differs from the live SA's, so the orchestrator uses this to steer the
        /// rekey's Main/Quick Mode replies apart from the live SA's steady-state DPD arriving on the same socket.
        /// </summary>
        public bool IsForThisSa(byte[] wire)
        {
            if (wire is null || wire.Length < InitiatorCookie.Length) return false;
            for (int i = 0; i < InitiatorCookie.Length; i++)
                if (wire[i] != InitiatorCookie[i]) return false;
            return true;
        }

        // The Quick Mode IDci/IDcr traffic selectors. For tunnel-mode remote access (Cisco IPsec / EzVPN) the client
        // proposes its assigned virtual IP as IDci (a /32 host) and a match-all 0.0.0.0/0 as IDcr, so the gateway
        // installs a tunnel-all CHILD SA. For transport mode (L2TP/IPsec) the original UDP/1701 endpoint identities
        // are used, exactly as before.
        IsakmpPayload QuickModeIdentity(bool local)
        {
            if (PreferTunnelMode)
            {
                return local
                    ? new IsakmpRawPayload(IsakmpPayloadType.Identification,
                        IdBody(IdTypeIpv4, 0, 0, (_modeConfigAddress ?? _localIdentity).GetAddressBytes()))
                    : new IsakmpRawPayload(IsakmpPayloadType.Identification,
                        IdBodySubnet(IPAddress.Any, IPAddress.Any)); // ID_IPV4_ADDR_SUBNET 0.0.0.0/0 = tunnel-all
            }
            IPAddress address = local ? _localIdentity : _remoteIdentity;
            return new IsakmpRawPayload(IsakmpPayloadType.Identification, IdBody(IdTypeIpv4, 17, 1701, address.GetAddressBytes()));
        }

        // ---- Transaction exchange: XAUTH (extended user authentication) + Mode-Config (pull virtual IP/DNS) ----

        IPAddress? _modeConfigAddress;
        IPAddress? _modeConfigNetmask;
        readonly List<IPAddress> _modeConfigDns = new();

        /// <summary>The virtual IP the gateway assigned via Mode-Config (INTERNAL_IP4_ADDRESS), or null until then.</summary>
        public IPAddress? AssignedAddress => _modeConfigAddress;

        /// <summary>The netmask the gateway pushed (INTERNAL_IP4_NETMASK), or null.</summary>
        public IPAddress? AssignedNetmask => _modeConfigNetmask;

        /// <summary>The DNS servers the gateway pushed (INTERNAL_IP4_DNS), in order.</summary>
        public IReadOnlyList<IPAddress> AssignedDns => _modeConfigDns;

        /// <summary>
        /// Parses the gateway's XAUTH CFG_REQUEST (a Transaction exchange asking for credentials) and builds the
        /// encrypted CFG_REPLY carrying the user name + password (RFC draft XAUTH §4). The CFG_REQUEST's identifier is
        /// echoed back so the gateway pairs request and reply; the XAUTH-TYPE (if present) is echoed unchanged. Throws
        /// <see cref="VpnServerRejectedException"/> if <paramref name="wire"/> is not an XAUTH CFG_REQUEST.
        /// </summary>
        public byte[] BuildXAuthReply(byte[] wire, string userName, string password)
        {
            IsakmpConfigPayload request = DecryptConfig(wire, expected: IsakmpCfgType.Request)
                ?? throw new VpnServerRejectedException("Expected an XAUTH CFG_REQUEST from the gateway.");

            var reply = new IsakmpConfigPayload { CfgType = IsakmpCfgType.Reply, Identifier = request.Identifier };
            // Echo the XAUTH-TYPE the gateway asked for (default Generic), then answer with the credentials.
            ushort xauthType = (ushort)(request.Find(IkeV1Constants.XAuthAttribute.Type)?.NumericValue ?? IkeV1Constants.XAuthType.Generic);
            reply.Attributes.Add(IsakmpAttribute.Tv(IkeV1Constants.XAuthAttribute.Type, xauthType));
            reply.Attributes.Add(IsakmpAttribute.Tlv(IkeV1Constants.XAuthAttribute.UserName, System.Text.Encoding.UTF8.GetBytes(userName)));
            reply.Attributes.Add(IsakmpAttribute.Tlv(IkeV1Constants.XAuthAttribute.UserPassword, System.Text.Encoding.UTF8.GetBytes(password)));
            _logger.LogProtocolStep(Layer, "XAUTH: CFG_REQUEST received, sending CFG_REPLY (user name + password)");
            // Echo the request's Message ID — XAUTH is a Transaction exchange; the reply shares the request's M-ID.
            return BuildTransaction(reply, IsakmpMessage.ReadHeader(wire, out _).MessageId);
        }

        /// <summary>
        /// Reads the gateway's XAUTH CFG_SET carrying the XAUTH-STATUS result and builds the CFG_ACK answering it. Sets
        /// <paramref name="success"/> to whether XAUTH succeeded (XAUTH-STATUS = OK). A SET whose identifier is echoed
        /// in the ACK so the gateway pairs them. Throws if <paramref name="wire"/> is not an XAUTH CFG_SET.
        /// </summary>
        public byte[] BuildXAuthAck(byte[] wire, out bool success)
        {
            IsakmpConfigPayload set = DecryptConfig(wire, expected: IsakmpCfgType.Set)
                ?? throw new VpnServerRejectedException("Expected an XAUTH CFG_SET (status) from the gateway.");
            success = (set.Find(IkeV1Constants.XAuthAttribute.Status)?.NumericValue ?? IkeV1Constants.XAuthStatus.Fail) == IkeV1Constants.XAuthStatus.Ok;

            var ack = new IsakmpConfigPayload { CfgType = IsakmpCfgType.Ack, Identifier = set.Identifier };
            ack.Attributes.Add(IsakmpAttribute.Tv(IkeV1Constants.XAuthAttribute.Status,
                success ? IkeV1Constants.XAuthStatus.Ok : IkeV1Constants.XAuthStatus.Fail));
            _logger.LogProtocolStep(Layer, success
                ? "XAUTH: CFG_SET status OK — sending CFG_ACK (extended authentication succeeded)"
                : "XAUTH: CFG_SET status FAIL — sending CFG_ACK (extended authentication failed)");
            // Echo the SET's Message ID — the ACK answers the server-initiated SET on the same Transaction exchange.
            return BuildTransaction(ack, IsakmpMessage.ReadHeader(wire, out _).MessageId);
        }

        /// <summary>
        /// True if <paramref name="wire"/> is an XAUTH CFG_SET (the status round), false for the Mode-Config CFG_REPLY.
        /// Lets the driver distinguish a gateway that interleaves XAUTH status with Mode-Config on the same channel.
        /// </summary>
        public bool IsXAuthSet(byte[] wire)
        {
            IsakmpConfigPayload? config = TryDecryptConfig(wire);
            return config is { CfgType: IsakmpCfgType.Set } && config.Has(IkeV1Constants.XAuthAttribute.Status);
        }

        /// <summary>
        /// Builds the Mode-Config CFG_REQUEST that pulls the virtual IP/DNS (draft-ietf-ipsec-isakmp-mode-cfg-04):
        /// empty INTERNAL_IP4_ADDRESS / NETMASK / DNS / NBNS attributes the gateway fills in its CFG_REPLY.
        /// </summary>
        public byte[] BuildModeConfigRequest()
        {
            var request = new IsakmpConfigPayload { CfgType = IsakmpCfgType.Request, Identifier = (ushort)RandomNonZeroUInt32() };
            request.Attributes.Add(IsakmpAttribute.Tlv(IkeV1Constants.ConfigAttribute.InternalIp4Address, Array.Empty<byte>()));
            request.Attributes.Add(IsakmpAttribute.Tlv(IkeV1Constants.ConfigAttribute.InternalIp4Netmask, Array.Empty<byte>()));
            request.Attributes.Add(IsakmpAttribute.Tlv(IkeV1Constants.ConfigAttribute.InternalIp4Dns, Array.Empty<byte>()));
            request.Attributes.Add(IsakmpAttribute.Tlv(IkeV1Constants.ConfigAttribute.InternalIp4Nbns, Array.Empty<byte>()));
            _logger.LogProtocolStep(Layer, "Mode-Config: sending CFG_REQUEST (pull virtual IP/netmask/DNS)");
            return BuildTransaction(request);
        }

        /// <summary>
        /// Parses the gateway's Mode-Config CFG_REPLY and captures the virtual IP (<see cref="AssignedAddress"/>),
        /// netmask and DNS (<see cref="AssignedDns"/>). Returns true if an INTERNAL_IP4_ADDRESS was assigned. Some
        /// gateways push the address in a server-initiated CFG_SET instead — that is accepted here too.
        /// </summary>
        public bool ProcessModeConfigReply(byte[] wire)
        {
            IsakmpConfigPayload? config = TryDecryptConfig(wire);
            if (config is null || (config.CfgType != IsakmpCfgType.Reply && config.CfgType != IsakmpCfgType.Set))
                return false;

            foreach (IsakmpAttribute attribute in config.Attributes)
            {
                switch (attribute.Type)
                {
                    case IkeV1Constants.ConfigAttribute.InternalIp4Address when attribute.LongValue.Length == 4:
                        _modeConfigAddress = new IPAddress(attribute.LongValue);
                        break;
                    case IkeV1Constants.ConfigAttribute.InternalIp4Netmask when attribute.LongValue.Length == 4:
                        _modeConfigNetmask = new IPAddress(attribute.LongValue);
                        break;
                    case IkeV1Constants.ConfigAttribute.InternalIp4Dns when attribute.LongValue.Length == 4:
                        _modeConfigDns.Add(new IPAddress(attribute.LongValue));
                        break;
                }
            }
            if (_modeConfigAddress != null && _logger.IsEnabled(LogLevel.Trace))
                _logger.LogProtocolStep(Layer,
                    $"Mode-Config: CFG_{config.CfgType} assigned virtual IP {_modeConfigAddress}" +
                    (_modeConfigDns.Count > 0 ? $", DNS {_modeConfigDns[0]}" : string.Empty));
            return _modeConfigAddress != null;
        }

        /// <summary>
        /// Builds the CFG_ACK answering a server-initiated Mode-Config CFG_SET (push model). Echoes the SET's
        /// identifier and the attribute types it carried (acknowledging the pushed configuration).
        /// </summary>
        public byte[] BuildModeConfigAck(byte[] wire)
        {
            IsakmpConfigPayload set = DecryptConfig(wire, expected: IsakmpCfgType.Set)
                ?? throw new VpnServerRejectedException("Expected a Mode-Config CFG_SET from the gateway.");
            var ack = new IsakmpConfigPayload { CfgType = IsakmpCfgType.Ack, Identifier = set.Identifier };
            foreach (IsakmpAttribute attribute in set.Attributes)
                ack.Attributes.Add(IsakmpAttribute.Tlv(attribute.Type, Array.Empty<byte>()));
            // Echo the SET's Message ID — the ACK answers the server-initiated SET on the same Transaction exchange.
            return BuildTransaction(ack, IsakmpMessage.ReadHeader(wire, out _).MessageId);
        }

        // Wraps a configuration payload in a HASH(1)-prefixed Transaction exchange under a fresh non-zero Message ID
        // (the same construction Quick Mode / Informational use): HASH = prf(SKEYID_a, M-ID | <Attribute payload>),
        // encrypted with the derived-IV cipher for that message id. Use only for a client-INITIATED Transaction
        // (Mode-Config CFG_REQUEST); a reply/ack to a server-initiated Transaction must echo the server's Message ID
        // (RFC 2408 §4.6 / §5.5 — a Transaction is a single exchange whose request and response share one M-ID), so use
        // the <see cref="BuildTransaction(IsakmpConfigPayload, uint)"/> overload there.
        byte[] BuildTransaction(IsakmpConfigPayload config) => BuildTransaction(config, RandomNonZeroUInt32());

        // Builds a HASH(1)-prefixed Transaction exchange under the given Message ID. The XAUTH CFG_REPLY/ACK and the
        // Mode-Config CFG_ACK MUST reuse the Message ID of the server-initiated request/set they answer — otherwise the
        // gateway treats the reply as a brand-new Transaction request (strongSwan: "queueing TRANSACTION request as
        // tasks still active" → "ignoring TRANSACTION request, queue full") and the XAUTH never completes.
        byte[] BuildTransaction(IsakmpConfigPayload config, uint messageId)
        {
            var afterHash = new List<IsakmpPayload> { config };
            var afterHashBytes = new List<byte>();
            IsakmpMessage.EncodePayloadChain(afterHashBytes, afterHash);
            byte[] hash = IkeV1QuickMode.ComputeHash1(_prf, _keys!.SkeyidA, messageId, afterHashBytes.ToArray());

            var inner = new List<IsakmpPayload> { new IsakmpRawPayload(IsakmpPayloadType.Hash, hash) };
            inner.AddRange(afterHash);
            // Reuse the cipher cached for this Transaction's Message ID so the CBC IV chains across the exchange
            // (RFC 2409 §5.5): a server-initiated XAUTH CFG_REQUEST advanced the IV when we decrypted it, so the
            // CFG_REPLY must encrypt from that advanced IV — NOT a freshly derived one — or the gateway fails to
            // decrypt it ("invalid HASH_V1 payload length, decryption failed?"). The first message under a new M-ID
            // (a client-initiated Mode-Config CFG_REQUEST) gets a freshly derived IV.
            return EncodeEncrypted(TransactionCipher(messageId), IsakmpExchangeType.Transaction, messageId, inner);
        }

        // Decrypts a Transaction message and returns its Attribute payload only if it matches the expected CfgType.
        IsakmpConfigPayload? DecryptConfig(byte[] wire, IsakmpCfgType expected)
        {
            IsakmpConfigPayload? config = TryDecryptConfig(wire);
            return config?.CfgType == expected ? config : null;
        }

        // Decrypts a Transaction message (or any encrypted exchange carrying an Attribute payload) and returns its
        // first Attribute payload, or null if it is not a decodable Transaction with one. Uses the cipher cached for
        // the message's M-ID so the IV chains across the exchange (the cached cipher then carries the advanced IV for
        // the reply built under the same M-ID).
        IsakmpConfigPayload? TryDecryptConfig(byte[] wire)
        {
            try
            {
                IsakmpMessage header = IsakmpMessage.ReadHeader(wire, out _);
                if (header.ExchangeType != IsakmpExchangeType.Transaction) return null;
                List<IsakmpPayload> payloads = DecryptWith(TransactionCipher(header.MessageId), wire, out _);
                return payloads.OfType<IsakmpConfigPayload>().FirstOrDefault();
            }
            catch { return null; }
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

            List<IsakmpPayload> payloads = DecryptWith(NewDerivedIvCipher(peek.MessageId), wire, out _);

            foreach (IsakmpRawPayload payload in payloads.OfType<IsakmpRawPayload>())
            {
                if (payload.Type == IsakmpPayloadType.Notification
                    && IkeV1Dpd.TryParseNotify(payload.Body, out ushort notifyType, out uint sequence))
                {
                    if (notifyType == IkeV1Dpd.RUThere)
                    {
                        if (_logger.IsEnabled(LogLevel.Trace))
                            _logger.LogProtocolStep(Layer, $"informational: DPD R-U-THERE seq={sequence}");
                        return new IkeV1InformationalResult(IkeV1InformationalKind.DpdRequest, sequence);
                    }
                    if (notifyType == IkeV1Dpd.RUThereAck)
                    {
                        if (_logger.IsEnabled(LogLevel.Trace))
                            _logger.LogProtocolStep(Layer, $"informational: DPD R-U-THERE-ACK seq={sequence}");
                        return new IkeV1InformationalResult(IkeV1InformationalKind.DpdAck, sequence);
                    }
                }
                else if (payload.Type == IsakmpPayloadType.Delete && payload.Body.Length >= 5)
                {
                    byte protocol = payload.Body[4]; // Delete body: DOI(4) | Protocol(1) | …
                    if (protocol == IkeV1Constants.Protocol.Esp)
                    {
                        _logger.LogProtocolStep(Layer, "informational: peer DELETE (ESP CHILD SA)");
                        return new IkeV1InformationalResult(IkeV1InformationalKind.DeleteEsp, 0);
                    }
                    if (protocol == IkeV1Constants.Protocol.Isakmp)
                    {
                        _logger.LogProtocolStep(Layer, "informational: peer DELETE (ISAKMP SA)");
                        return new IkeV1InformationalResult(IkeV1InformationalKind.DeleteIsakmp, 0);
                    }
                }
            }
            return new IkeV1InformationalResult(IkeV1InformationalKind.Unknown, 0);
        }

        // RFC 2408 §3.14: notify message types 1–16383 signal an error (NO-PROPOSAL-CHOSEN=14, INVALID-ID-INFORMATION=18,
        // AUTHENTICATION-FAILED=24…); 16384+ are status notifies (DPD R-U-THERE=36136, NAT-D, INITIAL-CONTACT…).
        const ushort MaxErrorNotifyType = 16383;

        /// <summary>
        /// Detects whether <paramref name="wire"/> is an unencrypted ISAKMP Informational carrying an error Notification —
        /// the way a gateway refuses a Main/Quick Mode exchange in the clear (e.g. NO-PROPOSAL-CHOSEN). Returns the notify
        /// type so a handshake caller can fail fast with a clear reason instead of mis-decoding it as the expected reply.
        /// Returns false for a normal (non-Informational) reply, a status notify (DPD…), or anything unparsable.
        /// </summary>
        public static bool TryReadRejectNotify(byte[] wire, out ushort notifyType)
        {
            notifyType = 0;
            if (wire is null || wire.Length < IsakmpMessage.HeaderSize) return false;

            IsakmpMessage header;
            IsakmpPayloadType first;
            try { header = IsakmpMessage.ReadHeader(wire, out first); }
            catch { return false; }
            if (header.ExchangeType != IsakmpExchangeType.Informational) return false;

            byte[] body = new byte[wire.Length - IsakmpMessage.HeaderSize];
            Buffer.BlockCopy(wire, IsakmpMessage.HeaderSize, body, 0, body.Length);
            var payloads = new List<IsakmpPayload>();
            try { IsakmpMessage.ParsePayloadChain(body, first, payloads); }
            catch { return false; }

            foreach (IsakmpRawPayload payload in payloads.OfType<IsakmpRawPayload>())
            {
                if (payload.Type == IsakmpPayloadType.Notification
                    && IkeV1Dpd.TryReadNotifyType(payload.Body, out ushort type)
                    && type >= 1 && type <= MaxErrorNotifyType)
                {
                    notifyType = type;
                    return true;
                }
            }
            return false;
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

        List<IsakmpPayload> DecryptWith(IkeV1Cipher cipher, byte[] wire, out byte[] plaintext)
        {
            IsakmpMessage.ReadHeader(wire, out IsakmpPayloadType first);
            byte[] ciphertext = new byte[wire.Length - IsakmpMessage.HeaderSize];
            Buffer.BlockCopy(wire, IsakmpMessage.HeaderSize, ciphertext, 0, ciphertext.Length);
            plaintext = cipher.Decrypt(ciphertext);

            var payloads = new List<IsakmpPayload>();
            IsakmpMessage.ParsePayloadChain(plaintext, first, payloads);
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

        IkeV1Cipher? _transactionCipher;
        uint _transactionCipherId;

        // Returns the CBC cipher for a Transaction (XAUTH / Mode-Config) Message ID, caching one instance per M-ID so
        // its IV chains across the request→reply→… messages of that exchange (RFC 2409 §5.5). The first time an M-ID is
        // seen the IV is freshly derived from the last Phase 1 IV; every later message under the same M-ID reuses the
        // advanced IV. A new M-ID (the next XAUTH round or the Mode-Config request) re-derives a fresh IV.
        IkeV1Cipher TransactionCipher(uint messageId)
        {
            if (_transactionCipher is null || _transactionCipherId != messageId)
            {
                byte[] iv = IkeV1Cipher.QuickModeIv(_hash, _phase1LastIv, messageId);
                _transactionCipher = new IkeV1Cipher(_keys!.CipherKey, iv);
                _transactionCipherId = messageId;
            }
            return _transactionCipher;
        }

        List<IsakmpPayload> DecryptMessage(byte[] wire, out IsakmpMessage header, out byte[] plaintext)
        {
            header = IsakmpMessage.ReadHeader(wire, out IsakmpPayloadType first);
            IkeV1Cipher cipher = header.ExchangeType == IsakmpExchangeType.QuickMode
                ? QuickModeCipher(header.MessageId, create: false)
                : _phase1Cipher!;

            byte[] ciphertext = new byte[wire.Length - IsakmpMessage.HeaderSize];
            Buffer.BlockCopy(wire, IsakmpMessage.HeaderSize, ciphertext, 0, ciphertext.Length);
            plaintext = cipher.Decrypt(ciphertext);

            var payloads = new List<IsakmpPayload>();
            IsakmpMessage.ParsePayloadChain(plaintext, first, payloads);
            return payloads;
        }

        // Verifies the responder's Quick Mode HASH(2) = prf(SKEYID_a, M-ID | Ni_b | <payloads after the HASH payload>)
        // (RFC 2409 §5.5). The "after-hash" bytes are sliced straight from the decrypted wire (PayloadChainAfterFirst),
        // never re-encoded from the parsed payloads, so a faithful gateway never trips on a codec round-trip difference —
        // only a genuinely wrong HASH(2) (tampering, or a SKEYID_a from the wrong PSK) fails.
        void VerifyQuickModeHash2(byte[] plaintext, List<IsakmpPayload> payloads, uint messageId, byte[] nonceInitiator)
        {
            IsakmpRawPayload? hash = payloads.OfType<IsakmpRawPayload>().FirstOrDefault(p => p.Type == IsakmpPayloadType.Hash);
            byte[] afterHash = PayloadChainAfterFirst(plaintext, IsakmpPayloadType.Hash);
            byte[] expected = IkeV1QuickMode.ComputeHash2(_prf, _keys!.SkeyidA, messageId, nonceInitiator, afterHash);
            if (hash is null || !FixedTimeEquals(expected, hash.Body))
                throw new VpnServerRejectedException("IKEv1 Quick Mode HASH(2) authentication failed (wrong PSK or tampered reply).");
        }

        // Returns the wire bytes of the payload chain that FOLLOW the first payload (the HASH payload), excluding the
        // zero-padding the CBC cipher leaves on the decrypted plaintext. Mirrors ParsePayloadChain's length walk: the
        // first payload's generic header carries its own length; everything from there to the end of the last declared
        // payload is the "message after hash" that HASH(1)/HASH(2) authenticate.
        static byte[] PayloadChainAfterFirst(byte[] plaintext, IsakmpPayloadType firstType)
        {
            int offset = 0;
            int afterFirst = -1;
            IsakmpPayloadType current = firstType;
            while (current != IsakmpPayloadType.None && offset + 4 <= plaintext.Length)
            {
                IsakmpPayloadType next = (IsakmpPayloadType)plaintext[offset];
                int length = (plaintext[offset + 2] << 8) | plaintext[offset + 3];
                if (length < 4 || offset + length > plaintext.Length) break;
                offset += length;
                if (afterFirst < 0) afterFirst = offset; // end of the first (HASH) payload
                current = next;
            }
            if (afterFirst < 0 || offset <= afterFirst) return Array.Empty<byte>();
            byte[] slice = new byte[offset - afterFirst];
            Buffer.BlockCopy(plaintext, afterFirst, slice, 0, slice.Length);
            return slice;
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

        const byte IdTypeIpv4Subnet = 4; // ID_IPV4_ADDR_SUBNET (RFC 2407 §4.6.2.1)

        // ID_IPV4_ADDR_SUBNET body: type/protocol/port header then address (4) + mask (4). 0.0.0.0/0.0.0.0 = tunnel-all.
        static byte[] IdBodySubnet(IPAddress address, IPAddress mask)
        {
            byte[] addressBytes = address.GetAddressBytes();
            byte[] maskBytes = mask.GetAddressBytes();
            byte[] body = new byte[4 + addressBytes.Length + maskBytes.Length];
            body[0] = IdTypeIpv4Subnet;
            Buffer.BlockCopy(addressBytes, 0, body, 4, addressBytes.Length);
            Buffer.BlockCopy(maskBytes, 0, body, 4 + addressBytes.Length, maskBytes.Length);
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
