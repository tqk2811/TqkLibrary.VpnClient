using System.Net;
using System.Security.Cryptography;
using TqkLibrary.VpnClient.Abstractions.Drivers;
using TqkLibrary.VpnClient.Crypto;
using TqkLibrary.VpnClient.Ipsec.Esp;
using TqkLibrary.VpnClient.Ipsec.Ike.V1;
using TqkLibrary.VpnClient.Ipsec.Ike.V1.Enums;
using TqkLibrary.VpnClient.Ipsec.Ike.V1.Models;
using TqkLibrary.VpnClient.Ipsec.Ike.V1.Payloads;
using Xunit;

namespace TqkLibrary.VpnClient.Ipsec.Ike.Tests
{
    /// <summary>
    /// Drives the real <see cref="IkeV1Client"/> through the Cisco IPsec / EzVPN remote-access flow in-process:
    /// Aggressive Mode (AG1→AG3, group PSK) → XAUTH (CFG_REQUEST/REPLY/SET/ACK) → Mode-Config (CFG_REQUEST/REPLY pulling
    /// the virtual IP/DNS) → Quick Mode (tunnel-mode ESP) against a hand-written <see cref="SimulatedCiscoResponder"/>,
    /// then both sides build ESP sessions and exchange a protected packet each direction. This pins the new
    /// Aggressive-Mode HASH_R/HASH_I auth, the Transaction-exchange HASH(1) + Attribute-payload codec (XAUTH attributes,
    /// Mode-Config INTERNAL_IP4_* attributes), and the tunnel-mode Quick Mode — offline before the live strongSwan run.
    /// </summary>
    public class IkeV1CiscoIpsecTests
    {
        static readonly byte[] GroupPsk = System.Text.Encoding.ASCII.GetBytes("groupsecret");
        const string GroupName = "vpngroup";
        const string XAuthUser = "testuser";
        const string XAuthPass = "testpass";

        [Fact]
        public void FullCiscoFlow_Aggressive_XAuth_ModeConfig_QuickMode_ThenEspExchange_Succeeds()
        {
            var client = new IkeV1Client(GroupPsk, IPAddress.Any, IPAddress.Any) { PreferTunnelMode = true };
            client.SetAggressiveIdentity(11 /* KEY_ID */, System.Text.Encoding.ASCII.GetBytes(GroupName));
            var responder = new SimulatedCiscoResponder(GroupPsk, client.InitiatorCookie);

            // --- Aggressive Mode ---
            byte[] ag1 = client.BuildAggressive1();
            byte[] ag2 = responder.HandleAggressive1(ag1);
            Assert.True(client.ProcessAggressive2(ag2)); // verifies HASH_R, derives keys
            byte[] ag3 = client.BuildAggressive3();
            responder.HandleAggressive3(ag3);            // verifies HASH_I

            // --- XAUTH ---
            byte[] xauthRequest = responder.BuildXAuthRequest();
            byte[] xauthReply = client.BuildXAuthReply(xauthRequest, XAuthUser, XAuthPass);
            (string user, string pass) = responder.ReadXAuthReply(xauthReply);
            Assert.Equal(XAuthUser, user);
            Assert.Equal(XAuthPass, pass);

            byte[] xauthSet = responder.BuildXAuthSet(ok: true);
            byte[] xauthAck = client.BuildXAuthAck(xauthSet, out bool xauthOk);
            Assert.True(xauthOk);
            Assert.True(responder.ReadXAuthAck(xauthAck)); // ACK status OK

            // --- Mode-Config (pull) ---
            byte[] cfgRequest = client.BuildModeConfigRequest();
            byte[] cfgReply = responder.HandleModeConfigRequest(cfgRequest,
                IPAddress.Parse("10.10.0.5"), IPAddress.Parse("255.255.255.0"), IPAddress.Parse("8.8.8.8"));
            Assert.True(client.ProcessModeConfigReply(cfgReply));
            Assert.Equal(IPAddress.Parse("10.10.0.5"), client.AssignedAddress);
            Assert.Equal(IPAddress.Parse("255.255.255.0"), client.AssignedNetmask);
            Assert.Equal(IPAddress.Parse("8.8.8.8"), client.AssignedDns[0]);

            // --- Quick Mode (tunnel mode ESP) ---
            byte[] qm1 = client.BuildQuickMode1();
            byte[] qm2 = responder.HandleQuickMode1(qm1);
            Assert.True(client.ProcessQuickMode2(qm2));
            byte[] qm3 = client.BuildQuickMode3();
            responder.HandleQuickMode3(qm3);

            // SPI orientation matches the SimulatedResponderV1 contract.
            Assert.Equal(responder.ChildInboundSpi, client.ChildOutboundSpi);
            Assert.Equal(client.ChildInboundSpi, responder.ChildOutboundSpi);

            // --- ESP data plane both directions ---
            IkeV1Phase2Keys c = client.CreatePhase2Keys();
            IkeV1Phase2Keys r = responder.CreatePhase2Keys();
            Assert.Equal(c.OutboundEncryption, r.InboundEncryption);

            EspSession clientEsp = new(
                ToSpi(client.ChildOutboundSpi), EspCipherSuite.AesCbcHmacSha1(c.OutboundEncryption, c.OutboundIntegrity),
                ToSpi(client.ChildInboundSpi), EspCipherSuite.AesCbcHmacSha1(c.InboundEncryption, c.InboundIntegrity));
            EspSession responderEsp = new(
                ToSpi(client.ChildInboundSpi), EspCipherSuite.AesCbcHmacSha1(r.OutboundEncryption, r.OutboundIntegrity),
                ToSpi(responder.ChildInboundSpi), EspCipherSuite.AesCbcHmacSha1(r.InboundEncryption, r.InboundIntegrity));

            byte[] toServer = clientEsp.Protect(System.Text.Encoding.ASCII.GetBytes("cisco ping"));
            Assert.True(responderEsp.TryUnprotect(toServer, out byte[] gotByServer, out _));
            Assert.Equal("cisco ping", System.Text.Encoding.ASCII.GetString(gotByServer));
            byte[] toClient = responderEsp.Protect(System.Text.Encoding.ASCII.GetBytes("cisco pong"));
            Assert.True(clientEsp.TryUnprotect(toClient, out byte[] gotByClient, out _));
            Assert.Equal("cisco pong", System.Text.Encoding.ASCII.GetString(gotByClient));
        }

        [Fact]
        public void Aggressive2_WrongGroupPsk_ProcessAggressive2ReturnsFalse()
        {
            var client = new IkeV1Client(GroupPsk, IPAddress.Any, IPAddress.Any) { PreferTunnelMode = true };
            client.SetAggressiveIdentity(11, System.Text.Encoding.ASCII.GetBytes(GroupName));
            // The responder authenticates HASH_R with a DIFFERENT PSK ⇒ the client's HASH_R check must fail.
            var responder = new SimulatedCiscoResponder(System.Text.Encoding.ASCII.GetBytes("wrong"), client.InitiatorCookie);

            byte[] ag2 = responder.HandleAggressive1(client.BuildAggressive1());
            Assert.False(client.ProcessAggressive2(ag2));
        }

        [Fact]
        public void XAuthAck_WhenServerStatusFail_ReportsFailure()
        {
            var client = new IkeV1Client(GroupPsk, IPAddress.Any, IPAddress.Any) { PreferTunnelMode = true };
            var responder = new SimulatedCiscoResponder(GroupPsk, client.InitiatorCookie);
            DriveThroughAggressive(client, responder);

            client.BuildXAuthReply(responder.BuildXAuthRequest(), XAuthUser, XAuthPass);
            byte[] set = responder.BuildXAuthSet(ok: false);
            client.BuildXAuthAck(set, out bool ok);
            Assert.False(ok);
        }

        [Fact]
        public void ModeConfigReply_AcceptedFromServerInitiatedSet_AsWellAsReply()
        {
            // Some gateways push the address in a CFG_SET rather than answering the pull with a CFG_REPLY; both work.
            var client = new IkeV1Client(GroupPsk, IPAddress.Any, IPAddress.Any) { PreferTunnelMode = true };
            var responder = new SimulatedCiscoResponder(GroupPsk, client.InitiatorCookie);
            DriveThroughAggressive(client, responder);

            byte[] set = responder.BuildModeConfigSet(IPAddress.Parse("172.16.0.9"), IPAddress.Parse("255.255.0.0"), IPAddress.Parse("1.1.1.1"));
            Assert.True(client.ProcessModeConfigReply(set));
            Assert.Equal(IPAddress.Parse("172.16.0.9"), client.AssignedAddress);
        }

        [Fact]
        public void ConfigPayload_RoundTrips_XAuthAndModeConfigAttributes()
        {
            // Pin the Attribute-payload codec independent of the cipher: a REPLY with a TV XAUTH-STATUS, a TLV user
            // name, and a 4-byte Mode-Config address must survive a write→parse round trip byte-for-byte.
            var payload = new IsakmpConfigPayload { CfgType = IsakmpCfgType.Reply, Identifier = 0xABCD };
            payload.Attributes.Add(IsakmpAttribute.Tv(IkeV1Constants.XAuthAttribute.Status, IkeV1Constants.XAuthStatus.Ok));
            payload.Attributes.Add(IsakmpAttribute.Tlv(IkeV1Constants.XAuthAttribute.UserName, System.Text.Encoding.ASCII.GetBytes("bob")));
            payload.Attributes.Add(IsakmpAttribute.Tlv(IkeV1Constants.ConfigAttribute.InternalIp4Address, IPAddress.Parse("10.0.0.7").GetAddressBytes()));

            var body = new List<byte>();
            payload.WriteBody(body);
            IsakmpConfigPayload parsed = IsakmpConfigPayload.Parse(body.ToArray());

            Assert.Equal(IsakmpCfgType.Reply, parsed.CfgType);
            Assert.Equal(0xABCD, parsed.Identifier);
            Assert.Equal(IkeV1Constants.XAuthStatus.Ok, (ushort)parsed.Find(IkeV1Constants.XAuthAttribute.Status)!.NumericValue);
            Assert.Equal("bob", System.Text.Encoding.ASCII.GetString(parsed.Find(IkeV1Constants.XAuthAttribute.UserName)!.LongValue));
            Assert.Equal(IPAddress.Parse("10.0.0.7"), new IPAddress(parsed.Find(IkeV1Constants.ConfigAttribute.InternalIp4Address)!.LongValue));
        }

        static void DriveThroughAggressive(IkeV1Client client, SimulatedCiscoResponder responder)
        {
            client.SetAggressiveIdentity(11, System.Text.Encoding.ASCII.GetBytes(GroupName));
            Assert.True(client.ProcessAggressive2(responder.HandleAggressive1(client.BuildAggressive1())));
            responder.HandleAggressive3(client.BuildAggressive3());
        }

        static uint ToSpi(byte[] spi) => (uint)((spi[0] << 24) | (spi[1] << 16) | (spi[2] << 8) | spi[3]);

        static byte[] Bytes(byte seed, int length)
        {
            byte[] b = new byte[length];
            for (int i = 0; i < length; i++) b[i] = (byte)(seed + i);
            return b;
        }

        /// <summary>
        /// A minimal in-process Cisco IPsec / EzVPN gateway used only to validate the real client: Aggressive Mode
        /// responder + XAUTH server + Mode-Config provider + tunnel-mode Quick Mode responder. It hand-rolls ISAKMP
        /// framing (the codec chain helpers are internal) and reuses the public crypto helpers.
        /// </summary>
        sealed class SimulatedCiscoResponder
        {
            const byte IdTypeIpv4 = 1;

            readonly byte[] _psk;
            readonly HashAlgorithmName _hash = HashAlgorithmName.SHA1;
            readonly HmacPrf _prf = new(HashAlgorithmName.SHA1);
            readonly ModpDhGroup _dh = ModpDhGroup.Group2(); // AG offers MODP-1024 (group 2)
            readonly byte[] _cookieI;
            readonly byte[] _cookieR = Bytes(0x90, 8);
            readonly byte[] _privateKey;
            readonly byte[] _keResponder;
            readonly byte[] _nonceResponder = Bytes(0x40, 16);

            byte[] _keInitiator = Array.Empty<byte>();
            byte[] _nonceInitiator = Array.Empty<byte>();
            byte[] _saInitiatorBody = Array.Empty<byte>();
            byte[] _idInitiatorBody = Array.Empty<byte>();
            IkeV1KeyMaterial? _keys;
            IkeV1Cipher? _phase1Cipher;
            byte[] _phase1LastIv = Array.Empty<byte>();

            uint _quickModeId;
            IkeV1Cipher? _quickModeCipher;
            byte[] _quickModeNonceInitiator = Array.Empty<byte>();

            public SimulatedCiscoResponder(byte[] psk, byte[] initiatorCookie)
            {
                _psk = psk;
                _cookieI = initiatorCookie;
                _privateKey = _dh.GeneratePrivateKey();
                _keResponder = _dh.DerivePublicValue(_privateKey);
                ChildInboundSpi = new byte[] { 0x51, 0x52, 0x53, 0x54 };
            }

            public byte[] ChildInboundSpi { get; }
            public byte[] ChildOutboundSpi { get; private set; } = Array.Empty<byte>();

            // ---- Aggressive Mode ----

            public byte[] HandleAggressive1(byte[] ag1)
            {
                IsakmpMessage request = IsakmpMessage.Decode(ag1);
                _saInitiatorBody = IkeV1Proposals.Phase1Aggressive(IkeV1Constants.Group.Modp1024).BodyBytes();
                _keInitiator = request.FindRaw(IsakmpPayloadType.KeyExchange)!.Body;
                _nonceInitiator = request.FindRaw(IsakmpPayloadType.Nonce)!.Body;
                _idInitiatorBody = request.FindRaw(IsakmpPayloadType.Identification)!.Body;

                // Echo the first transform.
                IsakmpProposal clientProposal = request.Find<IsakmpSaPayload>()!.Proposals[0];
                IsakmpTransform first = clientProposal.Transforms[0];
                var chosenProposal = new IsakmpProposal { Number = clientProposal.Number, ProtocolId = clientProposal.ProtocolId, Spi = clientProposal.Spi };
                var chosenTransform = new IsakmpTransform(first.Number, first.TransformId);
                foreach (IsakmpAttribute a in first.Attributes) chosenTransform.Attributes.Add(a);
                chosenProposal.Transforms.Add(chosenTransform);
                var sa = new IsakmpSaPayload();
                sa.Proposals.Add(chosenProposal);

                byte[] shared = _dh.DeriveSharedSecret(_privateKey, _keInitiator);
                _keys = IkeV1KeyMaterial.DeriveMainMode(_hash, _psk, _nonceInitiator, _nonceResponder, shared,
                    _cookieI, _cookieR, _keInitiator, _keResponder, cipherKeyLength: 32, blockSize: 16);
                _phase1Cipher = new IkeV1Cipher(_keys.CipherKey, _keys.InitialIv);

                byte[] idrBody = IdBody(IdTypeIpv4, 0, 0, IPAddress.Parse("203.0.113.1").GetAddressBytes());
                byte[] hashR = IkeV1Auth.ComputeHashR(_prf, _keys.Skeyid, _keInitiator, _keResponder, _cookieI, _cookieR, _saInitiatorBody, idrBody);

                var payloads = new List<IsakmpPayload>
                {
                    sa,
                    new IsakmpRawPayload(IsakmpPayloadType.KeyExchange, _keResponder),
                    new IsakmpRawPayload(IsakmpPayloadType.Nonce, _nonceResponder),
                    new IsakmpRawPayload(IsakmpPayloadType.Identification, idrBody),
                    new IsakmpRawPayload(IsakmpPayloadType.Hash, hashR),
                    new IsakmpRawPayload(IsakmpPayloadType.VendorId, IkeV1NatDetection.VendorIdRfc3947),
                    new IsakmpRawPayload(IsakmpPayloadType.VendorId, IkeV1NatDetection.VendorIdXAuth),
                };
                return EncodeClear(IsakmpExchangeType.Aggressive, 0, payloads);
            }

            public void HandleAggressive3(byte[] ag3)
            {
                List<IsakmpPayload> payloads = DecryptChain(_phase1Cipher!, ag3);
                byte[] hashI = Raw(payloads, IsakmpPayloadType.Hash);
                byte[] expected = IkeV1Auth.ComputeHashI(_prf, _keys!.Skeyid, _keInitiator, _keResponder, _cookieI, _cookieR, _saInitiatorBody, _idInitiatorBody);
                Assert.Equal(expected, hashI);
                _phase1LastIv = _phase1Cipher!.CurrentIv;
            }

            // ---- XAUTH ----

            public byte[] BuildXAuthRequest()
            {
                var request = new IsakmpConfigPayload { CfgType = IsakmpCfgType.Request, Identifier = 0x1001 };
                request.Attributes.Add(IsakmpAttribute.Tv(IkeV1Constants.XAuthAttribute.Type, IkeV1Constants.XAuthType.Generic));
                request.Attributes.Add(IsakmpAttribute.Tlv(IkeV1Constants.XAuthAttribute.UserName, Array.Empty<byte>()));
                request.Attributes.Add(IsakmpAttribute.Tlv(IkeV1Constants.XAuthAttribute.UserPassword, Array.Empty<byte>()));
                return BuildTransaction(request);
            }

            public (string, string) ReadXAuthReply(byte[] wire)
            {
                IsakmpConfigPayload reply = Config(wire);
                string user = System.Text.Encoding.UTF8.GetString(reply.Find(IkeV1Constants.XAuthAttribute.UserName)!.LongValue);
                string pass = System.Text.Encoding.UTF8.GetString(reply.Find(IkeV1Constants.XAuthAttribute.UserPassword)!.LongValue);
                return (user, pass);
            }

            public byte[] BuildXAuthSet(bool ok)
            {
                var set = new IsakmpConfigPayload { CfgType = IsakmpCfgType.Set, Identifier = 0x1002 };
                set.Attributes.Add(IsakmpAttribute.Tv(IkeV1Constants.XAuthAttribute.Status,
                    ok ? IkeV1Constants.XAuthStatus.Ok : IkeV1Constants.XAuthStatus.Fail));
                return BuildTransaction(set);
            }

            public bool ReadXAuthAck(byte[] wire)
            {
                IsakmpConfigPayload ack = Config(wire);
                Assert.Equal(IsakmpCfgType.Ack, ack.CfgType);
                return (ack.Find(IkeV1Constants.XAuthAttribute.Status)?.NumericValue ?? 0) == IkeV1Constants.XAuthStatus.Ok;
            }

            // ---- Mode-Config ----

            public byte[] HandleModeConfigRequest(byte[] wire, IPAddress address, IPAddress netmask, IPAddress dns)
            {
                IsakmpConfigPayload request = Config(wire);
                Assert.Equal(IsakmpCfgType.Request, request.CfgType);
                var reply = new IsakmpConfigPayload { CfgType = IsakmpCfgType.Reply, Identifier = request.Identifier };
                reply.Attributes.Add(IsakmpAttribute.Tlv(IkeV1Constants.ConfigAttribute.InternalIp4Address, address.GetAddressBytes()));
                reply.Attributes.Add(IsakmpAttribute.Tlv(IkeV1Constants.ConfigAttribute.InternalIp4Netmask, netmask.GetAddressBytes()));
                reply.Attributes.Add(IsakmpAttribute.Tlv(IkeV1Constants.ConfigAttribute.InternalIp4Dns, dns.GetAddressBytes()));
                return BuildTransaction(reply);
            }

            public byte[] BuildModeConfigSet(IPAddress address, IPAddress netmask, IPAddress dns)
            {
                var set = new IsakmpConfigPayload { CfgType = IsakmpCfgType.Set, Identifier = 0x2001 };
                set.Attributes.Add(IsakmpAttribute.Tlv(IkeV1Constants.ConfigAttribute.InternalIp4Address, address.GetAddressBytes()));
                set.Attributes.Add(IsakmpAttribute.Tlv(IkeV1Constants.ConfigAttribute.InternalIp4Netmask, netmask.GetAddressBytes()));
                set.Attributes.Add(IsakmpAttribute.Tlv(IkeV1Constants.ConfigAttribute.InternalIp4Dns, dns.GetAddressBytes()));
                return BuildTransaction(set);
            }

            // ---- Quick Mode (tunnel mode) ----

            public byte[] HandleQuickMode1(byte[] qm1)
            {
                _quickModeId = IsakmpMessage.Decode(qm1).MessageId;
                _quickModeCipher = NewQuickModeCipher(_quickModeId);
                List<IsakmpPayload> payloads = DecryptChain(_quickModeCipher, qm1);
                IsakmpSaPayload sa = payloads.OfType<IsakmpSaPayload>().First();
                ChildOutboundSpi = sa.Proposals[0].Spi;
                _quickModeNonceInitiator = Raw(payloads, IsakmpPayloadType.Nonce);

                var afterHash = new List<IsakmpPayload> { BuildSelectedEspSa(), new IsakmpRawPayload(IsakmpPayloadType.Nonce, _nonceResponder) };
                byte[] afterHashBytes = EncodeChain(afterHash);
                byte[] hash2 = IkeV1QuickMode.ComputeHash2(_prf, _keys!.SkeyidA, _quickModeId, _quickModeNonceInitiator, afterHashBytes);
                var inner = new List<IsakmpPayload> { new IsakmpRawPayload(IsakmpPayloadType.Hash, hash2) };
                inner.AddRange(afterHash);
                return EncodeEncrypted(_quickModeCipher, IsakmpExchangeType.QuickMode, _quickModeId, inner);
            }

            public void HandleQuickMode3(byte[] qm3)
            {
                List<IsakmpPayload> payloads = DecryptChain(_quickModeCipher!, qm3);
                byte[] hash3 = Raw(payloads, IsakmpPayloadType.Hash);
                byte[] expected = IkeV1QuickMode.ComputeHash3(_prf, _keys!.SkeyidA, _quickModeId, _quickModeNonceInitiator, _nonceResponder);
                Assert.Equal(expected, hash3);
            }

            public IkeV1Phase2Keys CreatePhase2Keys()
                => IkeV1Phase2Keys.Derive(_prf, _keys!.SkeyidD, IkeV1Constants.Protocol.Esp,
                    ChildInboundSpi, ChildOutboundSpi, _quickModeNonceInitiator, _nonceResponder, 32, 20);

            IsakmpSaPayload BuildSelectedEspSa()
            {
                var transform = new IsakmpTransform(1, IkeV1Constants.EspTransform.Aes)
                    .With(IsakmpAttribute.Tv(IkeV1Constants.Phase2Attribute.KeyLength, 256))
                    .With(IsakmpAttribute.Tv(IkeV1Constants.Phase2Attribute.AuthAlgorithm, IkeV1Constants.AuthAlgorithm.HmacSha1))
                    .With(IsakmpAttribute.Tv(IkeV1Constants.Phase2Attribute.EncapsulationMode, IkeV1Constants.EncapsulationMode.UdpTunnel));
                var proposal = new IsakmpProposal { Number = 1, ProtocolId = IkeV1Constants.Protocol.Esp, Spi = ChildInboundSpi };
                proposal.Transforms.Add(transform);
                var sa = new IsakmpSaPayload();
                sa.Proposals.Add(proposal);
                return sa;
            }

            // ---- framing helpers (hand-rolled; codec chain helpers are internal) ----

            IsakmpConfigPayload Config(byte[] wire)
            {
                uint messageId = IsakmpMessage.Decode(wire).MessageId;
                // Chain the IV across the Transaction exchange the way a real gateway (strongSwan) does: the cipher this
                // M-ID is cached under already advanced its IV when this side encrypted the CFG_REQUEST/SET, so the reply
                // decrypts from that advanced IV — re-deriving the IV here is what the old self-pair test got wrong and
                // the live strongSwan run exposed ("invalid HASH_V1 payload length, decryption failed?").
                List<IsakmpPayload> payloads = DecryptChain(TransactionCipher(messageId), wire);
                return payloads.OfType<IsakmpConfigPayload>().First();
            }

            byte[] BuildTransaction(IsakmpConfigPayload config)
            {
                uint messageId = 0x33445566u + (uint)config.Identifier;
                var afterHash = new List<IsakmpPayload> { config };
                byte[] hash = IkeV1QuickMode.ComputeHash1(_prf, _keys!.SkeyidA, messageId, EncodeChain(afterHash));
                var inner = new List<IsakmpPayload> { new IsakmpRawPayload(IsakmpPayloadType.Hash, hash) };
                inner.AddRange(afterHash);
                return EncodeEncrypted(TransactionCipher(messageId), IsakmpExchangeType.Transaction, messageId, inner);
            }

            IkeV1Cipher NewQuickModeCipher(uint messageId)
                => new IkeV1Cipher(_keys!.CipherKey, IkeV1Cipher.QuickModeIv(_hash, _phase1LastIv, messageId));

            // One cipher per Transaction M-ID, cached so the CBC IV chains across the request→reply messages of the
            // exchange (RFC 2409 §5.5) — the first message under an M-ID derives a fresh IV, later ones reuse it.
            readonly Dictionary<uint, IkeV1Cipher> _transactionCiphers = new();
            IkeV1Cipher TransactionCipher(uint messageId)
            {
                if (!_transactionCiphers.TryGetValue(messageId, out IkeV1Cipher? cipher))
                {
                    cipher = new IkeV1Cipher(_keys!.CipherKey, IkeV1Cipher.QuickModeIv(_hash, _phase1LastIv, messageId));
                    _transactionCiphers[messageId] = cipher;
                }
                return cipher;
            }

            byte[] EncodeClear(IsakmpExchangeType exchange, uint messageId, List<IsakmpPayload> payloads)
                => Frame(exchange, IsakmpFlags.None, messageId, payloads[0].Type, EncodeChain(payloads));

            byte[] EncodeEncrypted(IkeV1Cipher cipher, IsakmpExchangeType exchange, uint messageId, List<IsakmpPayload> payloads)
                => Frame(exchange, IsakmpFlags.Encryption, messageId, payloads[0].Type, cipher.Encrypt(EncodeChain(payloads)));

            byte[] Frame(IsakmpExchangeType exchange, IsakmpFlags flags, uint messageId, IsakmpPayloadType firstPayload, byte[] body)
            {
                int totalLength = IsakmpMessage.HeaderSize + body.Length;
                byte[] wire = new byte[totalLength];
                Buffer.BlockCopy(_cookieI, 0, wire, 0, 8);
                Buffer.BlockCopy(_cookieR, 0, wire, 8, 8);
                wire[16] = (byte)firstPayload;
                wire[17] = IsakmpMessage.Version10;
                wire[18] = (byte)exchange;
                wire[19] = (byte)flags;
                wire[20] = (byte)(messageId >> 24); wire[21] = (byte)(messageId >> 16);
                wire[22] = (byte)(messageId >> 8); wire[23] = (byte)messageId;
                wire[24] = (byte)(totalLength >> 24); wire[25] = (byte)(totalLength >> 16);
                wire[26] = (byte)(totalLength >> 8); wire[27] = (byte)totalLength;
                Buffer.BlockCopy(body, 0, wire, IsakmpMessage.HeaderSize, body.Length);
                return wire;
            }

            static byte[] EncodeChain(List<IsakmpPayload> payloads)
            {
                var output = new List<byte>();
                for (int i = 0; i < payloads.Count; i++)
                {
                    IsakmpPayloadType next = i + 1 < payloads.Count ? payloads[i + 1].Type : IsakmpPayloadType.None;
                    int start = output.Count;
                    output.Add((byte)next);
                    output.Add(0);
                    output.Add(0); output.Add(0);
                    payloads[i].WriteBody(output);
                    int length = output.Count - start;
                    output[start + 2] = (byte)(length >> 8);
                    output[start + 3] = (byte)length;
                }
                return output.ToArray();
            }

            List<IsakmpPayload> ParseChain(byte[] body, IsakmpPayloadType firstType)
            {
                byte[] cleartext = Frame(IsakmpExchangeType.Transaction, IsakmpFlags.None, 0, firstType, body);
                return IsakmpMessage.Decode(cleartext).Payloads;
            }

            List<IsakmpPayload> DecryptChain(IkeV1Cipher cipher, byte[] wire)
            {
                var firstType = (IsakmpPayloadType)wire[16];
                byte[] ciphertext = new byte[wire.Length - IsakmpMessage.HeaderSize];
                Buffer.BlockCopy(wire, IsakmpMessage.HeaderSize, ciphertext, 0, ciphertext.Length);
                byte[] plain = cipher.Decrypt(ciphertext);
                return ParseChain(plain, firstType);
            }

            static byte[] Raw(List<IsakmpPayload> payloads, IsakmpPayloadType type)
                => payloads.OfType<IsakmpRawPayload>().First(p => p.Type == type).Body;

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
        }
    }
}
