using System.Net;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using TqkLibrary.VpnClient.Abstractions.Drivers;
using TqkLibrary.VpnClient.Crypto;
using TqkLibrary.VpnClient.Ipsec.Esp;
using TqkLibrary.VpnClient.Ipsec.Ike.V2.Eap;
using TqkLibrary.VpnClient.Ipsec.Ike.V2.Enums;
using TqkLibrary.VpnClient.Ipsec.Ike.V2.Models;
using TqkLibrary.VpnClient.Ipsec.Ike.V2.Payloads;

namespace TqkLibrary.VpnClient.Ipsec.Ike.V2
{
    /// <summary>
    /// The initiator-side IKEv2 client for PSK authentication: drives IKE_SA_INIT then IKE_AUTH, verifies the
    /// responder's AUTH, and exposes the negotiated CHILD_SA SPIs and keys for the ESP data plane to consume.
    /// Pure protocol logic — the caller owns the UDP transport.
    /// </summary>
    public sealed class IkeClient
    {
        readonly HmacPrf _prf = HmacPrf.Sha256();
        readonly IkeSaInitiator _initiator;
        readonly byte[] _preSharedKey;
        readonly IdentificationPayload _identity;
        readonly bool _requestTransportMode;
        readonly bool _requestConfiguration;
        readonly string? _eapUserName;
        readonly string? _eapPassword;
        readonly IkeCertificateTrust? _responderTrust;
        readonly IReadOnlyList<TrafficSelector>? _initiatorSelectors;
        readonly IReadOnlyList<TrafficSelector>? _responderSelectors;

        IkeCipher? _cipher;
        uint _nextMessageId = 2; // IKE_SA_INIT=0, IKE_AUTH=1; post-auth exchanges start here.

        // The "current" IKE SA identity used for post-auth message headers and CHILD_SA keying. These start as the
        // SPIs/SK_d derived in IKE_SA_INIT and are swapped wholesale when the IKE SA is rekeyed (CREATE_CHILD_SA,
        // RFC 7296 §2.18) — so DPD/DELETE/child-rekey after a rekey ride the new SA without touching the init state.
        byte[] _currentInitiatorSpi;
        byte[] _currentResponderSpi = new byte[8];
        byte[]? _currentSkD;
        IkeKeyMaterial? _currentKeys;

        // EAP (RFC 7296 §2.16) state: the running method, the responder's RestOfIDr cached from the first response
        // (for the final MSK-based responder-AUTH check), and the IKE_AUTH message-ID counter for the EAP rounds.
        EapMsChapV2Client? _eap;
        byte[]? _eapResponderIdBody;
        uint _eapMessageId;
        bool _eapStarted;

        /// <summary>
        /// Creates a client with the given PSK and IDi. <paramref name="requestTransportMode"/> asks for ESP
        /// transport mode (L2TP); <paramref name="requestConfiguration"/> attaches a CFG_REQUEST so the gateway
        /// assigns a virtual IP/DNS (tunnel mode, IKEv2-native). The two are mutually exclusive in practice —
        /// transport mode keeps the host's address, tunnel mode pulls one.
        /// <para>When <paramref name="responderTrust"/> is supplied, the client sends a CERTREQ in IKE_AUTH and accepts
        /// a responder that authenticates with a <em>digital signature</em> (RFC 7296 §2.15): it validates the CERT the
        /// gateway returns against the trust and verifies the AUTH signature with that certificate's public key (a PSK
        /// AUTH from the gateway is still accepted as a fallback). <paramref name="initiatorSelectors"/> /
        /// <paramref name="responderSelectors"/> offer several traffic selectors (multiple subnets, RFC 7296 §3.13);
        /// null/empty offers the usual single "match all IPv4" selector.</para>
        /// </summary>
        public IkeClient(byte[] preSharedKey, IdentificationPayload identity, bool requestTransportMode = true,
            byte[]? initiatorSpi = null, bool requestConfiguration = false,
            string? eapUserName = null, string? eapPassword = null,
            IkeCertificateTrust? responderTrust = null,
            IReadOnlyList<TrafficSelector>? initiatorSelectors = null,
            IReadOnlyList<TrafficSelector>? responderSelectors = null)
        {
            _preSharedKey = preSharedKey;
            _identity = identity;
            _requestTransportMode = requestTransportMode;
            _requestConfiguration = requestConfiguration;
            _eapUserName = eapUserName;
            _eapPassword = eapPassword;
            _responderTrust = responderTrust;
            _initiatorSelectors = initiatorSelectors;
            _responderSelectors = responderSelectors;
            _initiator = new IkeSaInitiator(initiatorSpi);
            _currentInitiatorSpi = _initiator.InitiatorSpi;
            ChildInboundSpi = RandomSpi();
        }

        /// <summary>The certificate the responder presented in IKE_AUTH (digital-signature auth), or null for PSK.</summary>
        public X509Certificate2? ResponderCertificate { get; private set; }

        // Builds the TSi/TSr pair — the configured multi-selector list, or the single match-all default.
        TrafficSelectorPayload BuildInitiatorTs() => TrafficSelectorPayload.Multiple(isInitiator: true, _initiatorSelectors);
        TrafficSelectorPayload BuildResponderTs() => TrafficSelectorPayload.Multiple(isInitiator: false, _responderSelectors);

        /// <summary>The ESP SPI we chose (the peer uses it when sending to us). Updated after a CHILD_SA rekey.</summary>
        public byte[] ChildInboundSpi { get; private set; }

        /// <summary>The ESP SPI the responder chose (we use it when sending to the peer).</summary>
        public byte[] ChildOutboundSpi { get; private set; } = Array.Empty<byte>();

        /// <summary>The CHILD_SA keys, valid after a successful <see cref="ProcessAuthResponse"/>.</summary>
        public ChildSaKeys? ChildKeys { get; private set; }

        /// <summary>The ESP suite the responder selected in IKE_AUTH, valid after a successful <see cref="ProcessAuthResponse"/>.</summary>
        public EspSuiteSelection? NegotiatedEsp { get; private set; }

        /// <summary>
        /// The Configuration Payload the responder returned (virtual IP/DNS), or null when none was requested or sent.
        /// Valid after a successful <see cref="ProcessAuthResponse"/>; read <see cref="ConfigurationPayload.AssignedIp4Address"/>
        /// / <see cref="ConfigurationPayload.DnsServers"/> for the assigned tunnel address and resolvers.
        /// </summary>
        public ConfigurationPayload? Configuration { get; private set; }

        /// <summary>The current IKE SA key material — the IKE_SA_INIT set, or the rekeyed set after an IKE SA rekey.</summary>
        public IkeKeyMaterial? IkeKeys => _currentKeys ?? _initiator.Keys;

        /// <summary>Builds the IKE_SA_INIT request (caller encodes &amp; sends it).</summary>
        public IkeMessage BuildInitRequest(IPAddress localIp, ushort localPort, IPAddress remoteIp, ushort remotePort)
            => _initiator.BuildInitRequest(localIp, localPort, remoteIp, remotePort);

        /// <summary>Processes the IKE_SA_INIT response, deriving the IKE SA keys and preparing the SK cipher.</summary>
        public void ProcessInitResponse(IkeMessage response)
        {
            IkeKeyMaterial keys = _initiator.ProcessInitResponse(response);
            _cipher = IkeCipher.ForInitiator(keys);
            _currentResponderSpi = _initiator.ResponderSpi;
            _currentSkD = keys.SkD;
            _currentKeys = keys;
        }

        /// <summary>Builds the encrypted IKE_AUTH request (IDi, AUTH, SAi2, TSi, TSr [, USE_TRANSPORT_MODE]).</summary>
        public byte[] BuildAuthRequest()
        {
            if (_cipher is null || _initiator.Keys is null)
                throw new InvalidOperationException("IKE_SA_INIT must complete before IKE_AUTH.");

            byte[] auth = IkePskAuth.ComputeInitiatorAuth(
                _prf, _preSharedKey, _initiator.InitRequestBytes, _initiator.PeerNonce,
                _initiator.Keys.SkPi, _identity.BodyBytes());

            var message = new IkeMessage
            {
                InitiatorSpi = _initiator.InitiatorSpi,
                ResponderSpi = _initiator.ResponderSpi,
                ExchangeType = IkeExchangeType.IkeAuth,
                Flags = IkeHeaderFlags.Initiator,
                MessageId = 1,
            };
            message.Payloads.Add(_identity);
            // CERTREQ (digital-signature auth): ask the gateway to send its certificate so we can verify its AUTH.
            if (_responderTrust is not null)
                message.Payloads.Add(CertificateRequestPayload.AnyX509());
            message.Payloads.Add(new AuthenticationPayload { Method = IkeAuthMethod.SharedKey, Data = auth });

            // CFG_REQUEST (if asked): goes before SAi2 so the gateway assigns a virtual IP/DNS for tunnel mode.
            if (_requestConfiguration)
                message.Payloads.Add(ConfigurationPayload.Request());

            var sa = new SecurityAssociationPayload();
            foreach (IkeProposal proposal in IkeProposals.EspProposals(ChildInboundSpi))
                sa.Proposals.Add(proposal);
            message.Payloads.Add(sa);
            message.Payloads.Add(BuildInitiatorTs());
            message.Payloads.Add(BuildResponderTs());
            if (_requestTransportMode)
                message.Payloads.Add(NotifyPayload.Create(IkeNotifyMessageType.UseTransportMode, Array.Empty<byte>()));

            return _cipher.EncryptMessage(message);
        }

        /// <summary>
        /// Decrypts and validates the IKE_AUTH response: verifies the responder AUTH, records its ESP SPI, and
        /// derives the CHILD_SA keys. Returns false if decryption, AUTH verification, or the SAr2 is invalid.
        /// </summary>
        public bool ProcessAuthResponse(byte[] wire)
        {
            if (_cipher is null || _initiator.Keys is null) return false;

            IkeMessage? response = _cipher.DecryptMessage(wire);
            if (response is null) return false;

            IdentificationPayload? idR = response.Payloads.OfType<IdentificationPayload>().FirstOrDefault(p => !p.IsInitiator);
            AuthenticationPayload? auth = response.Find<AuthenticationPayload>();
            SecurityAssociationPayload? sa = response.Find<SecurityAssociationPayload>();
            if (idR is null || auth is null || sa is null) return false;

            if (!VerifyResponderAuth(response, idR, auth)) return false;

            IkeProposal? proposal = sa.Proposals.FirstOrDefault();
            if (proposal is null || proposal.Spi.Length == 0) return false;

            EspSuiteSelection? selection = ParseEspSelection(proposal);
            if (selection is null) return false;

            ChildOutboundSpi = proposal.Spi;
            NegotiatedEsp = selection;
            Configuration = response.Find<ConfigurationPayload>();
            ChildKeys = ChildSaKeys.Derive(_prf, _initiator.Keys.SkD, _initiator.Nonce, _initiator.PeerNonce,
                selection.EncryptionKeyLengthBytes, selection.SecondSliceLengthBytes);
            return true;
        }

        /// <summary>
        /// Verifies the responder's AUTH. When the responder authenticated with a digital signature (RFC 7296 §2.15
        /// method 1/9/14) we validate the CERT it sent against the configured trust and verify the signature with that
        /// certificate's public key — a failure means a deliberate server rejection (<see cref="VpnServerRejectedException"/>).
        /// When it authenticated with the PSK (Shared Key) — the only path when no trust is configured — a MIC mismatch
        /// returns false (the caller surfaces it as an authentication failure), preserving the original behaviour.
        /// </summary>
        bool VerifyResponderAuth(IkeMessage response, IdentificationPayload idR, AuthenticationPayload auth)
        {
            byte[] restOfIdR = idR.BodyBytes();

            if (auth.Method == IkeAuthMethod.SharedKey)
            {
                // A PSK AUTH where we required a certificate is a downgrade — refuse it.
                if (_responderTrust is not null)
                    throw new VpnServerRejectedException(
                        "The IKEv2 gateway authenticated with a pre-shared key, but a certificate was required (possible downgrade).");

                byte[] expected = IkePskAuth.ComputeResponderAuth(
                    _prf, _preSharedKey, _initiator.InitResponseBytes, _initiator.Nonce, _initiator.Keys!.SkPr, restOfIdR);
                return CryptoBytes.FixedTimeEquals(expected, auth.Data);
            }

            // Digital-signature responder auth requires a configured trust anchor and a CERT payload to verify against.
            if (_responderTrust is null)
                throw new VpnServerRejectedException(
                    "The IKEv2 gateway authenticated with a digital signature, but no certificate trust was configured to verify it.");

            CertificatePayload? cert = response.Find<CertificatePayload>();
            if (cert is null || cert.Encoding != IkeCertificateEncoding.X509CertificateSignature || cert.Data.Length == 0)
                throw new VpnServerRejectedException("The IKEv2 gateway signed its AUTH but sent no X.509 certificate to verify it.");

            X509Certificate2 certificate;
            try { certificate = new X509Certificate2(cert.Data); }
            catch (CryptographicException ex)
            {
                throw new VpnServerRejectedException("The IKEv2 gateway's certificate could not be parsed.", ex);
            }

            if (!_responderTrust.IsTrusted(certificate))
            {
                certificate.Dispose();
                throw new VpnServerRejectedException("The IKEv2 gateway's certificate is not trusted (no pinned match and no chain to a trusted CA).");
            }

            bool valid = IkeSignatureAuth.VerifyResponderSignature(
                _prf, auth.Method, certificate, auth.Data,
                _initiator.InitResponseBytes, _initiator.Nonce, _initiator.Keys!.SkPr, restOfIdR);
            if (!valid)
            {
                certificate.Dispose();
                throw new VpnServerRejectedException("The IKEv2 gateway's AUTH signature did not verify against its certificate.");
            }

            ResponderCertificate = certificate;
            return true;
        }

        // ---- IKE_AUTH with EAP-MSCHAPv2 (server username/password), RFC 7296 §2.16 + draft-kamath-pppext-eap-mschapv2 ----
        // Flow: the initiator omits its AUTH from the first IKE_AUTH (signalling EAP); the responder authenticates with
        // its PSK and starts EAP; EAP packets ride successive IKE_AUTH exchanges; on EAP-Success both sides authenticate
        // with the MSK (RFC 7296 §2.16) and the CHILD_SA is negotiated in the final exchange.

        /// <summary>True once EAP authentication completed and the CHILD_SA keys are ready (read <see cref="ChildKeys"/>).</summary>
        public bool EapEstablished { get; private set; }

        /// <summary>True if the EAP exchange failed (bad responder AUTH, EAP-Failure, or a verification mismatch).</summary>
        public bool EapFailed { get; private set; }

        /// <summary>
        /// Builds the first IKE_AUTH request for EAP (RFC 7296 §2.16): IDi, the ESP proposals and traffic selectors,
        /// but <em>no</em> AUTH payload — the absence tells the gateway we will authenticate with EAP. Requires the
        /// client to have been created with EAP credentials.
        /// </summary>
        public byte[] BuildAuthRequestEap()
        {
            if (_cipher is null || _initiator.Keys is null)
                throw new InvalidOperationException("IKE_SA_INIT must complete before IKE_AUTH.");
            if (_eapUserName is null || _eapPassword is null)
                throw new InvalidOperationException("EAP credentials were not supplied to the IkeClient.");

            _eap = new EapMsChapV2Client(_eapUserName, _eapPassword);
            _eapMessageId = 1; // IKE_AUTH exchanges count from 1 (IKE_SA_INIT was 0); each EAP round consumes one.

            var message = new IkeMessage
            {
                InitiatorSpi = _initiator.InitiatorSpi,
                ResponderSpi = _initiator.ResponderSpi,
                ExchangeType = IkeExchangeType.IkeAuth,
                Flags = IkeHeaderFlags.Initiator,
                MessageId = _eapMessageId++,
            };
            message.Payloads.Add(_identity);
            if (_requestConfiguration)
                message.Payloads.Add(ConfigurationPayload.Request());

            var sa = new SecurityAssociationPayload();
            foreach (IkeProposal proposal in IkeProposals.EspProposals(ChildInboundSpi))
                sa.Proposals.Add(proposal);
            message.Payloads.Add(sa);
            message.Payloads.Add(BuildInitiatorTs());
            message.Payloads.Add(BuildResponderTs());
            if (_requestTransportMode)
                message.Payloads.Add(NotifyPayload.Create(IkeNotifyMessageType.UseTransportMode, Array.Empty<byte>()));

            return _cipher.EncryptMessage(message);
        }

        /// <summary>
        /// Processes one IKE_AUTH response during the EAP exchange and returns the wire of the next IKE_AUTH request
        /// to send, or null when authentication is complete (<see cref="EapEstablished"/>) or has failed
        /// (<see cref="EapFailed"/>). The first response also carries the responder's PSK AUTH, which is verified here.
        /// </summary>
        public byte[]? ProcessAuthResponseEap(byte[] wire)
        {
            if (_cipher is null || _initiator.Keys is null || _eap is null) return Fail();

            IkeMessage? response = _cipher.DecryptMessage(wire);
            if (response is null) return Fail();

            // First response (message 4): verify the responder's PSK AUTH and cache RestOfIDr for the final MSK check.
            if (!_eapStarted)
            {
                IdentificationPayload? idR = response.Payloads.OfType<IdentificationPayload>().FirstOrDefault(p => !p.IsInitiator);
                AuthenticationPayload? auth = response.Find<AuthenticationPayload>();
                if (idR is null || auth is null) return Fail();

                byte[] expected = IkePskAuth.ComputeResponderAuth(
                    _prf, _preSharedKey, _initiator.InitResponseBytes, _initiator.Nonce, _initiator.Keys.SkPr, idR.BodyBytes());
                if (!CryptoBytes.FixedTimeEquals(expected, auth.Data)) return Fail();

                _eapResponderIdBody = idR.BodyBytes();
                _eapStarted = true;
            }

            EapPayload? eap = response.Find<EapPayload>();
            if (eap is not null)
            {
                EapResult result = _eap.Handle(eap.Message, out byte[]? eapResponse);
                if (result == EapResult.Failed) return Fail();
                if (result == EapResult.Success)
                    return BuildEapMessage(new AuthenticationPayload { Method = IkeAuthMethod.SharedKey, Data = ComputeMskAuth() });
                return BuildEapMessage(new EapPayload { Message = eapResponse! });
            }

            // No EAP payload → the final response (message 8): verify the responder's MSK AUTH and derive the CHILD_SA.
            return ProcessFinalEapResponse(response) ? null : Fail();
        }

        // The initiator's final AUTH uses the EAP MSK as the shared secret (RFC 7296 §2.16, syntax of §2.15).
        byte[] ComputeMskAuth()
            => IkePskAuth.ComputeInitiatorAuth(
                _prf, _eap!.Msk!, _initiator.InitRequestBytes, _initiator.PeerNonce, _initiator.Keys!.SkPi, _identity.BodyBytes());

        byte[] BuildEapMessage(IkePayload payload)
        {
            var message = new IkeMessage
            {
                InitiatorSpi = _initiator.InitiatorSpi,
                ResponderSpi = _initiator.ResponderSpi,
                ExchangeType = IkeExchangeType.IkeAuth,
                Flags = IkeHeaderFlags.Initiator,
                MessageId = _eapMessageId++,
            };
            message.Payloads.Add(payload);
            return _cipher!.EncryptMessage(message);
        }

        bool ProcessFinalEapResponse(IkeMessage response)
        {
            AuthenticationPayload? auth = response.Find<AuthenticationPayload>();
            SecurityAssociationPayload? sa = response.Find<SecurityAssociationPayload>();
            if (auth is null || sa is null || _eapResponderIdBody is null || _eap?.Msk is null || _initiator.Keys is null)
                return false;

            byte[] expected = IkePskAuth.ComputeResponderAuth(
                _prf, _eap.Msk, _initiator.InitResponseBytes, _initiator.Nonce, _initiator.Keys.SkPr, _eapResponderIdBody);
            if (!CryptoBytes.FixedTimeEquals(expected, auth.Data)) return false;

            IkeProposal? proposal = sa.Proposals.FirstOrDefault();
            if (proposal is null || proposal.Spi.Length == 0) return false;
            EspSuiteSelection? selection = ParseEspSelection(proposal);
            if (selection is null) return false;

            ChildOutboundSpi = proposal.Spi;
            NegotiatedEsp = selection;
            Configuration = response.Find<ConfigurationPayload>();
            ChildKeys = ChildSaKeys.Derive(_prf, _initiator.Keys.SkD, _initiator.Nonce, _initiator.PeerNonce,
                selection.EncryptionKeyLengthBytes, selection.SecondSliceLengthBytes);

            _nextMessageId = _eapMessageId; // post-auth exchanges continue after the EAP message IDs
            EapEstablished = true;
            return true;
        }

        byte[]? Fail()
        {
            EapFailed = true;
            return null;
        }

        // ---- Post-IKE_AUTH exchanges (INFORMATIONAL: DPD + DELETE), RFC 7296 §1.4/§2.4 ----

        /// <summary>The message ID the next initiator-sent request will carry (IKE_SA_INIT=0, IKE_AUTH=1, then 2…).</summary>
        public uint NextMessageId => _nextMessageId;

        /// <summary>Decrypts any SK-protected message received after IKE_AUTH (INFORMATIONAL / CREATE_CHILD_SA); null if invalid.</summary>
        public IkeMessage? Decrypt(byte[] wire) => _cipher?.DecryptMessage(wire);

        /// <summary>Builds an encrypted INFORMATIONAL request carrying <paramref name="payloads"/> (empty = liveness/DPD), consuming a message ID.</summary>
        public byte[] BuildInformationalRequest(params IkePayload[] payloads)
            => BuildEncryptedRequest(IkeExchangeType.Informational, payloads);

        /// <summary>Builds an empty INFORMATIONAL request — an IKEv2 liveness (Dead Peer Detection) probe (RFC 7296 §2.4).</summary>
        public byte[] BuildDeadPeerDetection() => BuildInformationalRequest();

        /// <summary>Builds an INFORMATIONAL request deleting the ESP CHILD_SA (our inbound SPI), for teardown.</summary>
        public byte[] BuildDeleteChildSa() => BuildInformationalRequest(DeletePayload.Esp(ChildInboundSpi));

        /// <summary>
        /// Builds an INFORMATIONAL request deleting a specific ESP CHILD_SA by its inbound SPI — used after a
        /// CREATE_CHILD_SA rekey to retire the <em>old</em> SA (whose SPI is no longer <see cref="ChildInboundSpi"/>),
        /// per RFC 7296 §2.8. The request rides the current (live) IKE SA.
        /// </summary>
        public byte[] BuildDeleteChildSa(byte[] inboundSpi) => BuildInformationalRequest(DeletePayload.Esp(inboundSpi));

        /// <summary>Builds an INFORMATIONAL request deleting the IKE SA itself — a clean tunnel teardown (RFC 7296 §1.4.1).</summary>
        public byte[] BuildDeleteIkeSa() => BuildInformationalRequest(DeletePayload.Ike());

        /// <summary>
        /// Builds an INFORMATIONAL response echoing a peer-initiated request's message ID — e.g. the empty ack to the
        /// gateway's DPD probe, or the ack to a peer DELETE. Keeps the Initiator flag (we remain the SA initiator).
        /// </summary>
        public byte[] BuildInformationalResponse(uint messageId, params IkePayload[] payloads)
        {
            if (_cipher is null) throw new InvalidOperationException("IKE SA not established.");
            var message = new IkeMessage
            {
                InitiatorSpi = _currentInitiatorSpi,
                ResponderSpi = _currentResponderSpi,
                ExchangeType = IkeExchangeType.Informational,
                Flags = IkeHeaderFlags.Initiator | IkeHeaderFlags.Response,
                MessageId = messageId,
            };
            foreach (IkePayload payload in payloads) message.Payloads.Add(payload);
            return _cipher.EncryptMessage(message);
        }

        byte[] BuildEncryptedRequest(IkeExchangeType exchange, IkePayload[] payloads)
        {
            if (_cipher is null) throw new InvalidOperationException("IKE SA not established.");
            var message = new IkeMessage
            {
                InitiatorSpi = _currentInitiatorSpi,
                ResponderSpi = _currentResponderSpi,
                ExchangeType = exchange,
                Flags = IkeHeaderFlags.Initiator,
                MessageId = _nextMessageId++,
            };
            foreach (IkePayload payload in payloads) message.Payloads.Add(payload);
            return _cipher.EncryptMessage(message);
        }

        // ---- CREATE_CHILD_SA: rekey the ESP CHILD_SA (make-before-break), RFC 7296 §1.3.3/§2.8 ----

        byte[]? _rekeyInboundSpi;  // the inbound SPI we proposed for the replacement CHILD_SA
        byte[]? _rekeyNonce;       // our Ni for the replacement CHILD_SA's KEYMAT

        /// <summary>
        /// Builds a CREATE_CHILD_SA request that rekeys the current ESP CHILD_SA (no PFS): a REKEY_SA notify naming
        /// the old inbound SPI, a fresh SA proposal with a new inbound SPI, a new nonce, and the traffic selectors.
        /// </summary>
        public byte[] BuildRekeyChildSaRequest()
        {
            byte[] newInboundSpi = RandomSpi();
            byte[] newNonce = RandomNonce();
            _rekeyInboundSpi = newInboundSpi;
            _rekeyNonce = newNonce;

            var rekey = new NotifyPayload
            {
                ProtocolId = IkeProtocolId.Esp,
                MessageType = (ushort)IkeNotifyMessageType.RekeySa,
                Spi = ChildInboundSpi, // the SA being rekeyed, identified by the SPI we currently receive on
            };
            var sa = new SecurityAssociationPayload();
            foreach (IkeProposal proposal in IkeProposals.EspProposals(newInboundSpi))
                sa.Proposals.Add(proposal);

            return BuildEncryptedRequest(IkeExchangeType.CreateChildSa, new IkePayload[]
            {
                rekey,
                sa,
                new NoncePayload { Nonce = newNonce },
                BuildInitiatorTs(),
                BuildResponderTs(),
            });
        }

        /// <summary>
        /// Processes the CREATE_CHILD_SA response: derives the replacement CHILD_SA keys (KEYMAT = prf+(SK_d, Ni|Nr)),
        /// adopts the new SPIs as current, and returns the parameters for the driver to build the fresh
        /// <see cref="EspSession"/>. Returns null if there is no in-flight rekey or the response is invalid.
        /// </summary>
        public ChildSaParameters? ProcessRekeyChildSaResponse(byte[] wire)
        {
            if (_cipher is null || _currentSkD is null || _rekeyInboundSpi is null || _rekeyNonce is null) return null;

            IkeMessage? response = _cipher.DecryptMessage(wire);
            if (response is null) return null;

            SecurityAssociationPayload? sa = response.Find<SecurityAssociationPayload>();
            NoncePayload? nr = response.Find<NoncePayload>();
            if (sa is null || nr is null) return null;

            IkeProposal? proposal = sa.Proposals.FirstOrDefault();
            if (proposal is null || proposal.Spi.Length == 0) return null;

            EspSuiteSelection? selection = ParseEspSelection(proposal);
            if (selection is null) return null;

            ChildSaKeys keys = ChildSaKeys.Derive(_prf, _currentSkD, _rekeyNonce, nr.Nonce,
                selection.EncryptionKeyLengthBytes, selection.SecondSliceLengthBytes);

            // Adopt the replacement SA as current so the next DELETE/rekey references it.
            ChildInboundSpi = _rekeyInboundSpi;
            ChildOutboundSpi = proposal.Spi;
            ChildKeys = keys;
            NegotiatedEsp = selection;
            _rekeyInboundSpi = null;
            _rekeyNonce = null;

            return new ChildSaParameters(ChildInboundSpi, ChildOutboundSpi, keys, selection);
        }

        // ---- CREATE_CHILD_SA: rekey the IKE SA itself (new SPIs + fresh D-H), RFC 7296 §1.3.2/§2.18 ----
        // Phase-1-equivalent rekey: like the IKEv1 in-place Phase 1 rekey, it stands up a brand-new IKE SA (new SPIs,
        // new D-H, re-derived SK_*) over the existing SK channel, then swings every subsequent exchange onto it.

        readonly ModpDhGroup _ikeRekeyDh = ModpDhGroup.Group14();
        byte[]? _ikeRekeyPrivateKey;     // our D-H private value for the replacement IKE SA
        byte[]? _ikeRekeyInitiatorSpi;   // the 8-byte SPI we proposed for the replacement IKE SA
        byte[]? _ikeRekeyNonce;          // our Ni for the replacement IKE SA's SKEYSEED

        // A DELETE of the OLD IKE SA, encrypted with the old SK keys + old header SPIs the instant before the SA is
        // swung onto the new keys (RFC 7296 §2.18: the initiator SHOULD delete the replaced SA). Drained by the driver
        // via TakePendingOldIkeSaDelete() and sent on the old SA; once the new SA is live the old keys are gone, so the
        // wire must be built here while they still exist.
        byte[]? _pendingOldIkeSaDelete;

        /// <summary>
        /// Builds a CREATE_CHILD_SA request that rekeys the IKE SA (RFC 7296 §1.3.2): an IKE proposal carrying a fresh
        /// 8-byte initiator SPI, a new D-H public value (KEi), and a new nonce (Ni). Unlike a CHILD_SA rekey there is
        /// no REKEY_SA notify and no traffic selectors — the SA being replaced is the one the header SPIs identify.
        /// </summary>
        public byte[] BuildRekeyIkeSaRequest()
        {
            if (_cipher is null) throw new InvalidOperationException("IKE SA not established.");

            byte[] newSpi = RandomNonZeroSpi();
            byte[] newNonce = RandomNonce();
            _ikeRekeyPrivateKey = _ikeRekeyDh.GeneratePrivateKey();
            byte[] publicValue = _ikeRekeyDh.DerivePublicValue(_ikeRekeyPrivateKey);
            _ikeRekeyInitiatorSpi = newSpi;
            _ikeRekeyNonce = newNonce;

            var sa = new SecurityAssociationPayload();
            sa.Proposals.Add(IkeProposals.RekeyIke(newSpi));

            return BuildEncryptedRequest(IkeExchangeType.CreateChildSa, new IkePayload[]
            {
                sa,
                new KeyExchangePayload { DiffieHellmanGroup = IkeTransformId.DiffieHellman.Modp2048, KeyData = publicValue },
                new NoncePayload { Nonce = newNonce },
            });
        }

        /// <summary>
        /// Processes the IKE SA rekey response (decrypted with the <em>old</em> SK keys): computes the new shared secret
        /// from KEr, derives the replacement SK_* via <c>prf(SK_d_old, g^ir|Ni|Nr)</c> (RFC 7296 §2.18), then swings the
        /// SA over — new SPIs, new SK cipher, fresh SK_d, and the message-ID window reset to 0. Returns false if there
        /// is no in-flight rekey or the response is malformed; the old SA is left untouched so the caller can retry.
        /// </summary>
        public bool ProcessRekeyIkeSaResponse(byte[] wire)
        {
            if (_cipher is null || _currentSkD is null
                || _ikeRekeyPrivateKey is null || _ikeRekeyInitiatorSpi is null || _ikeRekeyNonce is null) return false;

            IkeMessage? response = _cipher.DecryptMessage(wire);
            if (response is null) return false;

            SecurityAssociationPayload? sa = response.Find<SecurityAssociationPayload>();
            KeyExchangePayload? ke = response.Find<KeyExchangePayload>();
            NoncePayload? nr = response.Find<NoncePayload>();
            if (sa is null || ke is null || nr is null) return false;

            IkeProposal? proposal = sa.Proposals.FirstOrDefault();
            if (proposal is null || proposal.Spi.Length != 8) return false; // the responder's new IKE SPI
            byte[] newResponderSpi = proposal.Spi;

            byte[] sharedSecret = _ikeRekeyDh.DeriveSharedSecret(_ikeRekeyPrivateKey, ke.KeyData);
            IkeKeyMaterial newKeys = IkeKeyMaterial.DeriveRekeyDefault(
                _currentSkD, _ikeRekeyNonce, nr.Nonce, sharedSecret, _ikeRekeyInitiatorSpi, newResponderSpi);

            // Build (but do not send) a DELETE of the old IKE SA on the OLD keys/SPIs/message-id while they still exist
            // (RFC 7296 §2.18). The driver drains and transmits it on the old SA; afterwards the old keys are discarded.
            _pendingOldIkeSaDelete = BuildEncryptedRequest(IkeExchangeType.Informational, new IkePayload[] { DeletePayload.Ike() });

            // Swing onto the replacement IKE SA: new SPIs in every header, new SK cipher, fresh SK_d for child rekeys,
            // and a fresh message-ID window (each IKE SA counts its own message IDs from 0, RFC 7296 §2.2).
            _currentInitiatorSpi = _ikeRekeyInitiatorSpi;
            _currentResponderSpi = newResponderSpi;
            _cipher = IkeCipher.ForInitiator(newKeys);
            _currentSkD = newKeys.SkD;
            _currentKeys = newKeys;
            _nextMessageId = 0;
            _ikeRekeyPrivateKey = null;
            _ikeRekeyInitiatorSpi = null;
            _ikeRekeyNonce = null;
            return true;
        }

        /// <summary>
        /// Returns and clears the INFORMATIONAL+DELETE for the old IKE SA prepared by the last successful
        /// <see cref="ProcessRekeyIkeSaResponse"/>, or null if none is pending. The wire is encrypted with the
        /// retired SA's keys and addressed with its SPIs, so the caller must send it as-is on the old SA (a peer ACK,
        /// if any, would arrive on that SA too — the caller treats it best-effort since the SA is being torn down).
        /// </summary>
        public byte[]? TakePendingOldIkeSaDelete()
        {
            byte[]? pending = _pendingOldIkeSaDelete;
            _pendingOldIkeSaDelete = null;
            return pending;
        }

        /// <summary>
        /// Maps the responder's selected CHILD_SA proposal to the suite we will build. AES-GCM when the ENCR
        /// transform says so; otherwise AES-CBC with the key length / integrity read from the transforms
        /// (defaulting to 256-bit / HMAC-SHA-256-128). Returns null if the proposal is unusable.
        /// </summary>
        static EspSuiteSelection? ParseEspSelection(IkeProposal proposal)
        {
            IkeTransform? encryption = proposal.Transforms.FirstOrDefault(t => t.Type == IkeTransformType.Encryption);
            if (encryption is null) return null;

            int keyBytes = KeyLengthOr(encryption, 256) / 8;
            if (keyBytes != 16 && keyBytes != 24 && keyBytes != 32) return null;

            if (encryption.Id == IkeTransformId.Encryption.AesGcm16)
                return EspSuiteSelection.AesGcm16(keyBytes);

            IkeTransform? integrity = proposal.Transforms.FirstOrDefault(t => t.Type == IkeTransformType.Integrity);
            return integrity != null && integrity.Id == IkeTransformId.Integrity.HmacSha1_96
                ? EspSuiteSelection.AesCbcHmacSha1(keyBytes)
                : EspSuiteSelection.AesCbcHmacSha256(keyBytes);
        }

        static int KeyLengthOr(IkeTransform transform, int fallback)
        {
            foreach (IkeTransformAttribute attribute in transform.Attributes)
                if (attribute.Type == IkeTransformId.KeyLengthAttribute) return attribute.Value;
            return fallback;
        }

        static byte[] RandomSpi()
        {
            byte[] spi = new byte[4];
            using var rng = RandomNumberGenerator.Create();
            rng.GetBytes(spi);
            return spi;
        }

        static byte[] RandomNonZeroSpi()
        {
            byte[] spi = new byte[8]; // IKE SPIs are 8 bytes and MUST be non-zero (RFC 7296 §3.1)
            using var rng = RandomNumberGenerator.Create();
            rng.GetBytes(spi);
            bool allZero = true;
            foreach (byte b in spi) if (b != 0) { allZero = false; break; }
            if (allZero) spi[0] = 1;
            return spi;
        }

        static byte[] RandomNonce()
        {
            byte[] nonce = new byte[32];
            using var rng = RandomNumberGenerator.Create();
            rng.GetBytes(nonce);
            return nonce;
        }
    }
}
