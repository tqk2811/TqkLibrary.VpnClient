using System.Collections.Concurrent;
using System.Net;
using System.Security.Cryptography;
using Microsoft.Extensions.Logging;
using TqkLibrary.VpnClient.Abstractions.Diagnostics;
using TqkLibrary.VpnClient.Abstractions.Drivers;
using TqkLibrary.VpnClient.Crypto;
using TqkLibrary.VpnClient.Ipsec.Esp;
using TqkLibrary.VpnClient.Ipsec.Esp.Enums;
using TqkLibrary.VpnClient.Ipsec.Ike.V1;
using TqkLibrary.VpnClient.Ipsec.Ike.V1.Enums;
using TqkLibrary.VpnClient.Ipsec.Ike.V1.Models;
using TqkLibrary.VpnClient.Ipsec.Ike.V1.Payloads;
using Xunit;

namespace TqkLibrary.VpnClient.Ipsec.Ike.Tests
{
    /// <summary>
    /// Drives the real <see cref="IkeV1Client"/> through a full IKEv1 exchange in-process: Main Mode MM1→MM6 (PSK)
    /// then Quick Mode QM1→QM3 against a hand-written <see cref="SimulatedResponderV1"/>, then both sides build
    /// <see cref="EspSession"/>s from the Phase-2 keys and exchange a protected packet each direction. This pins the
    /// IKEv1 encrypted-exchange math (Main Mode HASH_I/HASH_R auth, the CBC IV chain, the Quick-Mode derived IV,
    /// the client's HASH(1) and its HASH(3) verified by the responder, the responder's HASH(2) now verified by the
    /// client — see <see cref="IkeV1Client.ProcessQuickMode2"/>, SKEYID_d → ESP keymat) offline — previously only
    /// live-tested against VPN Gate. <see cref="QuickMode_ResponderHash2Tampered_ProcessQuickMode2Throws"/> pins the
    /// rejection path. The DPD and Delete round-trips at the end pin the derived-IV Informational cipher.
    ///
    /// The responder hand-rolls the tiny ISAKMP framing (28-byte header + TLV payload chain) so no production-code
    /// change (e.g. InternalsVisibleTo) is needed: <c>IsakmpMessage.EncodePayloadChain/WriteHeader/...</c> are internal.
    /// </summary>
    public class IkeV1HandshakeTests
    {
        static readonly byte[] Psk = System.Text.Encoding.ASCII.GetBytes("vpn");

        [Fact]
        public void FullMainModeAndQuickMode_ThenEspExchange_Succeeds()
        {
            var client = new IkeV1Client(Psk, IPAddress.Loopback, IPAddress.Loopback);
            var responder = new SimulatedResponderV1(Psk, client.InitiatorCookie);

            // --- Main Mode ---
            byte[] mm1 = client.BuildMainMode1();
            byte[] mm2 = responder.HandleMainMode1(mm1);
            client.ProcessMainMode2(mm2);

            byte[] mm3 = client.BuildMainMode3(IPAddress.Any, IPAddress.Loopback);
            byte[] mm4 = responder.HandleMainMode3(mm4Input: mm3, cookieR: responder.ResponderCookie);
            client.ProcessMainMode4(mm4);

            byte[] mm5 = client.BuildMainMode5();
            byte[] mm6 = responder.HandleMainMode5(mm5); // verifies HASH_I internally
            Assert.True(client.ProcessMainMode6(mm6));    // verifies HASH_R

            // --- Quick Mode ---
            byte[] qm1 = client.BuildQuickMode1();
            byte[] qm2 = responder.HandleQuickMode1(qm1); // captures client SPI + Ni; builds SA + Nr + HASH(2)
            Assert.True(client.ProcessQuickMode2(qm2));    // authenticates HASH(2), then accepts the responder's ESP SPI

            byte[] qm3 = client.BuildQuickMode3();
            responder.HandleQuickMode3(qm3); // verifies HASH(3) internally

            // SPI orientation (mirror Phase2Keys_TwoParties): the SA on the responder's SPI is the client's
            // outbound and the responder's inbound — same keys on both sides.
            Assert.Equal(responder.ChildInboundSpi, client.ChildOutboundSpi);
            Assert.Equal(client.ChildInboundSpi, responder.ChildOutboundSpi);

            // --- Phase-2 keys + ESP data plane both directions ---
            IkeV1Phase2Keys clientKeys = client.CreatePhase2Keys();
            IkeV1Phase2Keys responderKeys = responder.CreatePhase2Keys();

            // Sanity: the key set agrees on the shared SAs.
            Assert.Equal(clientKeys.OutboundEncryption, responderKeys.InboundEncryption);
            Assert.Equal(clientKeys.InboundEncryption, responderKeys.OutboundEncryption);

            EspSession clientEsp = new(
                ToSpi(client.ChildOutboundSpi),
                EspCipherSuite.AesCbcHmacSha1(clientKeys.OutboundEncryption, clientKeys.OutboundIntegrity),
                ToSpi(client.ChildInboundSpi),
                EspCipherSuite.AesCbcHmacSha1(clientKeys.InboundEncryption, clientKeys.InboundIntegrity));
            EspSession responderEsp = new(
                ToSpi(client.ChildInboundSpi),
                EspCipherSuite.AesCbcHmacSha1(responderKeys.OutboundEncryption, responderKeys.OutboundIntegrity),
                ToSpi(responder.ChildInboundSpi),
                EspCipherSuite.AesCbcHmacSha1(responderKeys.InboundEncryption, responderKeys.InboundIntegrity));

            byte[] toServer = clientEsp.Protect(System.Text.Encoding.ASCII.GetBytes("ping from client"));
            Assert.True(responderEsp.TryUnprotect(toServer, out byte[] gotByServer, out _));
            Assert.Equal("ping from client", System.Text.Encoding.ASCII.GetString(gotByServer));

            byte[] toClient = responderEsp.Protect(System.Text.Encoding.ASCII.GetBytes("pong from server"));
            Assert.True(clientEsp.TryUnprotect(toClient, out byte[] gotByClient, out _));
            Assert.Equal("pong from server", System.Text.Encoding.ASCII.GetString(gotByClient));
        }

        [Fact]
        public void FullHandshake_WithLogger_EmitsProtocolStepTraces()
        {
            // Q.2: the deep IKEv1 layer takes an optional ILogger and stamps each fine-grained step on the shared
            // ProtocolStep event id. A captured logger must see the Main/Quick Mode + NAT-D traces.
            var log = new CapturingLogger();
            var client = new IkeV1Client(Psk, IPAddress.Loopback, IPAddress.Loopback, logger: log);
            var responder = new SimulatedResponderV1(Psk, client.InitiatorCookie);

            // A real NAT-D verdict (gateway reports our source seen at a translated port) so the NAT-D trace fires too.
            IPAddress localIp = IPAddress.Parse("198.51.100.10"), serverIp = IPAddress.Parse("203.0.113.5");
            client.ProcessMainMode2(responder.HandleMainMode1(client.BuildMainMode1()));
            byte[] mm3 = client.BuildMainMode3(localIp, 500, serverIp, 500);
            client.ProcessMainMode4(responder.HandleMainMode3(mm3, responder.ResponderCookie,
                observedInitiatorEndpoint: localIp, observedInitiatorPort: 61000,
                responderEndpoint: serverIp, responderPort: 500));
            IkeV1NatDetectionResult nat = client.DetectNat(localIp, 500, serverIp, 500);
            Assert.True(nat.ServerSentNatD);
            Assert.True(client.ProcessMainMode6(responder.HandleMainMode5(client.BuildMainMode5())));
            Assert.True(client.ProcessQuickMode2(responder.HandleQuickMode1(client.BuildQuickMode1())));
            responder.HandleQuickMode3(client.BuildQuickMode3());

            Assert.True(log.Captured(VpnEventIds.ProtocolStep));
            Assert.Contains(log.MessagesFor(VpnEventIds.ProtocolStep), m => m.Contains("MM4"));
            Assert.Contains(log.MessagesFor(VpnEventIds.ProtocolStep), m => m.Contains("NAT-D verdict"));
            Assert.Contains(log.MessagesFor(VpnEventIds.ProtocolStep), m => m.Contains("MM6") && m.Contains("verified"));
            Assert.Contains(log.MessagesFor(VpnEventIds.ProtocolStep), m => m.Contains("QM2"));
        }

        [Fact]
        public void FullHandshake_NullLogger_ReachesSameNegotiatedSa()
        {
            // The null-logger path runs the exact same handshake (logging is additive): same negotiated SPIs, no throw.
            var client = new IkeV1Client(Psk, IPAddress.Loopback, IPAddress.Loopback, logger: null);
            var responder = new SimulatedResponderV1(Psk, client.InitiatorCookie);

            client.ProcessMainMode2(responder.HandleMainMode1(client.BuildMainMode1()));
            client.ProcessMainMode4(responder.HandleMainMode3(client.BuildMainMode3(IPAddress.Any, IPAddress.Loopback), responder.ResponderCookie));
            Assert.True(client.ProcessMainMode6(responder.HandleMainMode5(client.BuildMainMode5())));
            Assert.True(client.ProcessQuickMode2(responder.HandleQuickMode1(client.BuildQuickMode1())));
            responder.HandleQuickMode3(client.BuildQuickMode3());

            Assert.Equal(responder.ChildInboundSpi, client.ChildOutboundSpi);
            Assert.Equal(client.ChildInboundSpi, responder.ChildOutboundSpi);
        }

        [Fact]
        public void FullHandshake_WhenGatewaySelectsGcm_NegotiatesGcmAndEspExchangeSucceeds()
        {
            var client = new IkeV1Client(Psk, IPAddress.Loopback, IPAddress.Loopback);
            var responder = new SimulatedResponderV1(Psk, client.InitiatorCookie, EspSuiteSelection.AesGcm16());

            DriveToQuickModeComplete(client, responder);

            // The client must build the AES-GCM suite the gateway selected, not the default AES-CBC.
            Assert.Equal(EspEncryptionAlgorithm.AesGcm16, client.NegotiatedEsp.Algorithm);
            Assert.Equal(36, client.NegotiatedEsp.KeyMaterialLengthPerDirection); // 32-byte key + 4-byte salt

            IkeV1Phase2Keys clientKeys = client.CreatePhase2Keys();
            IkeV1Phase2Keys responderKeys = responder.CreatePhase2Keys();
            Assert.Equal(4, clientKeys.OutboundIntegrity.Length); // the GCM salt occupies the second slice
            Assert.Equal(clientKeys.OutboundEncryption, responderKeys.InboundEncryption);

            EspSession clientEsp = new(
                ToSpi(client.ChildOutboundSpi),
                client.NegotiatedEsp.BuildSuite(clientKeys.OutboundEncryption, clientKeys.OutboundIntegrity),
                ToSpi(client.ChildInboundSpi),
                client.NegotiatedEsp.BuildSuite(clientKeys.InboundEncryption, clientKeys.InboundIntegrity));
            EspSession responderEsp = new(
                ToSpi(client.ChildInboundSpi),
                client.NegotiatedEsp.BuildSuite(responderKeys.OutboundEncryption, responderKeys.OutboundIntegrity),
                ToSpi(responder.ChildInboundSpi),
                client.NegotiatedEsp.BuildSuite(responderKeys.InboundEncryption, responderKeys.InboundIntegrity));

            byte[] toServer = clientEsp.Protect(System.Text.Encoding.ASCII.GetBytes("ping via gcm"));
            Assert.True(responderEsp.TryUnprotect(toServer, out byte[] gotByServer, out _));
            Assert.Equal("ping via gcm", System.Text.Encoding.ASCII.GetString(gotByServer));

            byte[] toClient = responderEsp.Protect(System.Text.Encoding.ASCII.GetBytes("pong via gcm"));
            Assert.True(clientEsp.TryUnprotect(toClient, out byte[] gotByClient, out _));
            Assert.Equal("pong via gcm", System.Text.Encoding.ASCII.GetString(gotByClient));
        }

        [Fact]
        public void Dpd_AndDelete_RoundTripThroughDerivedIvInformationalCipher()
        {
            var client = new IkeV1Client(Psk, IPAddress.Loopback, IPAddress.Loopback);
            var responder = new SimulatedResponderV1(Psk, client.InitiatorCookie);
            DriveToQuickModeComplete(client, responder);

            // DPD: client probes; responder decrypts the Informational and reads the R-U-THERE notify.
            byte[] probe = client.BuildDpdRUThere(0x11223344);
            (ushort notifyType, uint sequence) = responder.ReadDpdNotify(probe);
            Assert.Equal(IkeV1Dpd.RUThere, notifyType);
            Assert.Equal(0x11223344u, sequence);

            // The responder answers with a DPD ACK that the client must classify as DpdAck.
            byte[] ack = responder.BuildDpdAck(sequence);
            IkeV1InformationalResult result = client.ProcessInformational(ack);
            Assert.Equal(IkeV1InformationalKind.DpdAck, result.Kind);
            Assert.Equal(sequence, result.Sequence);

            // Delete: client tears the ESP CHILD SA down; responder confirms a Delete payload for ESP.
            byte[] delete = client.BuildDeleteEsp();
            Assert.Equal(IkeV1Constants.Protocol.Esp, responder.ReadDeleteProtocol(delete));
        }

        [Fact]
        public void QuickMode_ResponderHash2Tampered_ProcessQuickMode2Throws()
        {
            var client = new IkeV1Client(Psk, IPAddress.Loopback, IPAddress.Loopback);
            var responder = new SimulatedResponderV1(Psk, client.InitiatorCookie, corruptQuickModeHash2: true);

            // Main Mode succeeds; the responder then replies to QM1 with a deliberately wrong HASH(2).
            client.ProcessMainMode2(responder.HandleMainMode1(client.BuildMainMode1()));
            client.ProcessMainMode4(responder.HandleMainMode3(client.BuildMainMode3(IPAddress.Any, IPAddress.Loopback), responder.ResponderCookie));
            Assert.True(client.ProcessMainMode6(responder.HandleMainMode5(client.BuildMainMode5())));

            byte[] qm2 = responder.HandleQuickMode1(client.BuildQuickMode1());
            Assert.Throws<VpnServerRejectedException>(() => client.ProcessQuickMode2(qm2));
        }

        [Fact]
        public void DetectNat_WhenGatewaySeesTranslatedSource_ReportsNatAndFloats()
        {
            var client = new IkeV1Client(Psk, IPAddress.Loopback, IPAddress.Loopback);
            var responder = new SimulatedResponderV1(Psk, client.InitiatorCookie);
            client.ProcessMainMode2(responder.HandleMainMode1(client.BuildMainMode1()));

            IPAddress localIp = IPAddress.Parse("198.51.100.10"), serverIp = IPAddress.Parse("203.0.113.5");
            const ushort localPort = 500, serverPort = 500;

            // The gateway reports it observed our source at port 61000 (a NAT rewrote 500) — its NAT-D for us won't
            // match our honest claim of 500, so the client must conclude there is a NAT in front of it and float.
            byte[] mm3 = client.BuildMainMode3(localIp, localPort, serverIp, serverPort);
            client.ProcessMainMode4(responder.HandleMainMode3(mm3, responder.ResponderCookie,
                observedInitiatorEndpoint: localIp, observedInitiatorPort: 61000,
                responderEndpoint: serverIp, responderPort: serverPort));

            IkeV1NatDetectionResult nat = client.DetectNat(localIp, localPort, serverIp, serverPort);
            Assert.True(nat.ServerSentNatD);
            Assert.True(nat.LocalBehindNat);
            Assert.False(nat.RemoteBehindNat);
            Assert.True(nat.ShouldFloatToNatT);
        }

        [Fact]
        public void DetectNat_WhenGatewaySeesRealSource_ReportsNoNat()
        {
            var client = new IkeV1Client(Psk, IPAddress.Loopback, IPAddress.Loopback);
            var responder = new SimulatedResponderV1(Psk, client.InitiatorCookie);
            client.ProcessMainMode2(responder.HandleMainMode1(client.BuildMainMode1()));

            IPAddress localIp = IPAddress.Parse("198.51.100.10"), serverIp = IPAddress.Parse("203.0.113.5");
            const ushort localPort = 500, serverPort = 500;

            // The gateway observed our source exactly as claimed (no NAT in the path) → no float; it expects native ESP.
            byte[] mm3 = client.BuildMainMode3(localIp, localPort, serverIp, serverPort);
            client.ProcessMainMode4(responder.HandleMainMode3(mm3, responder.ResponderCookie,
                observedInitiatorEndpoint: localIp, observedInitiatorPort: localPort,
                responderEndpoint: serverIp, responderPort: serverPort));

            IkeV1NatDetectionResult nat = client.DetectNat(localIp, localPort, serverIp, serverPort);
            Assert.True(nat.ServerSentNatD);
            Assert.False(nat.LocalBehindNat);
            Assert.False(nat.ShouldFloatToNatT);
        }

        [Fact]
        public void DetectNat_WhenGatewaySendsNoNatD_ReportsServerSentNatDFalse()
        {
            var client = new IkeV1Client(Psk, IPAddress.Loopback, IPAddress.Loopback);
            var responder = new SimulatedResponderV1(Psk, client.InitiatorCookie);
            client.ProcessMainMode2(responder.HandleMainMode1(client.BuildMainMode1()));

            // MM4 without any NAT-D (default) → the verdict reports the gateway does not do NAT-T.
            client.ProcessMainMode4(responder.HandleMainMode3(
                client.BuildMainMode3(IPAddress.Loopback, 500, IPAddress.Loopback, 500), responder.ResponderCookie));

            IkeV1NatDetectionResult nat = client.DetectNat(IPAddress.Loopback, 500, IPAddress.Loopback, 500);
            Assert.False(nat.ServerSentNatD);
            Assert.False(nat.ShouldFloatToNatT);
        }

        [Fact]
        public void Phase1Rekey_NewIsakmpSa_CarriesEsp_WhileOldStaysValidDuringGrace()
        {
            // SA #1 — the live tunnel.
            var client1 = new IkeV1Client(Psk, IPAddress.Loopback, IPAddress.Loopback);
            var responder1 = new SimulatedResponderV1(Psk, client1.InitiatorCookie);
            DriveToQuickModeComplete(client1, responder1);
            (EspSession clientEsp1, EspSession responderEsp1) = BuildEspPair(client1, responder1);

            // Phase 1 rekey: a brand-new ISAKMP SA (fresh cookie) negotiated in place via a full Main Mode + Quick Mode,
            // exactly what L2tpIpsecConnection.RekeyPhase1Async drives on the live channel.
            var client2 = new IkeV1Client(Psk, IPAddress.Loopback, IPAddress.Loopback);
            var responder2 = new SimulatedResponderV1(Psk, client2.InitiatorCookie);
            DriveToQuickModeComplete(client2, responder2);
            (EspSession clientEsp2, EspSession responderEsp2) = BuildEspPair(client2, responder2);

            // The new SA is genuinely fresh: a different initiator cookie and different CHILD SA keys.
            Assert.NotEqual(client1.InitiatorCookie, client2.InitiatorCookie);
            Assert.NotEqual(client1.CreatePhase2Keys().OutboundEncryption, client2.CreatePhase2Keys().OutboundEncryption);
            // The new SA's cookie steers its replies in the receive loop; the old SA's do not match it.
            Assert.True(client2.IsForThisSa(client2.BuildMainMode1()));
            Assert.False(client2.IsForThisSa(client1.BuildMainMode1()));

            // Make-before-break: the new SA carries traffic both directions...
            byte[] viaNew = clientEsp2.Protect(Ascii("via new SA"));
            Assert.True(responderEsp2.TryUnprotect(viaNew, out byte[] gotNew, out _));
            Assert.Equal("via new SA", Ascii(gotNew));
            byte[] backNew = responderEsp2.Protect(Ascii("reply new SA"));
            Assert.True(clientEsp2.TryUnprotect(backNew, out byte[] gotBackNew, out _));
            Assert.Equal("reply new SA", Ascii(gotBackNew));

            // ...while the old SA still decrypts in-flight packets during the grace period (no drop on rekey).
            byte[] viaOld = clientEsp1.Protect(Ascii("late on old SA"));
            Assert.True(responderEsp1.TryUnprotect(viaOld, out byte[] gotOld, out _));
            Assert.Equal("late on old SA", Ascii(gotOld));
        }

        [Fact]
        public void IsForThisSa_MatchesOwnInitiatorCookie_RejectsOthersAndShortWire()
        {
            var client = new IkeV1Client(Psk, IPAddress.Loopback, IPAddress.Loopback);
            var other = new IkeV1Client(Psk, IPAddress.Loopback, IPAddress.Loopback);
            Assert.True(client.IsForThisSa(client.BuildMainMode1()));  // our own MM1 carries our cookie in bytes 0-7
            Assert.False(client.IsForThisSa(other.BuildMainMode1()));  // a different SA's cookie
            Assert.False(client.IsForThisSa(new byte[4]));             // too short to hold an 8-byte cookie
        }

        static void DriveToQuickModeComplete(IkeV1Client client, SimulatedResponderV1 responder)
        {
            client.ProcessMainMode2(responder.HandleMainMode1(client.BuildMainMode1()));
            client.ProcessMainMode4(responder.HandleMainMode3(client.BuildMainMode3(IPAddress.Any, IPAddress.Loopback), responder.ResponderCookie));
            Assert.True(client.ProcessMainMode6(responder.HandleMainMode5(client.BuildMainMode5())));
            Assert.True(client.ProcessQuickMode2(responder.HandleQuickMode1(client.BuildQuickMode1())));
            responder.HandleQuickMode3(client.BuildQuickMode3());
        }

        // Builds the bidirectional ESP pair for a completed handshake (AES-CBC + HMAC-SHA1), mirroring the SPI orientation
        // asserted in FullMainModeAndQuickMode_ThenEspExchange_Succeeds.
        static (EspSession Client, EspSession Responder) BuildEspPair(IkeV1Client client, SimulatedResponderV1 responder)
        {
            IkeV1Phase2Keys c = client.CreatePhase2Keys();
            IkeV1Phase2Keys r = responder.CreatePhase2Keys();
            EspSession clientEsp = new(
                ToSpi(client.ChildOutboundSpi),
                EspCipherSuite.AesCbcHmacSha1(c.OutboundEncryption, c.OutboundIntegrity),
                ToSpi(client.ChildInboundSpi),
                EspCipherSuite.AesCbcHmacSha1(c.InboundEncryption, c.InboundIntegrity));
            EspSession responderEsp = new(
                ToSpi(client.ChildInboundSpi),
                EspCipherSuite.AesCbcHmacSha1(r.OutboundEncryption, r.OutboundIntegrity),
                ToSpi(responder.ChildInboundSpi),
                EspCipherSuite.AesCbcHmacSha1(r.InboundEncryption, r.InboundIntegrity));
            return (clientEsp, responderEsp);
        }

        static byte[] Ascii(string s) => System.Text.Encoding.ASCII.GetBytes(s);
        static string Ascii(byte[] b) => System.Text.Encoding.ASCII.GetString(b);

        static uint ToSpi(byte[] spi) => (uint)((spi[0] << 24) | (spi[1] << 16) | (spi[2] << 8) | spi[3]);

        static byte[] Bytes(byte seed, int length)
        {
            byte[] b = new byte[length];
            for (int i = 0; i < length; i++) b[i] = (byte)(seed + i);
            return b;
        }

        /// <summary>
        /// A minimal in-process IKEv1 (Main Mode PSK + Quick Mode) responder used only to validate the real client.
        /// It hand-rolls ISAKMP framing (the codec's chain helpers are <c>internal</c>) and reuses the public crypto
        /// helpers (<see cref="IkeV1KeyMaterial"/>, <see cref="IkeV1Auth"/>, <see cref="IkeV1QuickMode"/>, …).
        /// </summary>
        // A tiny in-memory ILogger that records each entry's event id + formatted message (mirrors the per-driver
        // CapturingLoggerFactory the runtime-driver tests use, trimmed to what this layer's assertions need).
        sealed class CapturingLogger : ILogger
        {
            readonly ConcurrentQueue<(EventId Id, string Message)> _entries = new();

            public bool Captured(EventId id) => _entries.Any(e => e.Id.Id == id.Id);
            public IReadOnlyList<string> MessagesFor(EventId id)
                => _entries.Where(e => e.Id.Id == id.Id).Select(e => e.Message).ToArray();

            public IDisposable? BeginScope<TState>(TState state) where TState : notnull => null;
            public bool IsEnabled(LogLevel logLevel) => true; // capture everything, including Trace-level ProtocolStep

            public void Log<TState>(LogLevel logLevel, EventId eventId, TState state, Exception? exception,
                Func<TState, Exception?, string> formatter)
                => _entries.Enqueue((eventId, formatter(state, exception)));
        }

        sealed class SimulatedResponderV1
        {
            const byte IdTypeIpv4 = 1;

            readonly byte[] _psk;
            readonly EspSuiteSelection _esp; // the ESP transform this responder selects in Quick Mode
            readonly bool _corruptHash2;     // when set, send a deliberately wrong QM2 HASH(2) to drive the rejection path
            readonly HashAlgorithmName _hash = HashAlgorithmName.SHA1;
            readonly HmacPrf _prf = new(HashAlgorithmName.SHA1);
            readonly ModpDhGroup _dh = ModpDhGroup.Group14(); // MM2 echoes MODP-2048 → the client uses group 14
            readonly byte[] _cookieI;
            readonly byte[] _cookieR = Bytes(0x90, 8);
            readonly byte[] _privateKey;
            readonly byte[] _keResponder;
            readonly byte[] _nonceResponder = Bytes(0x40, 16);

            byte[] _keInitiator = Array.Empty<byte>();
            byte[] _nonceInitiator = Array.Empty<byte>();
            byte[] _saInitiatorBody = Array.Empty<byte>();
            IkeV1KeyMaterial? _keys;
            IkeV1Cipher? _phase1Cipher;
            byte[] _phase1LastIv = Array.Empty<byte>();

            uint _quickModeId;
            IkeV1Cipher? _quickModeCipher;
            byte[] _quickModeNonceInitiator = Array.Empty<byte>();

            public SimulatedResponderV1(byte[] psk, byte[] initiatorCookie, EspSuiteSelection? esp = null, bool corruptQuickModeHash2 = false)
            {
                _psk = psk;
                _esp = esp ?? EspSuiteSelection.AesCbcHmacSha1();
                _corruptHash2 = corruptQuickModeHash2;
                _cookieI = initiatorCookie;
                _privateKey = _dh.GeneratePrivateKey();
                _keResponder = _dh.DerivePublicValue(_privateKey);
                ChildInboundSpi = new byte[] { 0x51, 0x52, 0x53, 0x54 };
            }

            /// <summary>The 8-byte responder cookie picked at construction.</summary>
            public byte[] ResponderCookie => _cookieR;

            /// <summary>The ESP SPI we chose (the client sends to us on it).</summary>
            public byte[] ChildInboundSpi { get; }

            /// <summary>The ESP SPI the client chose (we send to it on it).</summary>
            public byte[] ChildOutboundSpi { get; private set; } = Array.Empty<byte>();

            // ---- Main Mode ----

            /// <summary>MM2: echo the FIRST transform of the client's proposal (AES-256/SHA1/MODP-2048) + the RFC 3947 VID.</summary>
            public byte[] HandleMainMode1(byte[] mm1)
            {
                IsakmpMessage request = IsakmpMessage.Decode(mm1);
                // The HASH inputs use the client's exact MM1 SA body; reconstruct it the same way the client did.
                _saInitiatorBody = IkeV1Proposals.Phase1().BodyBytes();

                IsakmpProposal clientProposal = request.Find<IsakmpSaPayload>()!.Proposals[0];
                IsakmpTransform first = clientProposal.Transforms[0]; // AES-256 + SHA1 + MODP-2048

                var chosenProposal = new IsakmpProposal
                {
                    Number = clientProposal.Number,
                    ProtocolId = clientProposal.ProtocolId,
                    Spi = clientProposal.Spi,
                };
                var chosenTransform = new IsakmpTransform(first.Number, first.TransformId);
                foreach (IsakmpAttribute attribute in first.Attributes) chosenTransform.Attributes.Add(attribute);
                chosenProposal.Transforms.Add(chosenTransform);

                var sa = new IsakmpSaPayload();
                sa.Proposals.Add(chosenProposal);

                var payloads = new List<IsakmpPayload>
                {
                    sa,
                    new IsakmpRawPayload(IsakmpPayloadType.VendorId, IkeV1NatDetection.VendorIdRfc3947),
                };
                return EncodeClear(IsakmpExchangeType.MainMode, 0, payloads);
            }

            /// <summary>MM4: read KE_i + Ni, then build KE_r + Nr, derive the key set, and arm the Phase-1 cipher.</summary>
            /// <remarks>
            /// When <paramref name="observedInitiatorEndpoint"/> is set, two RFC 3947 NAT-D payloads are appended:
            /// #1 = the initiator endpoint as this responder claims to have observed it (drive a NAT verdict by passing
            /// a port/address that differs from what the client claims), #2 = this responder's own endpoint.
            /// </remarks>
            public byte[] HandleMainMode3(byte[] mm4Input, byte[] cookieR,
                IPAddress? observedInitiatorEndpoint = null, ushort observedInitiatorPort = 0,
                IPAddress? responderEndpoint = null, ushort responderPort = 0)
            {
                _ = cookieR; // the responder cookie is fixed at construction; the parameter only documents intent.
                IsakmpMessage request = IsakmpMessage.Decode(mm4Input);
                _keInitiator = request.FindRaw(IsakmpPayloadType.KeyExchange)!.Body;
                _nonceInitiator = request.FindRaw(IsakmpPayloadType.Nonce)!.Body;

                byte[] shared = _dh.DeriveSharedSecret(_privateKey, _keInitiator);
                _keys = IkeV1KeyMaterial.DeriveMainMode(
                    _hash, _psk, _nonceInitiator, _nonceResponder, shared,
                    _cookieI, _cookieR, _keInitiator, _keResponder, cipherKeyLength: 32, blockSize: 16);
                _phase1Cipher = new IkeV1Cipher(_keys.CipherKey, _keys.InitialIv);

                // KE_r + Nr always; the NAT-D pair only when a test wants to exercise the NAT verdict.
                var payloads = new List<IsakmpPayload>
                {
                    new IsakmpRawPayload(IsakmpPayloadType.KeyExchange, _keResponder),
                    new IsakmpRawPayload(IsakmpPayloadType.Nonce, _nonceResponder),
                };
                if (observedInitiatorEndpoint != null)
                {
                    payloads.Add(new IsakmpRawPayload(IsakmpPayloadType.NatDiscovery,
                        IkeV1NatDetection.ComputeHash(_hash, _cookieI, _cookieR, observedInitiatorEndpoint, observedInitiatorPort)));
                    payloads.Add(new IsakmpRawPayload(IsakmpPayloadType.NatDiscovery,
                        IkeV1NatDetection.ComputeHash(_hash, _cookieI, _cookieR, responderEndpoint ?? IPAddress.Loopback, responderPort)));
                }
                return EncodeClear(IsakmpExchangeType.MainMode, 0, payloads);
            }

            /// <summary>MM5: decrypt, verify HASH_I, then build the encrypted MM6 (IDr + HASH_R).</summary>
            public byte[] HandleMainMode5(byte[] mm5)
            {
                List<IsakmpPayload> payloads = DecryptChain(_phase1Cipher!, mm5);
                byte[] idiBody = Raw(payloads, IsakmpPayloadType.Identification);
                byte[] hashI = Raw(payloads, IsakmpPayloadType.Hash);

                byte[] expectedHashI = IkeV1Auth.ComputeHashI(
                    _prf, _keys!.Skeyid, _keInitiator, _keResponder, _cookieI, _cookieR, _saInitiatorBody, idiBody);
                Assert.Equal(expectedHashI, hashI); // the client authenticated correctly

                byte[] idrBody = IdBody(IdTypeIpv4, 0, 0, IPAddress.Parse("10.0.0.1").GetAddressBytes());
                byte[] hashR = IkeV1Auth.ComputeHashR(
                    _prf, _keys.Skeyid, _keInitiator, _keResponder, _cookieI, _cookieR, _saInitiatorBody, idrBody);

                var inner = new List<IsakmpPayload>
                {
                    new IsakmpRawPayload(IsakmpPayloadType.Identification, idrBody),
                    new IsakmpRawPayload(IsakmpPayloadType.Hash, hashR),
                };
                byte[] mm6 = EncodeEncrypted(_phase1Cipher!, IsakmpExchangeType.MainMode, 0, inner);
                _phase1LastIv = _phase1Cipher!.CurrentIv; // seeds every later derived-IV (QM / Informational) cipher
                return mm6;
            }

            // ---- Quick Mode ----

            /// <summary>QM1: decrypt with the derived QM IV, capture the client's ESP SPI + Ni, build QM2 (HASH(2)+SA+Nr).</summary>
            public byte[] HandleQuickMode1(byte[] qm1)
            {
                _quickModeId = IsakmpMessage.Decode(qm1).MessageId; // header is in the clear even when encrypted
                _quickModeCipher = NewQuickModeCipher(_quickModeId);

                List<IsakmpPayload> payloads = DecryptChain(_quickModeCipher, qm1);
                IsakmpSaPayload sa = payloads.OfType<IsakmpSaPayload>().First();
                ChildOutboundSpi = sa.Proposals[0].Spi; // the client's inbound ESP SPI; our outbound
                _quickModeNonceInitiator = Raw(payloads, IsakmpPayloadType.Nonce);

                // The payloads after HASH(2) on the wire, in order: SA(ESP, our SPI, single selected transform) then Nr.
                var afterHash = new List<IsakmpPayload>
                {
                    BuildSelectedEspSa(),
                    new IsakmpRawPayload(IsakmpPayloadType.Nonce, _nonceResponder),
                };
                byte[] afterHashBytes = EncodeChain(afterHash);
                byte[] hash2 = IkeV1QuickMode.ComputeHash2(
                    _prf, _keys!.SkeyidA, _quickModeId, _quickModeNonceInitiator, afterHashBytes);
                if (_corruptHash2) hash2[0] ^= 0xFF; // flip a byte → the client must reject this QM2

                var inner = new List<IsakmpPayload> { new IsakmpRawPayload(IsakmpPayloadType.Hash, hash2) };
                inner.AddRange(afterHash);
                return EncodeEncrypted(_quickModeCipher, IsakmpExchangeType.QuickMode, _quickModeId, inner);
            }

            /// <summary>QM3: decrypt with the same QM cipher (IV advanced) and verify HASH(3).</summary>
            public void HandleQuickMode3(byte[] qm3)
            {
                List<IsakmpPayload> payloads = DecryptChain(_quickModeCipher!, qm3);
                byte[] hash3 = Raw(payloads, IsakmpPayloadType.Hash);
                byte[] expected = IkeV1QuickMode.ComputeHash3(
                    _prf, _keys!.SkeyidA, _quickModeId, _quickModeNonceInitiator, _nonceResponder);
                Assert.Equal(expected, hash3);
            }

            /// <summary>Derives the ESP CHILD SA keys for the selected suite, mirroring the client's SPI orientation.</summary>
            public IkeV1Phase2Keys CreatePhase2Keys()
                => IkeV1Phase2Keys.Derive(_prf, _keys!.SkeyidD, IkeV1Constants.Protocol.Esp,
                    ChildInboundSpi, ChildOutboundSpi, _quickModeNonceInitiator, _nonceResponder,
                    _esp.EncryptionKeyLengthBytes, _esp.SecondSliceLengthBytes);

            // Builds the QM2 SA carrying exactly one ESP transform — the suite this responder selected (_esp).
            IsakmpSaPayload BuildSelectedEspSa()
            {
                ushort keyBits = (ushort)(_esp.EncryptionKeyLengthBytes * 8);
                IsakmpTransform transform;
                if (_esp.Algorithm == EspEncryptionAlgorithm.AesGcm16)
                {
                    transform = new IsakmpTransform(1, IkeV1Constants.EspTransform.AesGcm16)
                        .With(IsakmpAttribute.Tv(IkeV1Constants.Phase2Attribute.KeyLength, keyBits))
                        .With(IsakmpAttribute.Tv(IkeV1Constants.Phase2Attribute.EncapsulationMode, IkeV1Constants.EncapsulationMode.UdpTransport));
                }
                else
                {
                    ushort auth = _esp.SecondSliceLengthBytes == 32
                        ? IkeV1Constants.AuthAlgorithm.HmacSha2_256
                        : IkeV1Constants.AuthAlgorithm.HmacSha1;
                    transform = new IsakmpTransform(1, IkeV1Constants.EspTransform.Aes)
                        .With(IsakmpAttribute.Tv(IkeV1Constants.Phase2Attribute.KeyLength, keyBits))
                        .With(IsakmpAttribute.Tv(IkeV1Constants.Phase2Attribute.AuthAlgorithm, auth))
                        .With(IsakmpAttribute.Tv(IkeV1Constants.Phase2Attribute.EncapsulationMode, IkeV1Constants.EncapsulationMode.UdpTransport));
                }
                var proposal = new IsakmpProposal { Number = 1, ProtocolId = IkeV1Constants.Protocol.Esp, Spi = ChildInboundSpi };
                proposal.Transforms.Add(transform);
                var sa = new IsakmpSaPayload();
                sa.Proposals.Add(proposal);
                return sa;
            }

            // ---- Informational (DPD / Delete) ----

            /// <summary>Decrypts an Informational message and returns the DPD notify (type, sequence) it carries.</summary>
            public (ushort, uint) ReadDpdNotify(byte[] wire)
            {
                List<IsakmpPayload> payloads = DecryptInformational(wire);
                byte[] notifyBody = Raw(payloads, IsakmpPayloadType.Notification);
                Assert.True(IkeV1Dpd.TryParseNotify(notifyBody, out ushort notifyType, out uint sequence));
                return (notifyType, sequence);
            }

            /// <summary>Builds an encrypted DPD R-U-THERE-ACK the way the client's ProcessInformational expects it.</summary>
            public byte[] BuildDpdAck(uint sequence)
            {
                uint messageId = 0x55667788;
                byte[] notifyBody = IkeV1Dpd.BuildNotifyBody(_cookieI, _cookieR, IkeV1Dpd.RUThereAck, sequence);
                var afterHash = new List<IsakmpPayload> { new IsakmpRawPayload(IsakmpPayloadType.Notification, notifyBody) };
                byte[] hash = IkeV1QuickMode.ComputeHash1(_prf, _keys!.SkeyidA, messageId, EncodeChain(afterHash));

                var inner = new List<IsakmpPayload> { new IsakmpRawPayload(IsakmpPayloadType.Hash, hash) };
                inner.AddRange(afterHash);
                return EncodeEncrypted(NewQuickModeCipher(messageId), IsakmpExchangeType.Informational, messageId, inner);
            }

            /// <summary>Decrypts an Informational message and returns the protocol of the Delete payload it carries.</summary>
            public byte ReadDeleteProtocol(byte[] wire)
            {
                List<IsakmpPayload> payloads = DecryptInformational(wire);
                byte[] deleteBody = Raw(payloads, IsakmpPayloadType.Delete);
                return deleteBody[4]; // Delete body: DOI(4) | Protocol(1) | …
            }

            List<IsakmpPayload> DecryptInformational(byte[] wire)
            {
                uint messageId = IsakmpMessage.Decode(wire).MessageId;
                return DecryptChain(NewQuickModeCipher(messageId), wire);
            }

            // A QM / Informational message derives its IV from the last Phase-1 IV and its message id (RFC 2409 §5.5).
            IkeV1Cipher NewQuickModeCipher(uint messageId)
                => new IkeV1Cipher(_keys!.CipherKey, IkeV1Cipher.QuickModeIv(_hash, _phase1LastIv, messageId));

            // ---- hand-rolled ISAKMP framing (codec chain helpers are internal) ----

            byte[] EncodeClear(IsakmpExchangeType exchange, uint messageId, List<IsakmpPayload> payloads)
            {
                byte[] body = EncodeChain(payloads);
                return Frame(exchange, IsakmpFlags.None, messageId, payloads[0].Type, body);
            }

            byte[] EncodeEncrypted(IkeV1Cipher cipher, IsakmpExchangeType exchange, uint messageId, List<IsakmpPayload> payloads)
            {
                byte[] ciphertext = cipher.Encrypt(EncodeChain(payloads));
                return Frame(exchange, IsakmpFlags.Encryption, messageId, payloads[0].Type, ciphertext);
            }

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
                    output.Add(0);          // reserved
                    output.Add(0); output.Add(0); // length placeholder (filled below)
                    payloads[i].WriteBody(output);
                    int length = output.Count - start;
                    output[start + 2] = (byte)(length >> 8);
                    output[start + 3] = (byte)length;
                }
                return output.ToArray();
            }

            // The SA-payload parser (IsakmpSaPayload.Parse) is internal, so to parse a decrypted chain we re-frame the
            // plaintext as a cleartext ISAKMP message (header + body, no Encryption flag) and use the public
            // IsakmpMessage.Decode, which drives the real codec — including the SA payload parser — for us.
            List<IsakmpPayload> ParseChain(byte[] body, IsakmpPayloadType firstType)
            {
                byte[] cleartext = Frame(IsakmpExchangeType.QuickMode, IsakmpFlags.None, 0, firstType, body);
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
