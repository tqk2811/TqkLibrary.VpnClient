using System.Net;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using TqkLibrary.VpnClient.Abstractions.Drivers;
using TqkLibrary.VpnClient.Crypto;
using TqkLibrary.VpnClient.Ipsec.Esp;
using TqkLibrary.VpnClient.Ipsec.Ike.V2;
using TqkLibrary.VpnClient.Ipsec.Ike.V2.Enums;
using TqkLibrary.VpnClient.Ipsec.Ike.V2.Models;
using TqkLibrary.VpnClient.Ipsec.Ike.V2.Payloads;
using Xunit;

namespace TqkLibrary.VpnClient.Ipsec.Ike.Tests
{
    /// <summary>
    /// Exercises the IKEv2 client's <b>responder certificate</b> authentication (RFC 7296 §2.15, digital-signature
    /// method 1): a simulated responder signs its AUTH with an RSA key and returns its certificate in a CERT payload;
    /// the real <see cref="IkeClient"/> validates that certificate against a configured trust anchor and verifies the
    /// signature with the certificate's public key. Plus multi-traffic-selector (RFC 7296 §3.13). Self-interop with a
    /// test PKI generated in-process — no live gateway / strongSwan needed.
    /// </summary>
    public class IkeCertAuthHandshakeTests
    {
        static readonly byte[] Psk = System.Text.Encoding.ASCII.GetBytes("vpn");

        [Fact]
        public void ResponderCertAuth_WithTrustedCert_VerifiesSignatureAndCarriesEsp()
        {
            using X509Certificate2 serverCert = TestPki.SelfSignedServer("CN=gateway.example");
            var client = new IkeClient(Psk, IpId(), requestTransportMode: false, requestConfiguration: true,
                responderTrust: IkeCertificateTrust.PinLeaf(PublicOnly(serverCert)));
            var responder = new SimulatedCertResponder(Psk, serverCert);

            client.ProcessInitResponse(IkeMessage.Decode(
                responder.HandleInit(client.BuildInitRequest(IPAddress.Loopback, 4500, IPAddress.Loopback, 4500).Encode())));

            // The client must have asked for a certificate (CERTREQ) in IKE_AUTH.
            byte[] authRequest = client.BuildAuthRequest();
            Assert.True(responder.SawCertificateRequest(authRequest));

            Assert.True(client.ProcessAuthResponse(responder.HandleAuth(authRequest)));
            Assert.NotNull(client.ResponderCertificate);
            Assert.Equal(serverCert.Thumbprint, client.ResponderCertificate!.Thumbprint);

            // The CHILD_SA keyed by the cert-authenticated handshake protects traffic both ways.
            EspSession clientEsp = BuildInitiatorEsp(client);
            EspSession responderEsp = responder.BuildEsp();
            byte[] toServer = clientEsp.Protect(System.Text.Encoding.ASCII.GetBytes("cert ping"));
            Assert.True(responderEsp.TryUnprotect(toServer, out byte[] got, out _));
            Assert.Equal("cert ping", System.Text.Encoding.ASCII.GetString(got));
        }

        [Fact]
        public void ResponderCertAuth_WithCaTrust_AcceptsLeafChainingToTrustedCa()
        {
            using X509Certificate2 ca = TestPki.SelfSignedCa("CN=Test Root CA");
            using X509Certificate2 leaf = TestPki.IssuedBy(ca, "CN=gateway.example");
            var client = new IkeClient(Psk, IpId(), requestTransportMode: false, requestConfiguration: true,
                responderTrust: IkeCertificateTrust.TrustCa(PublicOnly(ca)));
            var responder = new SimulatedCertResponder(Psk, leaf);

            client.ProcessInitResponse(IkeMessage.Decode(
                responder.HandleInit(client.BuildInitRequest(IPAddress.Loopback, 4500, IPAddress.Loopback, 4500).Encode())));
            Assert.True(client.ProcessAuthResponse(responder.HandleAuth(client.BuildAuthRequest())));
            Assert.Equal(leaf.Thumbprint, client.ResponderCertificate!.Thumbprint);
        }

        [Fact]
        public void ResponderCertAuth_WithUntrustedCert_IsRejected()
        {
            using X509Certificate2 serverCert = TestPki.SelfSignedServer("CN=gateway.example");
            using X509Certificate2 otherCert = TestPki.SelfSignedServer("CN=other.example");
            // The gateway signs with serverCert, but the client only trusts an unrelated certificate.
            var client = new IkeClient(Psk, IpId(), requestTransportMode: false, requestConfiguration: true,
                responderTrust: IkeCertificateTrust.PinLeaf(PublicOnly(otherCert)));
            var responder = new SimulatedCertResponder(Psk, serverCert);

            client.ProcessInitResponse(IkeMessage.Decode(
                responder.HandleInit(client.BuildInitRequest(IPAddress.Loopback, 4500, IPAddress.Loopback, 4500).Encode())));

            byte[] authResponse = responder.HandleAuth(client.BuildAuthRequest());
            VpnServerRejectedException ex = Assert.Throws<VpnServerRejectedException>(() => client.ProcessAuthResponse(authResponse));
            Assert.Contains("not trusted", ex.Message);
            Assert.Null(client.ResponderCertificate);
        }

        [Fact]
        public void ResponderCertAuth_WithTamperedSignature_IsRejected()
        {
            using X509Certificate2 serverCert = TestPki.SelfSignedServer("CN=gateway.example");
            var client = new IkeClient(Psk, IpId(), requestTransportMode: false, requestConfiguration: true,
                responderTrust: IkeCertificateTrust.PinLeaf(PublicOnly(serverCert)));
            var responder = new SimulatedCertResponder(Psk, serverCert) { CorruptSignature = true };

            client.ProcessInitResponse(IkeMessage.Decode(
                responder.HandleInit(client.BuildInitRequest(IPAddress.Loopback, 4500, IPAddress.Loopback, 4500).Encode())));

            byte[] authResponse = responder.HandleAuth(client.BuildAuthRequest());
            VpnServerRejectedException ex = Assert.Throws<VpnServerRejectedException>(() => client.ProcessAuthResponse(authResponse));
            Assert.Contains("signature did not verify", ex.Message);
        }

        [Fact]
        public void ResponderCertAuth_WhenGatewayFallsBackToPsk_IsRejectedAsDowngrade()
        {
            using X509Certificate2 serverCert = TestPki.SelfSignedServer("CN=gateway.example");
            var client = new IkeClient(Psk, IpId(), requestTransportMode: false, requestConfiguration: true,
                responderTrust: IkeCertificateTrust.PinLeaf(PublicOnly(serverCert)));
            // A responder that authenticates with a PSK AUTH even though the client required a certificate.
            var responder = new SimulatedCertResponder(Psk, serverCert) { AuthenticateWithPsk = true };

            client.ProcessInitResponse(IkeMessage.Decode(
                responder.HandleInit(client.BuildInitRequest(IPAddress.Loopback, 4500, IPAddress.Loopback, 4500).Encode())));

            byte[] authResponse = responder.HandleAuth(client.BuildAuthRequest());
            VpnServerRejectedException ex = Assert.Throws<VpnServerRejectedException>(() => client.ProcessAuthResponse(authResponse));
            Assert.Contains("downgrade", ex.Message);
        }

        [Fact]
        public void PskAuth_StillWorks_WhenNoTrustConfigured()
        {
            // Without a trust anchor the client behaves exactly as before: PSK responder AUTH, no CERTREQ.
            var client = new IkeClient(Psk, IpId(), requestTransportMode: false, requestConfiguration: true);
            using X509Certificate2 unused = TestPki.SelfSignedServer("CN=ignored");
            var responder = new SimulatedCertResponder(Psk, unused) { AuthenticateWithPsk = true };

            client.ProcessInitResponse(IkeMessage.Decode(
                responder.HandleInit(client.BuildInitRequest(IPAddress.Loopback, 4500, IPAddress.Loopback, 4500).Encode())));

            byte[] authRequest = client.BuildAuthRequest();
            Assert.False(responder.SawCertificateRequest(authRequest)); // no CERTREQ when no trust configured
            Assert.True(client.ProcessAuthResponse(responder.HandleAuth(authRequest)));
            Assert.Null(client.ResponderCertificate);
        }

        [Fact]
        public void MultiTrafficSelector_OffersEveryConfiguredSubnet()
        {
            var initiatorSelectors = new[]
            {
                TrafficSelectorPayload.Subnet(IPAddress.Parse("10.0.0.0"), 8),
                TrafficSelectorPayload.Subnet(IPAddress.Parse("192.168.1.0"), 24),
            };
            var client = new IkeClient(Psk, IpId(), requestTransportMode: false, requestConfiguration: true,
                initiatorSelectors: initiatorSelectors);
            var responder = new SimulatedCertResponder(Psk, null) { AuthenticateWithPsk = true };

            client.ProcessInitResponse(IkeMessage.Decode(
                responder.HandleInit(client.BuildInitRequest(IPAddress.Loopback, 4500, IPAddress.Loopback, 4500).Encode())));

            TrafficSelectorPayload tsi = responder.DecodeInitiatorTs(client.BuildAuthRequest());
            Assert.Equal(2, tsi.Selectors.Count);
            Assert.Equal(IPAddress.Parse("10.0.0.0"), tsi.Selectors[0].StartAddress);
            Assert.Equal(IPAddress.Parse("10.255.255.255"), tsi.Selectors[0].EndAddress);
            Assert.Equal(IPAddress.Parse("192.168.1.0"), tsi.Selectors[1].StartAddress);
            Assert.Equal(IPAddress.Parse("192.168.1.255"), tsi.Selectors[1].EndAddress);
        }

        [Fact]
        public void Subnet_ComputesInclusiveAddressRange()
        {
            TrafficSelector ts = TrafficSelectorPayload.Subnet(IPAddress.Parse("172.16.5.0"), 22);
            Assert.Equal(IPAddress.Parse("172.16.4.0"), ts.StartAddress);
            Assert.Equal(IPAddress.Parse("172.16.7.255"), ts.EndAddress);

            TrafficSelector all = TrafficSelectorPayload.Subnet(IPAddress.Parse("0.0.0.0"), 0);
            Assert.Equal(IPAddress.Parse("0.0.0.0"), all.StartAddress);
            Assert.Equal(IPAddress.Parse("255.255.255.255"), all.EndAddress);
        }

        // ---- helpers ----

        static IdentificationPayload IpId()
            => new() { IsInitiator = true, IdType = IkeIdType.Ipv4Address, Data = new byte[] { 0, 0, 0, 0 } };

        // A public-key-only copy (as the wire CERT carries no private key) so trust matching mirrors production.
        static X509Certificate2 PublicOnly(X509Certificate2 cert) => new(cert.Export(X509ContentType.Cert));

        static EspSession BuildInitiatorEsp(IkeClient client)
        {
            ChildSaKeys k = client.ChildKeys!;
            EspSuiteSelection esp = client.NegotiatedEsp!;
            EspCipherSuite send = esp.BuildSuite(k.EncryptionInitiator, k.IntegrityInitiator);
            EspCipherSuite receive = esp.BuildSuite(k.EncryptionResponder, k.IntegrityResponder);
            return new EspSession(ToSpi(client.ChildOutboundSpi), send, ToSpi(client.ChildInboundSpi), receive);
        }

        static uint ToSpi(byte[] spi) => (uint)((spi[0] << 24) | (spi[1] << 16) | (spi[2] << 8) | spi[3]);

        /// <summary>A tiny in-process PKI for the tests: self-signed leaf, a CA, and CA-issued leaves.</summary>
        static class TestPki
        {
            public static X509Certificate2 SelfSignedServer(string subject)
            {
                using var rsa = RSA.Create(2048);
                var request = new CertificateRequest(subject, rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
                using X509Certificate2 cert = request.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddDays(1));
                return new X509Certificate2(cert.Export(X509ContentType.Pfx));
            }

            public static X509Certificate2 SelfSignedCa(string subject)
            {
                using var rsa = RSA.Create(2048);
                var request = new CertificateRequest(subject, rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
                request.CertificateExtensions.Add(new X509BasicConstraintsExtension(true, false, 0, true));
                request.CertificateExtensions.Add(new X509KeyUsageExtension(X509KeyUsageFlags.KeyCertSign, true));
                using X509Certificate2 cert = request.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddDays(2));
                return new X509Certificate2(cert.Export(X509ContentType.Pfx));
            }

            public static X509Certificate2 IssuedBy(X509Certificate2 ca, string subject)
            {
                using var rsa = RSA.Create(2048);
                var request = new CertificateRequest(subject, rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
                request.CertificateExtensions.Add(new X509BasicConstraintsExtension(false, false, 0, false));
                byte[] serial = new byte[8];
                RandomNumberGenerator.Fill(serial);
                using X509Certificate2 issued = request.Create(ca, DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddDays(1), serial);
                using X509Certificate2 withKey = issued.CopyWithPrivateKey(rsa);
                return new X509Certificate2(withKey.Export(X509ContentType.Pfx));
            }
        }

        /// <summary>An in-process responder that authenticates by certificate (RSA digital signature) or by PSK.</summary>
        sealed class SimulatedCertResponder
        {
            readonly HmacPrf _prf = HmacPrf.Sha256();
            readonly ModpDhGroup _dh = ModpDhGroup.Group14();
            readonly byte[] _psk;
            readonly X509Certificate2? _certificate;
            readonly EspSuiteSelection _esp = EspSuiteSelection.AesCbcHmacSha256();
            readonly byte[] _privateKey;
            readonly byte[] _publicKey;
            readonly byte[] _spi = new byte[8];
            readonly byte[] _nonce;

            byte[] _initResponseWire = Array.Empty<byte>();
            byte[] _initiatorNonce = Array.Empty<byte>();
            byte[] _initiatorSpi = new byte[8];
            IkeKeyMaterial? _keys;
            IkeCipher? _cipher;

            public SimulatedCertResponder(byte[] psk, X509Certificate2? certificate)
            {
                _psk = psk;
                _certificate = certificate;
                _privateKey = _dh.GeneratePrivateKey();
                _publicKey = _dh.DerivePublicValue(_privateKey);
                for (int i = 0; i < 8; i++) _spi[i] = (byte)(0x90 + i);
                _nonce = new byte[32];
                for (int i = 0; i < 32; i++) _nonce[i] = (byte)(0xC0 + i);
                ChildInboundSpi = new byte[] { 0x77, 0x66, 0x55, 0x44 };
            }

            /// <summary>When true the responder uses a PSK AUTH (Shared Key) instead of a digital signature.</summary>
            public bool AuthenticateWithPsk { get; set; }

            /// <summary>When true the responder flips a bit in its signature, simulating tampering / a wrong key.</summary>
            public bool CorruptSignature { get; set; }

            public byte[] ChildInboundSpi { get; }
            public byte[] ChildOutboundSpi { get; private set; } = Array.Empty<byte>();

            public bool SawCertificateRequest(byte[] authRequestWire)
                => _cipher!.DecryptMessage(authRequestWire)!.Find<CertificateRequestPayload>() is not null;

            public TrafficSelectorPayload DecodeInitiatorTs(byte[] authRequestWire)
                => _cipher!.DecryptMessage(authRequestWire)!.Payloads.OfType<TrafficSelectorPayload>().First(p => p.IsInitiator);

            public byte[] HandleInit(byte[] requestWire)
            {
                IkeMessage request = IkeMessage.Decode(requestWire);
                _initiatorSpi = request.InitiatorSpi;
                _initiatorNonce = request.Find<NoncePayload>()!.Nonce;
                byte[] initiatorPublic = request.Find<KeyExchangePayload>()!.KeyData;

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
                response.Payloads.Add(new KeyExchangePayload { DiffieHellmanGroup = IkeTransformId.DiffieHellman.Modp2048, KeyData = _publicKey });
                response.Payloads.Add(new NoncePayload { Nonce = _nonce });

                _initResponseWire = response.Encode();
                byte[] shared = _dh.DeriveSharedSecret(_privateKey, initiatorPublic);
                _keys = IkeKeyMaterial.DeriveDefault(_initiatorNonce, _nonce, shared, _initiatorSpi, _spi);
                _cipher = IkeCipher.ForResponder(_keys);
                return _initResponseWire;
            }

            public byte[] HandleAuth(byte[] requestWire)
            {
                IkeMessage request = _cipher!.DecryptMessage(requestWire)!;
                ChildOutboundSpi = request.Find<SecurityAssociationPayload>()!.Proposals.First().Spi;

                var idR = new IdentificationPayload { IsInitiator = false, IdType = IkeIdType.Fqdn, Data = System.Text.Encoding.ASCII.GetBytes("gateway.example") };

                var response = new IkeMessage
                {
                    InitiatorSpi = _initiatorSpi,
                    ResponderSpi = _spi,
                    ExchangeType = IkeExchangeType.IkeAuth,
                    Flags = IkeHeaderFlags.Response,
                    MessageId = 1,
                };
                response.Payloads.Add(idR);

                if (AuthenticateWithPsk)
                {
                    byte[] pskAuth = IkePskAuth.ComputeResponderAuth(_prf, _psk, _initResponseWire, _initiatorNonce, _keys!.SkPr, idR.BodyBytes());
                    response.Payloads.Add(new AuthenticationPayload { Method = IkeAuthMethod.SharedKey, Data = pskAuth });
                }
                else
                {
                    // Digital signature (RFC 7296 method 1): sign the responder signed-octets with the cert's RSA key.
                    response.Payloads.Add(new CertificatePayload { Encoding = IkeCertificateEncoding.X509CertificateSignature, Data = _certificate!.Export(X509ContentType.Cert) });
                    byte[] signedOctets = IkePskAuth.ComputeSignedOctets(_prf, _initResponseWire, _initiatorNonce, _keys!.SkPr, idR.BodyBytes());
                    using RSA rsa = _certificate.GetRSAPrivateKey()!;
                    byte[] signature = rsa.SignData(signedOctets, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
                    if (CorruptSignature) signature[0] ^= 0xFF;
                    response.Payloads.Add(new AuthenticationPayload { Method = IkeAuthMethod.RsaSignature, Data = signature });
                }

                var saR = new SecurityAssociationPayload();
                saR.Proposals.Add(IkeProposals.DefaultEsp(ChildInboundSpi));
                response.Payloads.Add(saR);
                response.Payloads.Add(TrafficSelectorPayload.AnyIpv4(isInitiator: true));
                response.Payloads.Add(TrafficSelectorPayload.AnyIpv4(isInitiator: false));
                return _cipher.EncryptMessage(response);
            }

            public EspSession BuildEsp()
            {
                ChildSaKeys k = ChildSaKeys.Derive(_prf, _keys!.SkD, _initiatorNonce, _nonce, _esp.EncryptionKeyLengthBytes, _esp.SecondSliceLengthBytes);
                EspCipherSuite send = _esp.BuildSuite(k.EncryptionResponder, k.IntegrityResponder);
                EspCipherSuite receive = _esp.BuildSuite(k.EncryptionInitiator, k.IntegrityInitiator);
                return new EspSession(ToSpi(ChildOutboundSpi), send, ToSpi(ChildInboundSpi), receive);
            }
        }
    }
}
