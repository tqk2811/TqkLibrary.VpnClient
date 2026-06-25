using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Operators;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Tls;
using Org.BouncyCastle.Tls.Crypto;
using Org.BouncyCastle.Tls.Crypto.Impl.BC;
using Org.BouncyCastle.X509;
using TqkLibrary.VpnClient.OpenVpn;
using TqkLibrary.VpnClient.OpenVpn.DataChannel;
using TqkLibrary.VpnClient.OpenVpn.Enums;
using TqkLibrary.VpnClient.OpenVpn.Models;
using BcX509Certificate = Org.BouncyCastle.X509.X509Certificate;

namespace TqkLibrary.VpnClient.OpenVpn.Tests
{
    /// <summary>
    /// A throwaway OpenVPN responder whose control-channel TLS runs over <b>BouncyCastle</b> (<see cref="TlsServerProtocol"/>),
    /// so — unlike the SslStream-based <c>SimulatedOpenVpnServer</c> — it can compute the RFC 5705 keying-material exporter
    /// the tls-ekm self-pair test needs. It answers HARD_RESET_CLIENT_V2 with HARD_RESET_SERVER_V2, acks every client
    /// control packet, runs a server BC TLS handshake over its own in-order bridge, and after the handshake exposes
    /// <see cref="ExportKeyingMaterial"/> so the test can assert the server derives the same data-channel key material the
    /// client does. This is test-only harness code (a client library — no server product code).
    /// </summary>
    sealed class SimulatedBouncyCastleOpenVpnServer : IDisposable
    {
        readonly IOpenVpnTransport _transport;
        readonly object _sync = new();
        readonly ServerBridgeStream _bridge = new();
        readonly TlsServerProtocol _protocol;
        readonly ExporterTlsServer _server;
        ulong _clientSessionId;
        uint _sendNext;     // our reliability packet-id stream (0 = our reset)
        uint _recvNext;     // next client packet-id we expect
        bool _resetSent;

        public ulong SessionId { get; } = 0x1122334455667788UL;

        public SimulatedBouncyCastleOpenVpnServer(IOpenVpnTransport transport)
        {
            _transport = transport;
            _transport.DatagramReceived += OnDatagram;
            _bridge.Send = SendTls;

            var crypto = new BcTlsCrypto(new SecureRandom());
            _server = new ExporterTlsServer(crypto);
            _protocol = new TlsServerProtocol(_bridge);
            _ = Task.Run(RunHandshake);
        }

        /// <summary>True once the BC server handshake has completed (the exporter is then valid).</summary>
        public bool HandshakeComplete => _server.HandshakeComplete;

        /// <summary>The RFC 5705 export captured at the server's handshake-complete (mirrors the client engine).</summary>
        public byte[] ExportKeyingMaterial(string label, int length) => _server.Export(label, length);

        void RunHandshake()
        {
            try { _protocol.Accept(_server); } catch { /* torn down at end of test */ }
        }

        void OnDatagram(ReadOnlyMemory<byte> datagram)
        {
            if (!OpenVpnPacketCodec.TryDecodeControl(datagram.Span, out OpenVpnControlPacket packet)) return;

            byte[]? wire = null;
            byte[]? deliver = null;
            lock (_sync)
            {
                if (_clientSessionId == 0 && packet.SessionId != 0) _clientSessionId = packet.SessionId;

                if (packet.Opcode == OpenVpnOpcode.ControlHardResetClientV2)
                {
                    if (!_resetSent)
                    {
                        _resetSent = true;
                        _recvNext = packet.PacketId + 1;
                        wire = Encode(OpenVpnOpcode.ControlHardResetServerV2, _sendNext++, new[] { packet.PacketId }, Array.Empty<byte>());
                    }
                    else wire = EncodeAck(new[] { packet.PacketId });
                }
                else if (!packet.IsAckOnly && packet.PacketId == _recvNext)
                {
                    _recvNext++;
                    deliver = packet.Payload;
                    wire = EncodeAck(new[] { packet.PacketId });
                }
                else if (!packet.IsAckOnly)
                {
                    wire = EncodeAck(new[] { packet.PacketId }); // duplicate/out-of-order: re-ack only
                }
            }

            if (deliver is { Length: > 0 }) _bridge.EnqueueInbound(deliver);
            if (wire != null) Send(wire);
        }

        void Send(byte[] wire) => _ = _transport.SendAsync(wire);

        void SendTls(byte[] data)
        {
            int offset = 0;
            while (offset < data.Length)
            {
                int len = System.Math.Min(1200, data.Length - offset);
                byte[] chunk = new byte[len];
                Array.Copy(data, offset, chunk, 0, len);
                byte[] wire;
                lock (_sync) wire = Encode(OpenVpnOpcode.ControlV1, _sendNext++, Array.Empty<uint>(), chunk);
                Send(wire);
                offset += len;
            }
        }

        byte[] Encode(OpenVpnOpcode opcode, uint id, uint[] acks, byte[] payload) => OpenVpnPacketCodec.EncodeControl(new OpenVpnControlPacket
        {
            Opcode = opcode,
            SessionId = SessionId,
            AckPacketIds = acks,
            RemoteSessionId = acks.Length > 0 ? _clientSessionId : 0,
            PacketId = id,
            Payload = payload,
        });

        byte[] EncodeAck(uint[] acks) => OpenVpnPacketCodec.EncodeControl(new OpenVpnControlPacket
        {
            Opcode = OpenVpnOpcode.AckV1,
            SessionId = SessionId,
            AckPacketIds = acks,
            RemoteSessionId = _clientSessionId,
        });

        public void Dispose()
        {
            _transport.DatagramReceived -= OnDatagram;
            try { _protocol.Close(); } catch { }
            _bridge.CompleteInbound();
        }

        /// <summary>The TLS 1.2 server: a self-signed RSA cert + the captured context for the RFC 5705 exporter.</summary>
        sealed class ExporterTlsServer : DefaultTlsServer
        {
            readonly AsymmetricKeyParameter _privateKey;
            readonly Certificate _certificate;

            public ExporterTlsServer(BcTlsCrypto crypto) : base(crypto)
            {
                (BcX509Certificate cert, AsymmetricKeyParameter priv) = SelfSignedCert();
                _privateKey = priv;
                _certificate = new Certificate(new TlsCertificate[] { new BcTlsCertificate(crypto, cert.GetEncoded()) });
            }

            byte[]? _cachedExport;

            public bool HandshakeComplete { get; private set; }

            protected override ProtocolVersion[] GetSupportedVersions() => ProtocolVersion.TLSv12.Only();

            // Capture the exporter while the master secret is alive (BC wipes it right after the handshake), like the client.
            public override void NotifyHandshakeComplete()
            {
                base.NotifyHandshakeComplete();
                _cachedExport = m_context.ExportKeyingMaterial(OpenVpnKeyMaterial.TlsEkmLabel, null, OpenVpnStaticKey.KeyLength);
                HandshakeComplete = true;
            }

            public byte[] Export(string label, int length)
            {
                if (_cachedExport != null && label == OpenVpnKeyMaterial.TlsEkmLabel && length == _cachedExport.Length)
                    return _cachedExport;
                throw new InvalidOperationException("server export not captured for the requested label/length.");
            }

            protected override TlsCredentialedSigner GetRsaSignerCredentials()
            {
                var cryptoParams = new TlsCryptoParameters(m_context);
                var sigAlg = new SignatureAndHashAlgorithm(HashAlgorithm.sha256, SignatureAlgorithm.rsa);
                return new BcDefaultTlsCredentialedSigner(cryptoParams, (BcTlsCrypto)Crypto, _privateKey, _certificate, sigAlg);
            }

            static (BcX509Certificate, AsymmetricKeyParameter) SelfSignedCert()
            {
                var rng = new SecureRandom();
                var kpg = new RsaKeyPairGenerator();
                kpg.Init(new KeyGenerationParameters(rng, 2048));
                AsymmetricCipherKeyPair kp = kpg.GenerateKeyPair();

                var gen = new X509V3CertificateGenerator();
                var name = new X509Name("CN=test-openvpn-bc-server");
                gen.SetSerialNumber(BigInteger.ValueOf(DateTime.UtcNow.Ticks & 0x7FFFFFFF));
                gen.SetIssuerDN(name);
                gen.SetSubjectDN(name);
                gen.SetNotBefore(DateTime.UtcNow.AddDays(-1));
                gen.SetNotAfter(DateTime.UtcNow.AddDays(1));
                gen.SetPublicKey(kp.Public);
                ISignatureFactory sigFactory = new Asn1SignatureFactory("SHA256WithRSA", kp.Private, rng);
                BcX509Certificate cert = gen.Generate(sigFactory);
                return (cert, kp.Private);
            }
        }
    }
}
