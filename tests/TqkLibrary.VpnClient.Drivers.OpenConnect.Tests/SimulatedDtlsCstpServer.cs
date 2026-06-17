using System;
using System.Collections.Concurrent;
using System.Threading;
using System.Threading.Tasks;
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
using TqkLibrary.VpnClient.Abstractions.Transport.Interfaces;
using TqkLibrary.VpnClient.OpenConnect;
using TqkLibrary.VpnClient.OpenConnect.Enums;
using TqkLibrary.VpnClient.OpenConnect.Models;

namespace TqkLibrary.VpnClient.Drivers.OpenConnect.Tests
{
    /// <summary>
    /// A throwaway DTLS 1.2 server (BouncyCastle <see cref="DtlsServerProtocol"/> + a self-signed RSA cert) that speaks
    /// the OpenConnect <b>CSTP-over-DTLS</b> data plane: after the handshake it decodes the 1-byte
    /// <see cref="CstpDatagramFraming"/> frames, echoes DATA back, answers a DPD-REQUEST with a DPD-RESPONSE, and can
    /// push unsolicited DATA / DPD-REQUEST / DISCONNECT on demand. The library ships only a client, so this server role
    /// exists solely to exercise the DTLS data path offline. Mirrors the Transport.Dtls test server, layering CSTP
    /// framing on top.
    /// </summary>
    sealed class SimulatedDtlsCstpServer : IDisposable
    {
        readonly IDatagramTransport _transport;
        readonly BcTlsCrypto _crypto;
        readonly Certificate _certificate;
        readonly AsymmetricKeyParameter _privateKey;
        readonly Thread _thread;
        DtlsTransport? _dtls;
        readonly object _sendLock = new();

        /// <summary>Count of inbound DATA packets the server received over DTLS.</summary>
        public int DataPacketsReceived { get; private set; }

        /// <summary>Count of DPD-RESPONSE packets the server received (answers to its probes).</summary>
        public int DpdResponsesReceived { get; private set; }

        /// <summary>Count of DPD-REQUEST packets the server received from the client (its idle probe).</summary>
        public int DpdRequestsReceived { get; private set; }

        /// <summary>The exception that ended the server loop, if any (handshake failure, etc.).</summary>
        public Exception? Failure { get; private set; }

        /// <summary>Set once the DTLS handshake has completed (the test waits before sending stimulus over DTLS).</summary>
        public TaskCompletionSource<bool> Handshaked { get; } = new(TaskCreationOptions.RunContinuationsAsynchronously);

        public SimulatedDtlsCstpServer(LoopbackDatagramLink.End transport)
        {
            _transport = transport;
            var rng = new SecureRandom();
            _crypto = new BcTlsCrypto(rng);

            var gen = new RsaKeyPairGenerator();
            gen.Init(new KeyGenerationParameters(rng, 2048));
            AsymmetricCipherKeyPair keyPair = gen.GenerateKeyPair();
            _privateKey = keyPair.Private;

            var name = new X509Name("CN=ocserv-dtls-loopback-test");
            var certGen = new Org.BouncyCastle.X509.X509V3CertificateGenerator();
            certGen.SetSerialNumber(BigInteger.ValueOf(1));
            certGen.SetIssuerDN(name);
            certGen.SetSubjectDN(name);
            certGen.SetNotBefore(DateTime.UtcNow.AddDays(-1));
            certGen.SetNotAfter(DateTime.UtcNow.AddDays(1));
            certGen.SetPublicKey(keyPair.Public);
            var sigFactory = new Asn1SignatureFactory("SHA256WITHRSA", _privateKey, rng);
            Org.BouncyCastle.X509.X509Certificate x509 = certGen.Generate(sigFactory);

            var tlsCert = new BcTlsCertificate(_crypto, x509.CertificateStructure);
            _certificate = new Certificate(new TlsCertificate[] { tlsCert });

            _thread = new Thread(RunLoop) { IsBackground = true, Name = "ocserv-dtls-test-server" };
        }

        /// <summary>Starts the DTLS handshake + CSTP echo loop on its background thread.</summary>
        public void Start() => _thread.Start();

        void RunLoop()
        {
            try
            {
                var protocol = new DtlsServerProtocol();
                var server = new CstpTlsServer(_crypto, _certificate, _privateKey);
                using var bridge = new ServerDatagramBridge(_transport);
                DtlsTransport dtls = protocol.Accept(server, bridge);
                _dtls = dtls;
                Handshaked.TrySetResult(true);

                byte[] buffer = new byte[2048];
                while (true)
                {
                    int read = dtls.Receive(buffer, 0, buffer.Length, 30000);
                    if (read < 0) break;      // 30s idle ⇒ stop
                    if (read == 0) continue;
                    CstpPacket packet;
                    try { packet = CstpDatagramFraming.Decode(buffer.AsSpan(0, read)); }
                    catch (FormatException) { continue; }
                    switch (packet.Type)
                    {
                        case CstpPacketType.Data:
                            DataPacketsReceived++;
                            SendFrame(CstpPacketType.Data, packet.Payload); // echo
                            break;
                        case CstpPacketType.DpdRequest:
                            DpdRequestsReceived++;
                            SendFrame(CstpPacketType.DpdResponse, Array.Empty<byte>());
                            break;
                        case CstpPacketType.DpdResponse:
                            DpdResponsesReceived++;
                            break;
                        case CstpPacketType.KeepAlive:
                            break;
                    }
                }
                dtls.Close();
            }
            catch (Exception e) { Failure = e; Handshaked.TrySetResult(false); }
        }

        /// <summary>Test stimulus: push an unsolicited DATA packet to the client over DTLS.</summary>
        public void SendData(byte[] inner) => SendFrame(CstpPacketType.Data, inner);

        /// <summary>Test stimulus: push a DPD-REQUEST to the client over DTLS (expects a DPD-RESPONSE back).</summary>
        public void SendDpdRequest() => SendFrame(CstpPacketType.DpdRequest, Array.Empty<byte>());

        void SendFrame(CstpPacketType type, byte[] payload)
        {
            DtlsTransport? dtls = _dtls;
            if (dtls is null) return;
            byte[] framed = CstpDatagramFraming.Encode(type, payload);
            lock (_sendLock) { dtls.Send(framed, 0, framed.Length); }
        }

        public void Dispose() { try { _dtls?.Close(); } catch { } }

        /// <summary>Test-side sync↔async bridge: a pump pulls datagrams off the async transport for BouncyCastle's blocking Receive; sends run synchronously.</summary>
        sealed class ServerDatagramBridge : DatagramTransport, IDisposable
        {
            const int MtuLimit = 1500;
            readonly IDatagramTransport _inner;
            readonly BlockingCollection<byte[]> _inbound = new(new ConcurrentQueue<byte[]>());
            readonly CancellationTokenSource _cts = new();
            readonly Task _pump;

            public ServerDatagramBridge(IDatagramTransport inner)
            {
                _inner = inner;
                _pump = Task.Run(() => PumpAsync(_cts.Token));
            }

            async Task PumpAsync(CancellationToken cancellationToken)
            {
                byte[] buffer = new byte[MtuLimit];
                try
                {
                    while (!cancellationToken.IsCancellationRequested)
                    {
                        int read = await _inner.ReceiveAsync(buffer, cancellationToken).ConfigureAwait(false);
                        if (read <= 0) continue;
                        _inbound.Add(buffer.AsSpan(0, read).ToArray(), cancellationToken);
                    }
                }
                catch (OperationCanceledException) { }
                catch (Exception) { }
                finally { _inbound.CompleteAdding(); }
            }

            public int GetReceiveLimit() => MtuLimit;
            public int GetSendLimit() => MtuLimit;

            public int Receive(byte[] buf, int off, int len, int waitMillis)
            {
                if (!_inbound.TryTake(out byte[]? d, waitMillis)) return -1;
                int n = Math.Min(len, d.Length);
                Buffer.BlockCopy(d, 0, buf, off, n);
                return n;
            }

            public int Receive(Span<byte> buffer, int waitMillis)
            {
                if (!_inbound.TryTake(out byte[]? d, waitMillis)) return -1;
                int n = Math.Min(buffer.Length, d.Length);
                d.AsSpan(0, n).CopyTo(buffer);
                return n;
            }

            public void Send(byte[] buf, int off, int len)
                => _inner.SendAsync(new ReadOnlyMemory<byte>(buf, off, len)).AsTask().GetAwaiter().GetResult();

            public void Send(ReadOnlySpan<byte> buffer) => Send(buffer.ToArray(), 0, buffer.Length);

            public void Close() => Dispose();

            public void Dispose()
            {
                try { _cts.Cancel(); } catch { }
                try { _pump.Wait(2000); } catch { }
                _cts.Dispose();
                _inbound.Dispose();
            }
        }

        /// <summary>The server-side DTLS 1.2 TlsServer: AEAD suites, RSA signer credentials from the self-signed cert.</summary>
        sealed class CstpTlsServer : DefaultTlsServer
        {
            readonly BcTlsCrypto _crypto;
            readonly Certificate _certificate;
            readonly AsymmetricKeyParameter _privateKey;

            public CstpTlsServer(BcTlsCrypto crypto, Certificate certificate, AsymmetricKeyParameter privateKey)
                : base(crypto)
            {
                _crypto = crypto;
                _certificate = certificate;
                _privateKey = privateKey;
            }

            protected override ProtocolVersion[] GetSupportedVersions() => ProtocolVersion.DTLSv12.Only();

            protected override int[] GetSupportedCipherSuites() => new[]
            {
                CipherSuite.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
                CipherSuite.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
                CipherSuite.TLS_DHE_RSA_WITH_AES_128_GCM_SHA256,
                CipherSuite.TLS_RSA_WITH_AES_128_GCM_SHA256,
            };

            protected override TlsCredentialedSigner GetRsaSignerCredentials()
            {
                var sah = new SignatureAndHashAlgorithm(HashAlgorithm.sha256, SignatureAlgorithm.rsa);
                return new BcDefaultTlsCredentialedSigner(new TlsCryptoParameters(m_context), _crypto, _privateKey, _certificate, sah);
            }

            protected override TlsCredentialedDecryptor GetRsaEncryptionCredentials()
                => new BcDefaultTlsCredentialedDecryptor(_crypto, _certificate, _privateKey);
        }
    }
}
