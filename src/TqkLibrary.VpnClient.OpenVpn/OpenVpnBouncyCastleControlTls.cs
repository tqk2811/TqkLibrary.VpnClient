using System.IO;
using System.Net.Security;
using System.Security.Cryptography.X509Certificates;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.OpenSsl;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Tls;
using Org.BouncyCastle.Tls.Crypto;
using Org.BouncyCastle.Tls.Crypto.Impl.BC;
using BcX509Certificate = Org.BouncyCastle.X509.X509Certificate;
using BcCertificateRequest = Org.BouncyCastle.Tls.CertificateRequest;

namespace TqkLibrary.VpnClient.OpenVpn
{
    /// <summary>
    /// Runs the OpenVPN control-channel TLS over <b>BouncyCastle</b> (<see cref="TlsClientProtocol"/>) on the in-memory
    /// <see cref="OpenVpnTlsBridgeStream"/>, instead of the BCL <see cref="SslStream"/>. It exists for one reason the
    /// SslStream path cannot serve: it exposes an <b>RFC 5705 keying-material exporter</b> over the finished session, the
    /// primitive OpenVPN's <c>--key-derivation tls-ekm</c> needs (label <c>"EXPORTER-OpenVPN-datakeys"</c>). This is the
    /// opt-in engine <see cref="OpenVpnControlChannel"/> selects only when tls-ekm is requested; the default control
    /// channel keeps using <see cref="SslStream"/> so the live, validated key-method-2 path is unaffected.
    /// <para>
    /// It supports OpenVPN client-certificate auth (the <c>cert</c>/<c>key</c> PEM the profile carries) and pins TLS 1.2
    /// (the version OpenVPN community servers and the exporter interop are simplest at). The exporter prefers BouncyCastle's
    /// standards-correct <see cref="TlsContext.ExportKeyingMaterial"/> (which honours extended-master-secret when the
    /// session negotiated it — OpenSSL servers do); it falls back to the legacy TLS 1.2 PRF computed by hand only if BC
    /// refuses a non-EMS session, mirroring OpenSSL's <c>SSL_export_keying_material</c> on a non-EMS handshake.
    /// </para>
    /// </summary>
    public sealed class OpenVpnBouncyCastleControlTls : ITlsKeyingMaterialExporter, IDisposable
    {
        readonly OpenVpnTlsBridgeStream _bridge;
        readonly string _targetHost;
        readonly string? _clientCertPem;
        readonly string? _clientKeyPem;
        readonly RemoteCertificateValidationCallback? _serverCertificateValidation;

        TlsClientProtocol? _protocol;
        ExporterTlsClient? _client;

        /// <summary>
        /// Creates the engine over the control channel's <paramref name="bridge"/>. <paramref name="targetHost"/> is the
        /// TLS SNI/target. <paramref name="clientCertPem"/>/<paramref name="clientKeyPem"/> carry the OpenVPN client
        /// certificate + private key (PEM) for cert auth — both null when the server requires no client cert.
        /// <paramref name="serverCertificateValidation"/> validates the server certificate (null = accept any; the driver
        /// supplies real validation).
        /// </summary>
        internal OpenVpnBouncyCastleControlTls(OpenVpnTlsBridgeStream bridge, string targetHost,
            string? clientCertPem = null, string? clientKeyPem = null,
            RemoteCertificateValidationCallback? serverCertificateValidation = null)
        {
            _bridge = bridge ?? throw new ArgumentNullException(nameof(bridge));
            _targetHost = targetHost ?? throw new ArgumentNullException(nameof(targetHost));
            _clientCertPem = clientCertPem;
            _clientKeyPem = clientKeyPem;
            _serverCertificateValidation = serverCertificateValidation;
        }

        /// <summary>The decrypted application-data pipe (valid after <see cref="ConnectAsync"/>): key-method-2 runs on it.</summary>
        public Stream PlaintextStream => _protocol?.Stream ?? throw new InvalidOperationException("The control channel TLS is not established yet.");

        /// <summary>The server certificate captured during the handshake (null until/unless one was presented).</summary>
        public X509Certificate2? RemoteCertificate { get; private set; }

        /// <summary>
        /// Runs the BouncyCastle TLS 1.2 client handshake on the bridge. The BC record layer is blocking (it reads/writes
        /// the bridge inline), so the handshake runs on a thread-pool thread; cancellation completes the bridge so the
        /// blocking read returns.
        /// </summary>
        public async Task ConnectAsync(CancellationToken cancellationToken = default)
        {
            var crypto = new BcTlsCrypto(new SecureRandom());
            var client = new ExporterTlsClient(crypto, _targetHost, _clientCertPem, _clientKeyPem,
                _serverCertificateValidation, cert => RemoteCertificate = cert);
            var protocol = new TlsClientProtocol(_bridge);

            try
            {
                using (cancellationToken.Register(() => _bridge.CompleteInbound()))
                    await Task.Run(() => protocol.Connect(client), cancellationToken).ConfigureAwait(false);
            }
            catch
            {
                try { protocol.Close(); } catch { }
                throw;
            }

            _client = client;
            _protocol = protocol;
        }

        /// <inheritdoc/>
        /// <remarks>Valid only after <see cref="ConnectAsync"/> completes; the OpenVPN tls-ekm call uses an empty context.</remarks>
        public byte[] Export(string label, ReadOnlySpan<byte> context, int length)
        {
            ExporterTlsClient client = _client ?? throw new InvalidOperationException("The control channel TLS is not established yet.");
            return client.Export(label, context, length);
        }

        /// <inheritdoc/>
        public void Dispose()
        {
            try { _protocol?.Close(); } catch { } // best-effort close_notify
            RemoteCertificate?.Dispose();
        }

        /// <summary>
        /// The TLS 1.2 client: pins the version, presents the optional OpenVPN client certificate, captures the server
        /// certificate, and runs the RFC 5705 exporter over the finished session for tls-ekm.
        /// </summary>
        sealed class ExporterTlsClient : DefaultTlsClient
        {
            // The OpenVPN data-channel export is computed eagerly at handshake-complete and cached, because BouncyCastle
            // clears the TLS master secret as soon as the handshake finishes (so a lazy export afterwards would find no
            // secret). The label/length are fixed (EXPORTER-OpenVPN-datakeys, 256, empty context).
            byte[]? _cachedDataKeys;

            readonly string _host;
            readonly string? _certPem;
            readonly string? _keyPem;
            readonly RemoteCertificateValidationCallback? _validation;
            readonly Action<X509Certificate2?> _onCertificate;

            public ExporterTlsClient(TlsCrypto crypto, string host, string? certPem, string? keyPem,
                RemoteCertificateValidationCallback? validation, Action<X509Certificate2?> onCertificate)
                : base(crypto)
            {
                _host = host;
                _certPem = certPem;
                _keyPem = keyPem;
                _validation = validation;
                _onCertificate = onCertificate;
            }

            // TLS 1.2 only — OpenVPN community servers negotiate it and the exporter interop is simplest there.
            protected override ProtocolVersion[] GetSupportedVersions() => ProtocolVersion.TLSv12.Only();

            public override TlsAuthentication GetAuthentication()
                => new CallbackAuthentication(this, _host, _certPem, _keyPem, _validation, _onCertificate);

            // Compute the OpenVPN data-channel export while the master secret is still alive (BC wipes it right after).
            public override void NotifyHandshakeComplete()
            {
                base.NotifyHandshakeComplete();
                TlsClientContext ctx = m_context ?? throw new InvalidOperationException("TLS context not initialised.");
                _cachedDataKeys = ComputeExport(ctx,
                    DataChannel.OpenVpnKeyMaterial.TlsEkmLabel, ReadOnlySpan<byte>.Empty, OpenVpnStaticKey.KeyLength);
            }

            /// <summary>Returns the cached RFC 5705 export for the OpenVPN data-channel label/length captured at handshake-complete.</summary>
            public byte[] Export(string label, ReadOnlySpan<byte> context, int length)
            {
                if (_cachedDataKeys != null
                    && label == DataChannel.OpenVpnKeyMaterial.TlsEkmLabel && context.Length == 0 && length == _cachedDataKeys.Length)
                    return _cachedDataKeys;
                throw new InvalidOperationException(
                    $"No keying-material export was captured for label '{label}' (length {length}); only the OpenVPN tls-ekm export is supported, and only after the handshake completes.");
            }

            // RFC 5705 export from the finished session. Prefer BouncyCastle's standards-correct exporter (it derives from
            // the exporter_master_secret with extended-master-secret when negotiated — OpenSSL servers enable EMS); fall
            // back to the legacy by-hand TLS 1.2 PRF only if BC refuses (a non-EMS session), matching OpenSSL's
            // SSL_export_keying_material in that case. Run while the master secret is still alive.
            static byte[] ComputeExport(TlsClientContext ctx, string label, ReadOnlySpan<byte> context, int length)
            {
                byte[] ctxBytes = context.ToArray();
                try
                {
                    return ctx.ExportKeyingMaterial(label, ctxBytes.Length == 0 ? null : ctxBytes, length);
                }
                catch (Exception)
                {
                    // Legacy non-EMS path: PRF(master_secret, label, client_random + server_random [+ uint16 len + ctx]).
                    SecurityParameters sp = ctx.SecurityParameters;
                    TlsSecret masterSecret = sp.MasterSecret
                        ?? throw new InvalidOperationException("TLS master secret unavailable for the keying-material export.");
                    byte[] clientRandom = sp.ClientRandom;
                    byte[] serverRandom = sp.ServerRandom;
                    bool hasContext = ctxBytes.Length > 0;
                    int seedLen = clientRandom.Length + serverRandom.Length + (hasContext ? 2 + ctxBytes.Length : 0);
                    byte[] seed = new byte[seedLen];
                    int p = 0;
                    Buffer.BlockCopy(clientRandom, 0, seed, p, clientRandom.Length); p += clientRandom.Length;
                    Buffer.BlockCopy(serverRandom, 0, seed, p, serverRandom.Length); p += serverRandom.Length;
                    if (hasContext)
                    {
                        seed[p++] = (byte)(ctxBytes.Length >> 8);
                        seed[p++] = (byte)ctxBytes.Length;
                        Buffer.BlockCopy(ctxBytes, 0, seed, p, ctxBytes.Length);
                    }
                    return masterSecret.DeriveUsingPrf(sp.PrfAlgorithm, label, seed, length).Extract();
                }
            }

            sealed class CallbackAuthentication : TlsAuthentication
            {
                readonly ExporterTlsClient _owner;
                readonly string _host;
                readonly string? _certPem;
                readonly string? _keyPem;
                readonly RemoteCertificateValidationCallback? _validation;
                readonly Action<X509Certificate2?> _onCertificate;

                public CallbackAuthentication(ExporterTlsClient owner, string host, string? certPem, string? keyPem,
                    RemoteCertificateValidationCallback? validation, Action<X509Certificate2?> onCertificate)
                {
                    _owner = owner;
                    _host = host;
                    _certPem = certPem;
                    _keyPem = keyPem;
                    _validation = validation;
                    _onCertificate = onCertificate;
                }

                public void NotifyServerCertificate(TlsServerCertificate serverCertificate)
                {
                    X509Certificate2? leaf = null;
                    TlsCertificate[] chain = serverCertificate.Certificate.GetCertificateList();
                    if (chain.Length > 0)
                        leaf = new X509Certificate2(chain[0].GetEncoded());
                    _onCertificate(leaf);

                    // No callback ⇒ accept any (the driver applies real validation upstream). A callback may reject.
                    if (_validation is null) return;
                    bool ok = _validation(_host, leaf, chain: null, System.Net.Security.SslPolicyErrors.None);
                    if (!ok) throw new TlsFatalAlert(AlertDescription.bad_certificate);
                }

                public TlsCredentials? GetClientCredentials(BcCertificateRequest certificateRequest)
                {
                    if (_certPem is null || _keyPem is null) return null; // no client cert: anonymous (e.g. auth-user-pass only)
                    return BuildClientCredentials(_owner, _certPem, _keyPem, certificateRequest);
                }
            }

            // Assembles a signing credential from the OpenVPN client cert + key PEM, choosing a signature algorithm the
            // server asked for that matches the key. Uses BouncyCastle's PemReader (no BCL PEM importer on ns2.0).
            static TlsCredentials BuildClientCredentials(ExporterTlsClient owner, string certPem, string keyPem,
                BcCertificateRequest certificateRequest)
            {
                var crypto = (BcTlsCrypto)owner.Crypto;
                BcX509Certificate bcCert = ReadCertificate(certPem);
                AsymmetricKeyParameter privateKey = ReadPrivateKey(keyPem);

                var tlsCert = new BcTlsCertificate(crypto, bcCert.GetEncoded());
                var certificate = new Certificate(new TlsCertificate[] { tlsCert });

                SignatureAndHashAlgorithm sigAlg = ChooseSignatureAlgorithm(privateKey, certificateRequest);
                var cryptoParams = new Org.BouncyCastle.Tls.Crypto.TlsCryptoParameters(owner.m_context);
                return new BcDefaultTlsCredentialedSigner(cryptoParams, crypto, privateKey, certificate, sigAlg);
            }

            // Picks a server-offered signature+hash the private key can produce. Prefer the matching key family with
            // SHA-256; if the server sent no supported list, default to RSA/ECDSA-with-SHA256.
            static SignatureAndHashAlgorithm ChooseSignatureAlgorithm(AsymmetricKeyParameter key, BcCertificateRequest request)
            {
                short sigAlgorithm = key is Org.BouncyCastle.Crypto.Parameters.ECKeyParameters
                    ? SignatureAlgorithm.ecdsa
                    : SignatureAlgorithm.rsa;

                var supported = request?.SupportedSignatureAlgorithms;
                if (supported != null)
                {
                    foreach (object o in supported)
                    {
                        var sah = (SignatureAndHashAlgorithm)o;
                        if (sah.Signature == sigAlgorithm && sah.Hash == HashAlgorithm.sha256)
                            return sah;
                    }
                    foreach (object o in supported)
                    {
                        var sah = (SignatureAndHashAlgorithm)o;
                        if (sah.Signature == sigAlgorithm)
                            return sah;
                    }
                }
                return new SignatureAndHashAlgorithm(HashAlgorithm.sha256, sigAlgorithm);
            }

            static BcX509Certificate ReadCertificate(string certPem)
            {
                using var reader = new StringReader(certPem);
                var pemReader = new PemReader(reader);
                object? obj;
                while ((obj = pemReader.ReadObject()) != null)
                    if (obj is BcX509Certificate cert) return cert;
                throw new ArgumentException("No certificate found in the OpenVPN 'cert' PEM material.");
            }

            static AsymmetricKeyParameter ReadPrivateKey(string keyPem)
            {
                using var reader = new StringReader(keyPem);
                var pemReader = new PemReader(reader);
                object? obj;
                while ((obj = pemReader.ReadObject()) != null)
                {
                    switch (obj)
                    {
                        case AsymmetricCipherKeyPair pair: return pair.Private;
                        case AsymmetricKeyParameter k when k.IsPrivate: return k;
                    }
                }
                throw new ArgumentException("No private key found in the OpenVPN 'key' PEM material.");
            }
        }
    }
}
