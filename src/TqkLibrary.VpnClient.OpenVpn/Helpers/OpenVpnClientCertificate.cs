using System.Security.Cryptography.X509Certificates;
using TqkLibrary.VpnClient.OpenVpn.Config;
#if !NET5_0_OR_GREATER
using System.IO;
using System.Linq;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.OpenSsl;
using Org.BouncyCastle.Pkcs;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.X509;
using BcX509Certificate = Org.BouncyCastle.X509.X509Certificate;
#endif

namespace TqkLibrary.VpnClient.OpenVpn.Helpers
{
    /// <summary>
    /// Loads the OpenVPN client certificate + private key from a profile (the <c>cert</c>/<c>key</c> directives, either
    /// inline PEM or a file path) into an <see cref="X509Certificate2"/> the TLS control channel can present for
    /// client-certificate authentication. The driver still accepts a pre-built <see cref="X509CertificateCollection"/>
    /// (back-compat); this helper exists so a parsed <c>.ovpn</c> with cert/key needs no manual wiring.
    /// <para>net5+ uses the BCL PEM importer (<see cref="X509Certificate2.CreateFromPem(string,string)"/>) then
    /// round-trips through a PKCS#12 export so the private key survives into an ephemeral key set usable by
    /// <c>SslStream</c>. netstandard2.0 has no PEM importer in its BCL, so the cert + key are parsed with BouncyCastle
    /// and assembled into a PKCS#12 that <see cref="X509Certificate2"/> can load.</para>
    /// </summary>
    public static class OpenVpnClientCertificate
    {
        /// <summary>
        /// Builds the client-certificate collection the TLS handshake should present: returns <paramref name="explicit"/>
        /// verbatim when the caller supplied one (it always wins, for back-compat), otherwise auto-loads the profile's
        /// <c>cert</c>+<c>key</c> when both are present (file-path forms are read from disk here). Returns null when there
        /// is nothing to present (no explicit collection and the profile carries no cert/key).
        /// </summary>
        public static X509CertificateCollection? Resolve(OpenVpnProfile profile, X509CertificateCollection? @explicit)
        {
            if (@explicit != null) return @explicit;
            X509Certificate2? loaded = TryLoad(profile);
            return loaded != null ? new X509CertificateCollection { loaded } : null;
        }

        /// <summary>
        /// Loads the profile's <c>cert</c>+<c>key</c> into a single <see cref="X509Certificate2"/> carrying its private
        /// key, or null when the profile has no cert/key pair. Throws if only one of the pair is present, or if the
        /// material cannot be parsed. File-path forms are read from disk; inline forms are taken verbatim.
        /// </summary>
        public static X509Certificate2? TryLoad(OpenVpnProfile profile)
        {
            if (profile is null) throw new ArgumentNullException(nameof(profile));
            if (profile.Cert is null && profile.Key is null) return null;
            if (profile.Cert is null || profile.Key is null)
                throw new ArgumentException("OpenVPN client-certificate auth needs both a 'cert' and a 'key'; the profile carries only one.");

            string certPem = ReadMaterial(profile.Cert);
            string keyPem = ReadMaterial(profile.Key);
            return LoadFromPem(certPem, keyPem);
        }

        /// <summary>Builds an <see cref="X509Certificate2"/> with its private key from the cert + key PEM text.</summary>
        public static X509Certificate2 LoadFromPem(string certPem, string keyPem)
        {
            if (certPem is null) throw new ArgumentNullException(nameof(certPem));
            if (keyPem is null) throw new ArgumentNullException(nameof(keyPem));
#if NET5_0_OR_GREATER
            // The BCL parses the PEM cert + key (PKCS#8/PKCS#1/EC) directly; round-trip through PKCS#12 so SslStream
            // gets a cert whose private key lives in a key set it can use (CreateFromPem yields an ephemeral key only).
            using X509Certificate2 fromPem = X509Certificate2.CreateFromPem(certPem, keyPem);
            return new X509Certificate2(fromPem.Export(X509ContentType.Pkcs12));
#else
            return LoadWithBouncyCastle(certPem, keyPem);
#endif
        }

        // Reads inline PEM verbatim, or the referenced file from disk (this is where the deferred .ovpn file I/O happens).
        static string ReadMaterial(OpenVpnFileOrInline material)
        {
            if (material.Inline is string inline) return inline;
            if (material.FilePath is string path)
            {
#if NET5_0_OR_GREATER
                return System.IO.File.ReadAllText(path);
#else
                return File.ReadAllText(path);
#endif
            }
            throw new ArgumentException("The certificate/key reference carries neither inline material nor a file path.");
        }

#if !NET5_0_OR_GREATER
        // netstandard2.0: no BCL PEM importer — parse the cert + key with BouncyCastle and assemble a PKCS#12.
        static X509Certificate2 LoadWithBouncyCastle(string certPem, string keyPem)
        {
            BcX509Certificate bcCert = ReadCertificate(certPem);
            AsymmetricKeyParameter privateKey = ReadPrivateKey(keyPem);

            var store = new Pkcs12StoreBuilder().Build();
            var entry = new X509CertificateEntry(bcCert);
            const string alias = "openvpn-client";
            store.SetCertificateEntry(alias, entry);
            store.SetKeyEntry(alias, new AsymmetricKeyEntry(privateKey), new[] { entry });

            char[] pfxPassword = new char[0];
            using var ms = new MemoryStream();
            store.Save(ms, pfxPassword, new SecureRandom());
            return new X509Certificate2(ms.ToArray(), new string(pfxPassword), X509KeyStorageFlags.Exportable);
        }

        static BcX509Certificate ReadCertificate(string certPem)
        {
            using var reader = new StringReader(certPem);
            object? obj;
            var pemReader = new PemReader(reader);
            while ((obj = pemReader.ReadObject()) != null)
            {
                if (obj is BcX509Certificate cert) return cert;
            }
            throw new ArgumentException("No certificate found in the OpenVPN 'cert' PEM material.");
        }

        static AsymmetricKeyParameter ReadPrivateKey(string keyPem)
        {
            using var reader = new StringReader(keyPem);
            object? obj;
            var pemReader = new PemReader(reader);
            while ((obj = pemReader.ReadObject()) != null)
            {
                switch (obj)
                {
                    case AsymmetricCipherKeyPair pair: return pair.Private;
                    case AsymmetricKeyParameter key when key.IsPrivate: return key;
                }
            }
            throw new ArgumentException("No private key found in the OpenVPN 'key' PEM material.");
        }
#endif
    }
}
