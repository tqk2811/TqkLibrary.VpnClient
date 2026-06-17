using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using TqkLibrary.VpnClient.OpenVpn.Config;
using TqkLibrary.VpnClient.OpenVpn.Helpers;
using Xunit;

namespace TqkLibrary.VpnClient.OpenVpn.Tests
{
    /// <summary>
    /// Verifies the OpenVPN client-certificate auto-load (V.2 offline): a profile carrying <c>cert</c>+<c>key</c> as
    /// inline PEM loads into an <see cref="X509Certificate2"/> with its private key (ready for client-cert TLS), the
    /// pre-built collection still wins (back-compat), and the half-pair / empty cases behave.
    /// </summary>
    public class OpenVpnClientCertificateTests
    {
        // A self-signed cert + its PKCS#8 private key, both as PEM text (what an inline <cert>/<key> block holds).
        static (string CertPem, string KeyPem, string Thumbprint) MakeClientPem()
        {
            using var rsa = RSA.Create(2048);
            var request = new CertificateRequest("CN=test-openvpn-client", rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
            using X509Certificate2 cert = request.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddDays(1));
            string certPem = cert.ExportCertificatePem();
            string keyPem = rsa.ExportPkcs8PrivateKeyPem();
            return (certPem, keyPem, cert.Thumbprint);
        }

        [Fact]
        public void LoadFromPem_YieldsCertWithPrivateKey()
        {
            (string certPem, string keyPem, string thumbprint) = MakeClientPem();

            using X509Certificate2 loaded = OpenVpnClientCertificate.LoadFromPem(certPem, keyPem);

            Assert.True(loaded.HasPrivateKey);
            Assert.Equal(thumbprint, loaded.Thumbprint);
        }

        [Fact]
        public void TryLoad_InlinePemProfile_LoadsClientCert()
        {
            (string certPem, string keyPem, string thumbprint) = MakeClientPem();
            var profile = new OpenVpnProfile
            {
                Cert = new OpenVpnFileOrInline { Inline = certPem },
                Key = new OpenVpnFileOrInline { Inline = keyPem },
            };

            using X509Certificate2? loaded = OpenVpnClientCertificate.TryLoad(profile);

            Assert.NotNull(loaded);
            Assert.True(loaded!.HasPrivateKey);
            Assert.Equal(thumbprint, loaded.Thumbprint);
        }

        [Fact]
        public void TryLoad_NoCertNorKey_ReturnsNull()
        {
            Assert.Null(OpenVpnClientCertificate.TryLoad(new OpenVpnProfile()));
        }

        [Fact]
        public void TryLoad_OnlyCert_Throws()
        {
            (string certPem, _, _) = MakeClientPem();
            var profile = new OpenVpnProfile { Cert = new OpenVpnFileOrInline { Inline = certPem } };
            Assert.Throws<ArgumentException>(() => OpenVpnClientCertificate.TryLoad(profile));
        }

        [Fact]
        public void Resolve_ExplicitCollectionWins_BackCompat()
        {
            (string certPem, string keyPem, _) = MakeClientPem();
            var profile = new OpenVpnProfile
            {
                Cert = new OpenVpnFileOrInline { Inline = certPem },
                Key = new OpenVpnFileOrInline { Inline = keyPem },
            };
            var supplied = new X509CertificateCollection();

            // An explicit collection is returned verbatim even when the profile carries a cert/key.
            Assert.Same(supplied, OpenVpnClientCertificate.Resolve(profile, supplied));

            // No explicit collection ⇒ auto-load the profile's cert/key.
            X509CertificateCollection? auto = OpenVpnClientCertificate.Resolve(profile, null);
            Assert.NotNull(auto);
            Assert.Single(auto!);

            // Nothing supplied and nothing in the profile ⇒ null (nothing to present).
            Assert.Null(OpenVpnClientCertificate.Resolve(new OpenVpnProfile(), null));
        }
    }
}
