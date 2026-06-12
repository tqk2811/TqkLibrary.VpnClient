using System.Net;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Authentication;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using TqkLibrary.Vpn.Drivers.Sstp.Transport;
using Xunit;

namespace TqkLibrary.Vpn.Sstp.Tests
{
    /// <summary>
    /// Offline coverage for the configurable TLS certificate-validation callback on <see cref="TlsByteStream"/> (P0.6).
    /// Each test runs a real TLS handshake against a loopback <see cref="TcpListener"/> (no external network — so this
    /// is NOT marked Integration), proving the callback reaches <see cref="SslStream"/> and gates the handshake while
    /// the server certificate is still captured for the SSTP crypto binding.
    /// </summary>
    public class TlsByteStreamCertCallbackTests
    {
        [Fact]
        public async Task Connect_NoCallback_AcceptsSelfSignedCert_AndCapturesIt()
        {
            using var serverCert = CreateServerCert();
            var listener = new TcpListener(IPAddress.Loopback, 0);
            listener.Start();
            try
            {
                int port = ((IPEndPoint)listener.LocalEndpoint).Port;
                Task server = RunTlsServerAsync(listener, serverCert);

                using var client = new TlsByteStream("127.0.0.1", port); // no callback ⇒ accept any cert
                using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(10));
                await client.ConnectAsync(cts.Token);

                Assert.NotNull(client.RemoteCertificate);
                Assert.Equal(serverCert.Thumbprint, client.RemoteCertificate!.Thumbprint);
                await server;
            }
            finally { listener.Stop(); }
        }

        [Fact]
        public async Task Connect_Callback_ReceivesServerCert_AndAccepts()
        {
            using var serverCert = CreateServerCert();
            var listener = new TcpListener(IPAddress.Loopback, 0);
            listener.Start();
            try
            {
                int port = ((IPEndPoint)listener.LocalEndpoint).Port;
                Task server = RunTlsServerAsync(listener, serverCert);

                string? seenThumbprint = null;
                SslPolicyErrors seenErrors = SslPolicyErrors.None;
                RemoteCertificateValidationCallback callback = (sender, certificate, chain, errors) =>
                {
                    using var seen = new X509Certificate2(certificate!);
                    seenThumbprint = seen.Thumbprint;
                    seenErrors = errors;
                    return true; // accept despite the self-signed chain error
                };

                using var client = new TlsByteStream("127.0.0.1", port, callback);
                using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(10));
                await client.ConnectAsync(cts.Token);

                Assert.Equal(serverCert.Thumbprint, seenThumbprint);
                Assert.NotEqual(SslPolicyErrors.None, seenErrors); // self-signed ⇒ chain/name error surfaced to the callback
                Assert.NotNull(client.RemoteCertificate);          // captured for the crypto binding regardless
                await server;
            }
            finally { listener.Stop(); }
        }

        [Fact]
        public async Task Connect_CallbackRejects_ThrowsAuthenticationException()
        {
            using var serverCert = CreateServerCert();
            var listener = new TcpListener(IPAddress.Loopback, 0);
            listener.Start();
            try
            {
                int port = ((IPEndPoint)listener.LocalEndpoint).Port;
                Task server = RunTlsServerAsync(listener, serverCert);

                using var client = new TlsByteStream("127.0.0.1", port, (sender, certificate, chain, errors) => false);
                using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(10));

                await Assert.ThrowsAsync<AuthenticationException>(() => client.ConnectAsync(cts.Token).AsTask());
                await server; // the server-side handshake fails too; RunTlsServerAsync swallows it
            }
            finally { listener.Stop(); }
        }

        // Accepts one TLS client over loopback and completes the server handshake; swallows the failure a rejecting
        // client triggers. The handshake completing is all the client side needs, so it returns without reading data.
        static async Task RunTlsServerAsync(TcpListener listener, X509Certificate2 cert)
        {
            try
            {
                using TcpClient server = await listener.AcceptTcpClientAsync();
                using var ssl = new SslStream(server.GetStream(), leaveInnerStreamOpen: false);
                await ssl.AuthenticateAsServerAsync(cert);
            }
            catch { /* client rejected the cert or closed early — expected in the reject test */ }
        }

        // A self-signed server cert, round-tripped through PFX so Windows SChannel can use its private key in
        // AuthenticateAsServerAsync (an ephemeral key from CreateSelfSigned alone is rejected there).
        static X509Certificate2 CreateServerCert()
        {
            using var rsa = RSA.Create(2048);
            var request = new CertificateRequest("CN=tls-callback-test", rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
            using var ephemeral = request.CreateSelfSigned(DateTimeOffset.UnixEpoch, DateTimeOffset.UnixEpoch.AddYears(10));
            return new X509Certificate2(ephemeral.Export(X509ContentType.Pfx));
        }
    }
}
