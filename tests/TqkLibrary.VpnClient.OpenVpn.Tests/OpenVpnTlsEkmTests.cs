using TqkLibrary.VpnClient.OpenVpn;
using TqkLibrary.VpnClient.OpenVpn.DataChannel;
using TqkLibrary.VpnClient.OpenVpn.Enums;
using Xunit;

namespace TqkLibrary.VpnClient.OpenVpn.Tests
{
    /// <summary>
    /// Tests OpenVPN <c>key-derivation tls-ekm</c> (RFC 5705, roadmap F.5). The real <see cref="OpenVpnControlChannel"/>
    /// runs in tls-ekm mode (BouncyCastle TLS over the in-memory reliability bridge) against a BouncyCastle TLS server
    /// harness that can compute the same exporter. The property that matters — the same one live interop depends on — is
    /// that the two roles derive <b>complementary</b> data-channel keys from the exporter (the client's send key = the
    /// server's receive key, and vice-versa) over the label <c>"EXPORTER-OpenVPN-datakeys"</c>, replacing the
    /// key-method-2 PRF. A self-pair offline test cannot catch a wrong-but-symmetric label/length on its own, so the live
    /// validation against a real OpenVPN server is the authority; this guards the wiring + slicing direction.
    /// </summary>
    public class OpenVpnTlsEkmTests
    {
        [Fact]
        public async Task TlsEkm_ClientAndServer_DeriveComplementaryDataKeys()
        {
            var link = new OpenVpnLoopbackLink();
            using var server = new SimulatedBouncyCastleOpenVpnServer(link.Server);

            var client = new OpenVpnControlChannel(link.Client,
                options: new OpenVpnReliabilityOptions { Interval = TimeSpan.FromSeconds(30) },
                keyDerivation: OpenVpnKeyDerivationMode.TlsEkm);

            using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(20));
            await client.ConnectAsync("test-openvpn-bc-server", serverCertificateValidation: (_, _, _, _) => true,
                cancellationToken: cts.Token);

            // The control channel exposes the RFC 5705 exporter only in tls-ekm mode.
            Assert.NotNull(client.KeyingMaterialExporter);
            Assert.Equal(OpenVpnKeyDerivationMode.TlsEkm, client.KeyDerivation);

            // Wait until the server-side BC handshake completes so its exporter is valid.
            for (int i = 0; i < 200 && !server.HandshakeComplete; i++)
                await Task.Delay(25, cts.Token);
            Assert.True(server.HandshakeComplete, "server BC TLS handshake did not complete");

            // Client derives the data keys straight from the exporter (no key-method-2 message exchanged here).
            OpenVpnKeyMaterial clientMaterial = OpenVpnKeyMaterial.FromTlsExporter(client.KeyingMaterialExporter!);
            OpenVpnDataChannelKeys clientKeys = clientMaterial.DeriveDataKeys(OpenVpnDataCipher.Aes256Gcm, isServer: false);

            // Server derives from its own session's exporter (same label/length) and slices for the server role.
            byte[] serverKey2 = server.ExportKeyingMaterial(OpenVpnKeyMaterial.TlsEkmLabel, OpenVpnStaticKey.KeyLength);
            OpenVpnDataChannelKeys serverKeys = new OpenVpnKeyMaterial(serverKey2).DeriveDataKeys(OpenVpnDataCipher.Aes256Gcm, isServer: true);

            // Complementary: the client's send side is the server's receive side, and vice-versa.
            Assert.Equal(clientKeys.SendCipherKey, serverKeys.ReceiveCipherKey);
            Assert.Equal(clientKeys.ReceiveCipherKey, serverKeys.SendCipherKey);
            Assert.Equal(clientKeys.SendImplicitIv, serverKeys.ReceiveImplicitIv);
            Assert.Equal(clientKeys.ReceiveImplicitIv, serverKeys.SendImplicitIv);

            // Each direction is a distinct slice (not accidentally identical), and the key sizes are right.
            Assert.NotEqual(clientKeys.SendCipherKey, clientKeys.ReceiveCipherKey);
            Assert.Equal(OpenVpnDataChannelKeys.CipherKeySize, clientKeys.SendCipherKey.Length);

            client.Dispose();
        }

        [Fact]
        public void FromTlsExporter_RequestsExpectedLabelAndLength()
        {
            var exporter = new RecordingExporter();
            OpenVpnKeyMaterial.FromTlsExporter(exporter);
            Assert.Equal("EXPORTER-OpenVPN-datakeys", exporter.Label);
            Assert.Equal(0, exporter.ContextLength);          // OpenVPN tls-ekm uses an empty context
            Assert.Equal(OpenVpnStaticKey.KeyLength, exporter.Length); // 256 bytes = key_c2s|auth_c2s|key_s2c|auth_s2c
        }

        sealed class RecordingExporter : ITlsKeyingMaterialExporter
        {
            public string? Label { get; private set; }
            public int ContextLength { get; private set; }
            public int Length { get; private set; }

            public byte[] Export(string label, ReadOnlySpan<byte> context, int length)
            {
                Label = label;
                ContextLength = context.Length;
                Length = length;
                return new byte[length];
            }
        }
    }
}
