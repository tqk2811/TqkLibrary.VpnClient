using System.Collections.Generic;
using System.Text;
using TqkLibrary.VpnClient.OpenVpn.DataChannel;
using Xunit;

namespace TqkLibrary.VpnClient.OpenVpn.Tests
{
    /// <summary>
    /// Tests NCP cipher negotiation (V2.f): the advertised cipher catalog, the peer-info block, and that key2 sliced
    /// for a negotiated cipher (here AES-128-GCM) yields complementary keys a data channel can use.
    /// </summary>
    public class OpenVpnNcpTests
    {
        [Fact]
        public void DataCipher_ResolvesByName_AndAdvertisesList()
        {
            Assert.True(OpenVpnDataCipher.TryResolve("AES-128-GCM", out OpenVpnDataCipher c128));
            Assert.Equal(16, c128.KeySizeBytes);
            Assert.True(OpenVpnDataCipher.TryResolve("aes-256-gcm", out OpenVpnDataCipher c256)); // case-insensitive
            Assert.Equal(32, c256.KeySizeBytes);
            Assert.True(OpenVpnDataCipher.TryResolve("chacha20-poly1305", out OpenVpnDataCipher cChaCha)); // case-insensitive
            Assert.Equal(32, cChaCha.KeySizeBytes);
            Assert.False(OpenVpnDataCipher.TryResolve("BF-CBC", out _)); // unsupported

            Assert.Equal("AES-256-GCM:AES-128-GCM:CHACHA20-POLY1305", OpenVpnDataCipher.AdvertisedList);
        }

        [Fact]
        public void ServerCipherList_PicksFirstSupportedInServerOrder()
        {
            // Server's order wins: the first mutually-supported entry is chosen even when later entries are also supported.
            Assert.True(OpenVpnDataCipher.TryResolveServerList("UNKNOWN-CIPHER:CHACHA20-POLY1305:AES-256-GCM", out OpenVpnDataCipher c));
            Assert.Equal("CHACHA20-POLY1305", c.Name);

            Assert.False(OpenVpnDataCipher.TryResolveServerList("BF-CBC:DES-CBC", out _)); // nothing supported
            Assert.False(OpenVpnDataCipher.TryResolveServerList("", out _));
            Assert.False(OpenVpnDataCipher.TryResolveServerList(null, out _));
        }

        [Fact]
        public void ExtractIvCiphers_ReadsServerPushedList()
        {
            // The server may echo its NCP offer in the key-method-2 reply options (newline- or comma-separated key=value).
            Assert.Equal("AES-128-GCM:AES-256-GCM",
                OpenVpnDataCipher.ExtractIvCiphers("V4,dev-type tun\nIV_CIPHERS=AES-128-GCM:AES-256-GCM\nIV_PROTO=6"));
            Assert.Equal("AES-256-GCM",
                OpenVpnDataCipher.ExtractIvCiphers("V4,iv_ciphers=AES-256-GCM,cipher AES-256-GCM")); // case-insensitive key
            Assert.Null(OpenVpnDataCipher.ExtractIvCiphers("V4,cipher AES-256-GCM")); // no IV_CIPHERS line
            Assert.Null(OpenVpnDataCipher.ExtractIvCiphers(null));
        }

        [Fact]
        public void PeerInfo_CarriesCiphersAndProto()
        {
            string peerInfo = OpenVpnPeerInfo.Build();
            Assert.Contains("IV_CIPHERS=AES-256-GCM:AES-128-GCM:CHACHA20-POLY1305", peerInfo);
            Assert.Contains("IV_NCP=2", peerInfo);
            Assert.Contains($"IV_PROTO={OpenVpnPeerInfo.IvProtoDataV2 | OpenVpnPeerInfo.IvProtoRequestPush}", peerInfo);
            // The minimal always-on lines are present; IV_MTU is opt-in (the connection fills it), so absent by default.
            Assert.Contains("IV_VER=", peerInfo);
            Assert.Contains("IV_PLAT=", peerInfo);
            Assert.DoesNotContain("IV_MTU=", peerInfo);
        }

        [Fact]
        public void PeerInfo_AdvancedOptions_EmitMtuPlatformAndUserVars()
        {
            string peerInfo = OpenVpnPeerInfo.Build(new OpenVpnPeerInfoOptions
            {
                Platform = "win",
                Mtu = 1400,
                GuiVersion = "tqkvpn 1.0",
                PlatformVersion = null,                 // explicitly omit the auto OS line
                Extra = new[] { new KeyValuePair<string, string>("UV_ID", "client-7") },
            });

            Assert.Contains("IV_PLAT=win\n", peerInfo);
            Assert.Contains("IV_MTU=1400\n", peerInfo);
            Assert.Contains("IV_GUI_VER=tqkvpn 1.0\n", peerInfo);
            Assert.Contains("UV_ID=client-7\n", peerInfo);
            Assert.DoesNotContain("IV_PLAT_VER=", peerInfo); // omitted via null
            // Custom IV_PROTO bits flow through verbatim (e.g. future tls-ekm / exit-notify capabilities).
            string withBits = OpenVpnPeerInfo.Build(new OpenVpnPeerInfoOptions
            {
                IvProto = OpenVpnPeerInfo.IvProtoDataV2 | OpenVpnPeerInfo.IvProtoRequestPush | OpenVpnPeerInfo.IvProtoCcExitNotify,
            });
            Assert.Contains($"IV_PROTO={OpenVpnPeerInfo.IvProtoDataV2 | OpenVpnPeerInfo.IvProtoRequestPush | OpenVpnPeerInfo.IvProtoCcExitNotify}\n", withBits);
        }

        [Theory]
        [InlineData("AES-256-GCM", 32)]
        [InlineData("AES-128-GCM", 16)]
        [InlineData("CHACHA20-POLY1305", 32)]
        public void NegotiatedCipher_DerivesComplementaryKeys_AndDataFlows(string cipherName, int expectedKeyLen)
        {
            Assert.True(OpenVpnDataCipher.TryResolve(cipherName, out OpenVpnDataCipher cipher));

            // Shared key2 (cipher-independent), then slice for the negotiated cipher on each side.
            var clientKs = OpenVpnKeySource2.GenerateClient();
            byte[] r1 = new byte[OpenVpnKeySource2.RandomSize], r2 = new byte[OpenVpnKeySource2.RandomSize];
            for (int i = 0; i < r1.Length; i++) { r1[i] = (byte)(i + 5); r2[i] = (byte)(i + 50); }
            var serverKs = new OpenVpnKeySource2(Array.Empty<byte>(), r1, r2);

            byte[] key2 = OpenVpnKeyMethod2.DeriveKey2(clientKs, serverKs, 0xAAAA, 0xBBBB);
            var clientKeys = new OpenVpnKeyMaterial(key2).DeriveDataKeys(cipher, isServer: false);
            var serverKeys = OpenVpnKeyMethod2.SliceDataKeys(key2, cipher, isServer: true);

            Assert.Equal(expectedKeyLen, clientKeys.SendCipherKey.Length);
            Assert.Equal(clientKeys.SendCipherKey, serverKeys.ReceiveCipherKey);
            Assert.Equal(clientKeys.ReceiveCipherKey, serverKeys.SendCipherKey);

            // Drive the data channel with the negotiated AEAD (so CHACHA20-POLY1305 is genuinely exercised); a packet round-trips.
            var clientDc = new OpenVpnDataChannel(clientKeys, cipher: cipher.CreateCipher());
            var serverDc = new OpenVpnDataChannel(serverKeys, cipher: cipher.CreateCipher());
            byte[] payload = Encoding.ASCII.GetBytes($"data over {cipherName}");
            Assert.True(serverDc.TryUnprotect(clientDc.Protect(payload), out byte[] got));
            Assert.Equal(payload, got);
        }
    }
}
