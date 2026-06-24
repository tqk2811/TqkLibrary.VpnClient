using System.Text.Json;
using TqkLibrary.VpnClient.Tailscale.Control.Messages;
using Xunit;

namespace TqkLibrary.VpnClient.Tailscale.Tests
{
    public class TailscaleMessageJsonTests
    {
        [Fact]
        public void RegisterRequest_SerializesPascalCase_WithAuthKey()
        {
            var req = new RegisterRequest
            {
                Version = 113,
                NodeKey = "nodekey:" + new string('a', 64),
                Auth = new RegisterResponseAuth { AuthKey = "secret-preauth" },
                Hostinfo = new Hostinfo { Hostname = "lab", OS = "linux" },
            };
            string json = JsonSerializer.Serialize(req);

            // Go wire structs use PascalCase field names verbatim.
            Assert.Contains("\"Version\":113", json);
            Assert.Contains("\"NodeKey\":\"nodekey:", json);
            Assert.Contains("\"Auth\":{", json);
            Assert.Contains("\"AuthKey\":\"secret-preauth\"", json);
            Assert.Contains("\"Hostinfo\":{", json);
            // Null OldNodeKey is omitted.
            Assert.DoesNotContain("OldNodeKey", json);
        }

        [Fact]
        public void OverTlsPublicKeyResponse_DeserializesLowerCamelCase()
        {
            string json = "{\"legacyPublicKey\":\"\",\"publicKey\":\"mkey:" + new string('b', 64) + "\"}";
            OverTlsPublicKeyResponse? resp = JsonSerializer.Deserialize<OverTlsPublicKeyResponse>(json);
            Assert.NotNull(resp);
            Assert.StartsWith("mkey:", resp!.PublicKey);
        }

        [Fact]
        public void MapResponse_DeserializesNodeAndPeers()
        {
            string json = @"{
              ""Node"": {
                ""ID"": 1,
                ""Key"": ""nodekey:aaaa"",
                ""Addresses"": [""100.64.0.1/32"", ""fd7a:115c:a1e0::1/128""]
              },
              ""Peers"": [
                {
                  ""ID"": 2,
                  ""Key"": ""nodekey:bbbb"",
                  ""Addresses"": [""100.64.0.2/32""],
                  ""AllowedIPs"": [""100.64.0.2/32""],
                  ""Endpoints"": [""192.168.1.7:41641""],
                  ""DERP"": ""127.3.3.40:1"",
                  ""Online"": true
                }
              ],
              ""Domain"": ""lab.example""
            }";
            MapResponse? map = JsonSerializer.Deserialize<MapResponse>(json);
            Assert.NotNull(map);
            Assert.NotNull(map!.Node);
            Assert.Equal(1, map.Node!.ID);
            Assert.Equal(2, map.Node.Addresses!.Count);
            Assert.Single(map.Peers!);
            TailscaleNode peer = map.Peers![0];
            Assert.Equal(2, peer.ID);
            Assert.Equal("nodekey:bbbb", peer.Key);
            Assert.Equal("192.168.1.7:41641", peer.Endpoints![0]);
            Assert.Equal("127.3.3.40:1", peer.Derp); // DERP rename captured
            Assert.True(peer.Online);
        }

        [Fact]
        public void MapRequest_SerializesStreamAndEmptyCompress()
        {
            var req = new MapRequest
            {
                Version = 113,
                NodeKey = "nodekey:" + new string('c', 64),
                Stream = false,
                Compress = "",
            };
            string json = JsonSerializer.Serialize(req);
            Assert.Contains("\"Stream\":false", json);
            Assert.Contains("\"Compress\":\"\"", json);
        }
    }
}
