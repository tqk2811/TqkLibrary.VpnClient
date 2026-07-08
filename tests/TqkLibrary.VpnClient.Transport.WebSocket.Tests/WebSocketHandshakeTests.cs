using System.Text;
using TqkLibrary.VpnClient.Transport.WebSocket;
using Xunit;

namespace TqkLibrary.VpnClient.Transport.WebSocket.Tests
{
    /// <summary>
    /// Tests for the RFC 6455 §4 opening handshake helper: the §1.3 <c>Sec-WebSocket-Accept</c> worked example, the
    /// client request format, and response validation (accept a valid 101, reject wrong/missing accept and non-101).
    /// </summary>
    public class WebSocketHandshakeTests
    {
        [Fact]
        public void ComputeAccept_MatchesRfc6455Section1_3_Vector()
        {
            // RFC 6455 §1.3: key "dGhlIHNhbXBsZSBub25jZQ==" ⇒ accept "s3pPLMBiTxaQ9kYGzzhZRbK+xOo=".
            string accept = WebSocketHandshake.ComputeAccept("dGhlIHNhbXBsZSBub25jZQ==");
            Assert.Equal("s3pPLMBiTxaQ9kYGzzhZRbK+xOo=", accept);
        }

        [Fact]
        public void BuildClientRequest_ProducesWellFormedUpgrade()
        {
            byte[] bytes = WebSocketHandshake.BuildClientRequest("example.org", "/tunnel", "dGhlIHNhbXBsZSBub25jZQ==");
            string text = Encoding.ASCII.GetString(bytes);

            Assert.StartsWith("GET /tunnel HTTP/1.1\r\n", text);
            Assert.Contains("Host: example.org\r\n", text);
            Assert.Contains("Upgrade: websocket\r\n", text);
            Assert.Contains("Connection: Upgrade\r\n", text);
            Assert.Contains("Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n", text);
            Assert.Contains("Sec-WebSocket-Version: 13\r\n", text);
            Assert.EndsWith("\r\n\r\n", text);
            Assert.DoesNotContain("Sec-WebSocket-Protocol", text);
        }

        [Fact]
        public void BuildClientRequest_EmptyPath_DefaultsToRoot()
        {
            string text = Encoding.ASCII.GetString(WebSocketHandshake.BuildClientRequest("h", "", "k"));
            Assert.StartsWith("GET / HTTP/1.1\r\n", text);
        }

        [Fact]
        public void BuildClientRequest_IncludesSubProtocol_WhenProvided()
        {
            string text = Encoding.ASCII.GetString(
                WebSocketHandshake.BuildClientRequest("h", "/", "k", subProtocol: "chat"));
            Assert.Contains("Sec-WebSocket-Protocol: chat\r\n", text);
        }

        [Fact]
        public void TryParseResponse_Accepts_Valid101()
        {
            string accept = WebSocketHandshake.ComputeAccept("dGhlIHNhbXBsZSBub25jZQ==");
            string response = "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n" +
                              "Sec-WebSocket-Accept: " + accept + "\r\n\r\n";
            Assert.True(WebSocketHandshake.TryParseResponse(response, accept));
        }

        [Fact]
        public void TryParseResponse_Accepts_ByteSpanOverload()
        {
            string accept = WebSocketHandshake.ComputeAccept("dGhlIHNhbXBsZSBub25jZQ==");
            byte[] response = Encoding.ASCII.GetBytes(
                "HTTP/1.1 101 Switching Protocols\r\nSec-WebSocket-Accept: " + accept + "\r\n\r\n");
            Assert.True(WebSocketHandshake.TryParseResponse(response, accept));
        }

        [Fact]
        public void TryParseResponse_Rejects_WrongAccept()
        {
            string response = "HTTP/1.1 101 Switching Protocols\r\nSec-WebSocket-Accept: WRONGWRONGWRONG=\r\n\r\n";
            string expected = WebSocketHandshake.ComputeAccept("dGhlIHNhbXBsZSBub25jZQ==");
            Assert.False(WebSocketHandshake.TryParseResponse(response, expected));
        }

        [Fact]
        public void TryParseResponse_Rejects_MissingAcceptHeader()
        {
            string response = "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\n\r\n";
            string expected = WebSocketHandshake.ComputeAccept("dGhlIHNhbXBsZSBub25jZQ==");
            Assert.False(WebSocketHandshake.TryParseResponse(response, expected));
        }

        [Theory]
        [InlineData("HTTP/1.1 200 OK")]
        [InlineData("HTTP/1.1 400 Bad Request")]
        [InlineData("HTTP/1.1 401 Unauthorized")]
        public void TryParseResponse_Rejects_NonUpgradeStatus(string statusLine)
        {
            string accept = WebSocketHandshake.ComputeAccept("dGhlIHNhbXBsZSBub25jZQ==");
            string response = statusLine + "\r\nSec-WebSocket-Accept: " + accept + "\r\n\r\n";
            Assert.False(WebSocketHandshake.TryParseResponse(response, accept));
        }
    }
}
