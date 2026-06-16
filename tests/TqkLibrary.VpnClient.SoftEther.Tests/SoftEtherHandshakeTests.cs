using System.Buffers.Binary;
using System.Text;
using System.Threading.Channels;
using TqkLibrary.VpnClient.Abstractions.Transport.Interfaces;
using TqkLibrary.VpnClient.Crypto;
using TqkLibrary.VpnClient.SoftEther.Enums;
using TqkLibrary.VpnClient.SoftEther.Models;
using Xunit;

namespace TqkLibrary.VpnClient.SoftEther.Tests
{
    /// <summary>
    /// Offline tests for the SoftEther V4.b handshake codec: watermark POST framing, SHA-0 password auth against a
    /// hand-built vector, the login PACK fields, and the full hello→login→welcome flow driven over an in-memory stub
    /// server (no network, no Integration trait). Also covers a server that rejects the login.
    /// </summary>
    public class SoftEtherHandshakeTests
    {
        static SoftEtherAuth NewAuth() => new(new Sha0());
        static SoftEtherHandshake NewHandshake(int seed = 1) => new(NewAuth(), new Random(seed));

        static byte[] Challenge(byte start = 1)
        {
            var r = new byte[SoftEtherProtocol.RandomSize];
            for (int i = 0; i < r.Length; i++) r[i] = (byte)(start + i);
            return r;
        }

        // ---- Auth (SHA-0) vector --------------------------------------------------------------------

        [Fact]
        public void Auth_SecurePassword_MatchesHandBuiltSha0Vector()
        {
            const string password = "P@ssw0rd";
            const string username = "alice";
            byte[] serverRandom = Challenge();

            // Hand-built: SecurePassword = SHA0( SHA0(password || UPPER(username)) || server_random ).
            byte[] hashed = Sha0.Hash(Concat(
                Encoding.ASCII.GetBytes(password),
                Encoding.ASCII.GetBytes(username.ToUpperInvariant())));
            byte[] expected = Sha0.Hash(Concat(hashed, serverRandom));

            byte[] actual = NewAuth().ComputeSecurePassword(password, username, serverRandom);
            Assert.Equal(expected, actual);
            Assert.Equal(20, actual.Length);
        }

        [Fact]
        public void Auth_HashPassword_IsChallengeIndependent()
        {
            byte[] h1 = NewAuth().HashPassword("pw", "user");
            byte[] h2 = NewAuth().HashPassword("pw", "USER"); // username upper-cased ⇒ same hash
            Assert.Equal(h1, h2);

            // But secure password differs per challenge.
            byte[] s1 = NewAuth().SecureFromHashedPassword(h1, Challenge(1));
            byte[] s2 = NewAuth().SecureFromHashedPassword(h1, Challenge(2));
            Assert.NotEqual(s1, s2);
        }

        [Fact]
        public void Auth_RejectsWrongSizedHashOrRandom()
        {
            SoftEtherAuth auth = NewAuth();
            Assert.Throws<ArgumentException>(() => auth.SecureFromHashedPassword(new byte[19], Challenge()));
            Assert.Throws<ArgumentException>(() => auth.SecureFromHashedPassword(new byte[20], new byte[19]));
        }

        // ---- Watermark POST -------------------------------------------------------------------------

        [Fact]
        public void Watermark_BuildRequest_HasCorrectPostLineAndBody()
        {
            var watermark = new SoftEtherWatermark();
            byte[] request = watermark.BuildRequest("vpn.example.com");
            string text = Encoding.ASCII.GetString(request);

            Assert.StartsWith("POST /vpnsvc/connect.cgi HTTP/1.1\r\n", text);
            Assert.Contains("Host: vpn.example.com\r\n", text);
            Assert.Contains($"Content-Length: {watermark.BodyLength}\r\n", text);

            // The body that follows the blank line must be exactly the signature (no padding by default).
            int bodyStart = text.IndexOf("\r\n\r\n", StringComparison.Ordinal) + 4;
            byte[] body = request[bodyStart..];
            Assert.Equal(watermark.Signature.ToArray(), body);
            Assert.True(watermark.Matches(body));
        }

        [Fact]
        public void Watermark_WithRandomPadding_AppendsAfterSignature()
        {
            var watermark = new SoftEtherWatermark().WithRandomPadding(64, new Random(7));
            Assert.Equal(SoftEtherWatermark.DefaultSignature.Length + 64, watermark.BodyLength);

            byte[] request = watermark.BuildRequest("h");
            int bodyStart = IndexOfHeaderEnd(request) + 4;
            byte[] body = request[bodyStart..];
            // Signature is still a prefix of the body (the server validates that).
            Assert.True(watermark.Matches(body));
            Assert.Equal(watermark.BodyLength, body.Length);
        }

        // ---- Login PACK fields ----------------------------------------------------------------------

        [Fact]
        public void BuildLoginPack_PasswordAuth_HasAllFields()
        {
            byte[] serverRandom = Challenge();
            var request = new SoftEtherLoginRequest
            {
                HubName = "DEFAULT",
                UserName = "alice",
                Password = "P@ssw0rd",
                Session = new SoftEtherSessionParams
                {
                    MaxConnection = 8,
                    UseEncrypt = true,
                    UseCompress = false,
                    HalfConnection = false,
                    UniqueId = Enumerable.Repeat((byte)0x5A, 20).ToArray(),
                },
            };

            Pack pack = NewHandshake().BuildLoginPack(request, serverRandom);

            Assert.Equal("login", pack.GetStr("method"));
            Assert.Equal("DEFAULT", pack.GetStr("hubname"));
            Assert.Equal("alice", pack.GetStr("username"));
            Assert.Equal((uint)SoftEtherAuthType.Password, pack.GetInt("authtype"));
            Assert.Equal(8u, pack.GetInt("max_connection"));
            Assert.True(pack.GetBool("use_encrypt"));
            Assert.False(pack.GetBool("use_compress"));
            Assert.False(pack.GetBool("half_connection"));
            Assert.Equal(20, pack.GetData("unique_id")!.Length);

            // secure_password must equal the hand-built SHA-0 mix and the password must NOT appear anywhere.
            byte[] expectedSecure = NewAuth().ComputeSecurePassword("P@ssw0rd", "alice", serverRandom);
            Assert.Equal(expectedSecure, pack.GetData("secure_password"));
            Assert.DoesNotContain("P@ssw0rd", AnsiOf(pack));
        }

        [Fact]
        public void BuildLoginPack_GeneratesUniqueIdWhenAbsent()
        {
            Pack pack = NewHandshake().BuildLoginPack(
                new SoftEtherLoginRequest { HubName = "DEFAULT", UserName = "u", Password = "p" }, Challenge());
            byte[]? id = pack.GetData("unique_id");
            Assert.NotNull(id);
            Assert.Equal(SoftEtherSessionParams.UniqueIdLength, id!.Length);
        }

        [Fact]
        public void BuildLoginPack_PlainPasswordAuth_UsesPlainField()
        {
            var request = new SoftEtherLoginRequest
            {
                HubName = "DEFAULT", UserName = "u", Password = "secret", AuthType = SoftEtherAuthType.PlainPassword,
            };
            Pack pack = NewHandshake().BuildLoginPack(request, Challenge());
            Assert.Equal((uint)SoftEtherAuthType.PlainPassword, pack.GetInt("authtype"));
            Assert.Equal("secret", pack.GetStr("plain_password"));
            Assert.Null(pack.GetData("secure_password"));
        }

        [Fact]
        public void BuildLoginPack_RejectsWrongSizedChallenge()
        {
            Assert.Throws<ArgumentException>(() => NewHandshake().BuildLoginPack(
                new SoftEtherLoginRequest { HubName = "h", UserName = "u" }, new byte[19]));
        }

        // ---- Hello parsing --------------------------------------------------------------------------

        [Fact]
        public void ParseHello_ExtractsFields()
        {
            byte[] random = Challenge(0xA0);
            var pack = new Pack()
                .SetStr("hello", "softether")
                .SetInt("version", 441u)
                .SetInt("build", 9772u)
                .SetData("random", random);

            SoftEtherHelloInfo hello = NewHandshake().ParseHello(pack);
            Assert.Equal("softether", hello.Hello);
            Assert.Equal(441u, hello.Version);
            Assert.Equal(9772u, hello.Build);
            Assert.Equal(random, hello.Random);
        }

        [Fact]
        public void ParseHello_RejectsMissingRandomOrWrongSize()
        {
            SoftEtherHandshake hs = NewHandshake();
            Assert.Throws<SoftEtherProtocolException>(() => hs.ParseHello(new Pack().SetStr("hello", "softether")));
            Assert.Throws<SoftEtherProtocolException>(() => hs.ParseHello(
                new Pack().SetStr("hello", "softether").SetData("random", new byte[19])));
        }

        // ---- Welcome / error parsing ----------------------------------------------------------------

        [Fact]
        public void ParseWelcome_Success_ReturnsSessionKey()
        {
            byte[] key = Enumerable.Range(0, 20).Select(i => (byte)i).ToArray();
            var pack = new Pack().SetInt("error", 0u).SetData("session_name", key);
            SoftEtherWelcomeInfo welcome = NewHandshake().ParseWelcome(pack);
            Assert.Equal(key, welcome.SessionKey);
        }

        [Fact]
        public void ParseWelcome_NonZeroError_Throws()
        {
            var pack = new Pack().SetInt("error", 13u);
            var ex = Assert.Throws<SoftEtherProtocolException>(() => NewHandshake().ParseWelcome(pack));
            Assert.Equal(13u, ex.ErrorCode);
        }

        // ---- HTTP-PACK framing ----------------------------------------------------------------------

        [Fact]
        public void HttpPackCodec_FrameBody_RoundTrips()
        {
            var pack = new Pack().SetStr("hello", "softether").SetInt("version", 5u);
            byte[] body = SoftEtherHttpPackCodec.FrameBody(pack);
            // First 4 bytes = big-endian length of the PACK bytes.
            uint declared = BinaryPrimitives.ReadUInt32BigEndian(body);
            Assert.Equal((uint)(body.Length - 4), declared);
            Pack parsed = SoftEtherHttpPackCodec.ParseBody(body);
            Assert.Equal("softether", parsed.GetStr("hello"));
            Assert.Equal(5u, parsed.GetInt("version"));
        }

        [Fact]
        public void HttpPackCodec_ParseBody_RejectsTooShortOrInconsistent()
        {
            Assert.Throws<FormatException>(() => SoftEtherHttpPackCodec.ParseBody(new byte[] { 0, 0 }));
            // length prefix claims more bytes than present
            byte[] bad = new byte[6];
            BinaryPrimitives.WriteUInt32BigEndian(bad, 100u);
            Assert.Throws<FormatException>(() => SoftEtherHttpPackCodec.ParseBody(bad));
        }

        // ---- End-to-end over an in-memory stub server -----------------------------------------------

        [Fact]
        public async Task RunAsync_FullHandshake_AgainstStubServer_Succeeds()
        {
            byte[] serverRandom = Challenge(0x10);
            byte[] sessionKey = Enumerable.Repeat((byte)0xAB, 20).ToArray();

            var (clientSide, server) = StubServer.Create();
            var serverTask = server.RunSuccessfulLoginAsync(serverRandom, sessionKey, "DEFAULT", "alice", "P@ssw0rd");

            var request = new SoftEtherLoginRequest { HubName = "DEFAULT", UserName = "alice", Password = "P@ssw0rd" };
            SoftEtherWelcomeInfo welcome = await NewHandshake()
                .RunAsync(clientSide, "vpn.example.com", request);

            Assert.Equal(sessionKey, welcome.SessionKey);
            await serverTask; // server-side asserts the client's watermark + login fields matched.
        }

        [Fact]
        public async Task RunAsync_ServerRejectsLogin_ThrowsWithErrorCode()
        {
            byte[] serverRandom = Challenge(0x20);
            var (clientSide, server) = StubServer.Create();
            var serverTask = server.RunRejectedLoginAsync(serverRandom, errorCode: 9);

            var request = new SoftEtherLoginRequest { HubName = "DEFAULT", UserName = "bob", Password = "wrong" };
            var ex = await Assert.ThrowsAsync<SoftEtherProtocolException>(() =>
                NewHandshake().RunAsync(clientSide, "vpn.example.com", request).AsTask());
            Assert.Equal(9u, ex.ErrorCode);
            await serverTask;
        }

        // ---- helpers --------------------------------------------------------------------------------

        static int IndexOfHeaderEnd(byte[] bytes)
        {
            for (int i = 0; i + 3 < bytes.Length; i++)
                if (bytes[i] == '\r' && bytes[i + 1] == '\n' && bytes[i + 2] == '\r' && bytes[i + 3] == '\n')
                    return i;
            return -1;
        }

        static string AnsiOf(Pack pack) => Encoding.Latin1.GetString(pack.ToBytes());

        static byte[] Concat(byte[] a, byte[] b)
        {
            var r = new byte[a.Length + b.Length];
            Buffer.BlockCopy(a, 0, r, 0, a.Length);
            Buffer.BlockCopy(b, 0, r, a.Length, b.Length);
            return r;
        }

        /// <summary>
        /// In-memory full-duplex byte-stream pair plus a stub SoftEther server that reads the client's HTTP messages
        /// and replies with hand-built hello/welcome PACKs. The client uses one end as its <see cref="IByteStreamTransport"/>.
        /// </summary>
        sealed class StubServer
        {
            readonly DuplexPipe _serverEnd;

            StubServer(DuplexPipe serverEnd) => _serverEnd = serverEnd;

            public static (IByteStreamTransport client, StubServer server) Create()
            {
                var (a, b) = DuplexPipe.CreatePair();
                return (a, new StubServer(b));
            }

            public async Task RunSuccessfulLoginAsync(
                byte[] serverRandom, byte[] sessionKey, string expectedHub, string expectedUser, string password)
            {
                // 1) Read the watermark POST (request line + body); validate the POST line + watermark signature.
                (string head, byte[] body) = await ReadHttpMessageAsync();
                Assert.StartsWith("POST /vpnsvc/connect.cgi HTTP/1.1", head);
                Assert.True(new SoftEtherWatermark().Matches(body));

                // 2) Reply with the hello PACK.
                var hello = new Pack()
                    .SetStr("hello", "softether").SetInt("version", 441u).SetInt("build", 9772u)
                    .SetData("random", serverRandom);
                await _serverEnd.WriteAsync(SoftEtherHttpPackCodec.BuildOkResponse(hello));

                // 3) Read the login POST and validate its fields + the SHA-0 secure password.
                (string loginHead, byte[] loginBody) = await ReadHttpMessageAsync();
                Assert.StartsWith("POST /vpnsvc/vpn.cgi HTTP/1.1", loginHead);
                Pack login = SoftEtherHttpPackCodec.ParseBody(loginBody);
                Assert.Equal("login", login.GetStr("method"));
                Assert.Equal(expectedHub, login.GetStr("hubname"));
                Assert.Equal(expectedUser, login.GetStr("username"));
                byte[] expectedSecure = new SoftEtherAuth(new Sha0())
                    .ComputeSecurePassword(password, expectedUser, serverRandom);
                Assert.Equal(expectedSecure, login.GetData("secure_password"));

                // 4) Reply with the welcome PACK.
                var welcome = new Pack().SetInt("error", 0u).SetData("session_name", sessionKey);
                await _serverEnd.WriteAsync(SoftEtherHttpPackCodec.BuildOkResponse(welcome));
            }

            public async Task RunRejectedLoginAsync(byte[] serverRandom, uint errorCode)
            {
                await ReadHttpMessageAsync(); // watermark POST
                var hello = new Pack().SetStr("hello", "softether").SetData("random", serverRandom);
                await _serverEnd.WriteAsync(SoftEtherHttpPackCodec.BuildOkResponse(hello));

                await ReadHttpMessageAsync(); // login POST
                var error = new Pack().SetInt("error", errorCode);
                await _serverEnd.WriteAsync(SoftEtherHttpPackCodec.BuildOkResponse(error));
            }

            async Task<(string head, byte[] body)> ReadHttpMessageAsync()
            {
                var buffer = new List<byte>();
                int headerEnd = -1;
                var chunk = new byte[1024];
                while (headerEnd < 0)
                {
                    int n = await _serverEnd.ReadAsync(chunk);
                    Assert.True(n > 0, "server: stream closed before headers");
                    for (int i = 0; i < n; i++) buffer.Add(chunk[i]);
                    headerEnd = FindHeaderEnd(buffer);
                }
                string head = Encoding.ASCII.GetString(buffer.ToArray(), 0, headerEnd);
                int contentLength = ParseContentLength(head);
                int bodyStart = headerEnd + 4;
                var body = new byte[contentLength];
                int have = Math.Min(contentLength, buffer.Count - bodyStart);
                for (int i = 0; i < have; i++) body[i] = buffer[bodyStart + i];
                int filled = have;
                while (filled < contentLength)
                {
                    int n = await _serverEnd.ReadAsync(new Memory<byte>(body, filled, contentLength - filled));
                    Assert.True(n > 0, "server: stream closed before body");
                    filled += n;
                }
                return (head, body);
            }

            static int FindHeaderEnd(List<byte> buffer)
            {
                for (int i = 0; i + 3 < buffer.Count; i++)
                    if (buffer[i] == '\r' && buffer[i + 1] == '\n' && buffer[i + 2] == '\r' && buffer[i + 3] == '\n')
                        return i;
                return -1;
            }

            static int ParseContentLength(string head)
            {
                foreach (string line in head.Split(new[] { "\r\n" }, StringSplitOptions.None))
                {
                    int c = line.IndexOf(':');
                    if (c < 0) continue;
                    if (line.Substring(0, c).Trim().Equals("Content-Length", StringComparison.OrdinalIgnoreCase))
                        return int.Parse(line.Substring(c + 1).Trim());
                }
                throw new InvalidOperationException("no Content-Length");
            }
        }

        /// <summary>
        /// An in-memory <see cref="IByteStreamTransport"/> backed by two byte channels (one per direction). Two of
        /// these wired crosswise form a loopback pipe between client and stub server.
        /// </summary>
        sealed class DuplexPipe : IByteStreamTransport
        {
            readonly Channel<byte[]> _inbound;
            readonly Channel<byte[]> _outbound;
            byte[] _readRemainder = Array.Empty<byte>();
            int _readOffset;

            DuplexPipe(Channel<byte[]> inbound, Channel<byte[]> outbound)
            {
                _inbound = inbound;
                _outbound = outbound;
            }

            public static (DuplexPipe a, DuplexPipe b) CreatePair()
            {
                var x = Channel.CreateUnbounded<byte[]>();
                var y = Channel.CreateUnbounded<byte[]>();
                return (new DuplexPipe(x, y), new DuplexPipe(y, x));
            }

            public ValueTask ConnectAsync(CancellationToken cancellationToken = default) => default;

            public async ValueTask<int> ReadAsync(Memory<byte> buffer, CancellationToken cancellationToken = default)
            {
                if (_readOffset >= _readRemainder.Length)
                {
                    _readRemainder = await _inbound.Reader.ReadAsync(cancellationToken).ConfigureAwait(false);
                    _readOffset = 0;
                }
                int n = Math.Min(buffer.Length, _readRemainder.Length - _readOffset);
                _readRemainder.AsSpan(_readOffset, n).CopyTo(buffer.Span);
                _readOffset += n;
                return n;
            }

            public ValueTask WriteAsync(ReadOnlyMemory<byte> buffer, CancellationToken cancellationToken = default)
            {
                _outbound.Writer.TryWrite(buffer.ToArray());
                return default;
            }

            public ValueTask DisposeAsync()
            {
                _outbound.Writer.TryComplete();
                return default;
            }
        }
    }
}
