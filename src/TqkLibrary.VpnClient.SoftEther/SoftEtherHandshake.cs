using System.Globalization;
using System.Text;
using TqkLibrary.VpnClient.Abstractions.Transport.Interfaces;
using TqkLibrary.VpnClient.SoftEther.Enums;
using TqkLibrary.VpnClient.SoftEther.Models;

namespace TqkLibrary.VpnClient.SoftEther
{
    /// <summary>
    /// Drives the SoftEther SSL-VPN control handshake on top of an established TLS byte stream
    /// (<see cref="IByteStreamTransport"/>, reused from F.1): watermark POST → read server <c>hello</c> PACK → POST
    /// <c>login</c> PACK (with SHA-0 <c>secure_password</c> + session params) → read <c>welcome</c> / error PACK.
    /// <para>
    /// The codec / state half is fully separated from socket I/O so it is offline-testable: <see cref="ParseHello"/>,
    /// <see cref="BuildLoginPack"/> and <see cref="ParseWelcome"/> are pure functions over <see cref="Pack"/>; the
    /// async <see cref="RunAsync"/> only wires them to the stream (write request bytes, read one HTTP message). Tests
    /// run it against an in-memory stub server, and may also exercise the pure methods directly.
    /// </para>
    /// Auth hashing is delegated to <see cref="SoftEtherAuth"/> (SHA-0, F.5a); HTTP framing to
    /// <see cref="SoftEtherHttpPackCodec"/>.
    /// </summary>
    public sealed class SoftEtherHandshake
    {
        readonly SoftEtherAuth _auth;
        readonly Random _random;

        /// <summary>Creates a handshake driver over the given authenticator and an optional RNG (for unique-id/padding).</summary>
        public SoftEtherHandshake(SoftEtherAuth auth, Random? random = null)
        {
            _auth = auth ?? throw new ArgumentNullException(nameof(auth));
            _random = random ?? new Random();
        }

        // ---- Pure codec / state ----------------------------------------------------------------------

        /// <summary>
        /// Parses a server <c>hello</c> PACK into <see cref="SoftEtherHelloInfo"/>. Throws
        /// <see cref="SoftEtherProtocolException"/> if the greeting is absent or the random challenge is not the
        /// expected 20 bytes.
        /// </summary>
        public SoftEtherHelloInfo ParseHello(Pack hello)
        {
            if (hello is null) throw new ArgumentNullException(nameof(hello));

            string? greeting = hello.GetStr(SoftEtherProtocol.HelloName);
            byte[]? random = hello.GetData(SoftEtherProtocol.RandomName);
            if (greeting is null || random is null)
                throw new SoftEtherProtocolException("SoftEther hello PACK is missing the 'hello' greeting or 'random' challenge.");
            if (random.Length != SoftEtherProtocol.RandomSize)
                throw new SoftEtherProtocolException(
                    $"SoftEther hello 'random' must be {SoftEtherProtocol.RandomSize} bytes, got {random.Length}.");

            return new SoftEtherHelloInfo
            {
                Hello = greeting,
                Version = hello.GetInt(SoftEtherProtocol.VersionName),
                Build = hello.GetInt(SoftEtherProtocol.BuildName),
                Random = random,
            };
        }

        /// <summary>
        /// Builds the client <c>login</c> PACK for <paramref name="request"/> against the server challenge
        /// <paramref name="serverRandom"/>: method/hubname/username/authtype, the credential (SHA-0
        /// <c>secure_password</c> for password auth, or <c>plain_password</c>), and the session params
        /// (max_connection/use_encrypt/use_compress/half_connection/unique_id). Pure — no I/O.
        /// </summary>
        public Pack BuildLoginPack(SoftEtherLoginRequest request, ReadOnlySpan<byte> serverRandom)
        {
            if (request is null) throw new ArgumentNullException(nameof(request));
            if (serverRandom.Length != SoftEtherProtocol.RandomSize)
                throw new ArgumentException($"serverRandom must be {SoftEtherProtocol.RandomSize} bytes.", nameof(serverRandom));

            var pack = new Pack()
                .SetStr(SoftEtherProtocol.MethodName, SoftEtherProtocol.MethodLogin)
                .SetStr(SoftEtherProtocol.HubNameName, request.HubName)
                .SetStr(SoftEtherProtocol.UserNameName, request.UserName)
                .SetInt(SoftEtherProtocol.AuthTypeName, (uint)request.AuthType);

            switch (request.AuthType)
            {
                case SoftEtherAuthType.Password:
                    byte[] secure = _auth.ComputeSecurePassword(request.Password, request.UserName, serverRandom);
                    pack.SetData(SoftEtherProtocol.SecurePasswordName, secure);
                    break;
                case SoftEtherAuthType.PlainPassword:
                    pack.SetStr(SoftEtherProtocol.PlainPasswordName, request.Password);
                    break;
                case SoftEtherAuthType.Anonymous:
                    break;
                default:
                    throw new SoftEtherProtocolException($"SoftEther auth type {request.AuthType} is not supported yet.");
            }

            SoftEtherSessionParams session = request.Session;
            byte[] uniqueId = session.UniqueId ?? NewUniqueId();
            pack.SetInt(SoftEtherProtocol.MaxConnectionName, session.MaxConnection)
                .SetBool(SoftEtherProtocol.UseEncryptName, session.UseEncrypt)
                .SetBool(SoftEtherProtocol.UseCompressName, session.UseCompress)
                .SetBool(SoftEtherProtocol.HalfConnectionName, session.HalfConnection)
                .SetData(SoftEtherProtocol.UniqueIdName, uniqueId);

            return pack;
        }

        /// <summary>
        /// Parses a server reply to a login. A non-zero <c>error</c> field (or a missing session key) ⇒
        /// <see cref="SoftEtherProtocolException"/>; otherwise returns the <see cref="SoftEtherWelcomeInfo"/>.
        /// </summary>
        public SoftEtherWelcomeInfo ParseWelcome(Pack reply)
        {
            if (reply is null) throw new ArgumentNullException(nameof(reply));

            uint error = reply.GetInt(SoftEtherProtocol.ErrorName);
            if (error != 0)
                throw new SoftEtherProtocolException($"SoftEther login was rejected (error {error}).", error);

            byte[]? sessionKey = reply.GetData(SoftEtherProtocol.SessionKeyName);
            if (sessionKey is null)
                throw new SoftEtherProtocolException("SoftEther login reply has no error but is missing the session key.");

            return new SoftEtherWelcomeInfo
            {
                SessionKey = sessionKey,
                SessionKey32 = reply.GetData(SoftEtherProtocol.SessionKey32Name) ?? Array.Empty<byte>(),
            };
        }

        byte[] NewUniqueId()
        {
            var id = new byte[SoftEtherSessionParams.UniqueIdLength];
            _random.NextBytes(id);
            return id;
        }

        // ---- I/O driver ------------------------------------------------------------------------------

        /// <summary>
        /// Runs the full handshake over <paramref name="transport"/> (already connected + TLS-established): writes the
        /// watermark POST, reads the server hello, writes the login PACK, reads the welcome PACK. Returns the
        /// <see cref="SoftEtherWelcomeInfo"/> on success; throws <see cref="SoftEtherProtocolException"/> on rejection.
        /// </summary>
        public async ValueTask<SoftEtherWelcomeInfo> RunAsync(
            IByteStreamTransport transport,
            string host,
            SoftEtherLoginRequest request,
            SoftEtherWatermark? watermark = null,
            CancellationToken cancellationToken = default)
        {
            if (transport is null) throw new ArgumentNullException(nameof(transport));
            if (request is null) throw new ArgumentNullException(nameof(request));

            watermark ??= new SoftEtherWatermark();

            // 1) Watermark POST — server replies with the hello PACK.
            await transport.WriteAsync(watermark.BuildRequest(host), cancellationToken).ConfigureAwait(false);
            Pack helloPack = await ReadHttpPackAsync(transport, cancellationToken).ConfigureAwait(false);
            SoftEtherHelloInfo hello = ParseHello(helloPack);

            // 2) Login POST — server replies with the welcome (or an error) PACK.
            Pack loginPack = BuildLoginPack(request, hello.Random);
            await transport.WriteAsync(SoftEtherHttpPackCodec.BuildPostRequest(host, loginPack), cancellationToken)
                .ConfigureAwait(false);
            Pack welcomePack = await ReadHttpPackAsync(transport, cancellationToken).ConfigureAwait(false);
            return ParseWelcome(welcomePack);
        }

        /// <summary>
        /// Reads exactly one HTTP message off <paramref name="transport"/> and returns the PACK in its framed body.
        /// Parses headers up to the blank line, honours <c>Content-Length</c>, then decodes the length-prefixed PACK.
        /// </summary>
        public static async ValueTask<Pack> ReadHttpPackAsync(IByteStreamTransport transport, CancellationToken cancellationToken)
        {
            if (transport is null) throw new ArgumentNullException(nameof(transport));

            var reader = new HttpMessageReader(transport);
            byte[] body = await reader.ReadMessageBodyAsync(cancellationToken).ConfigureAwait(false);
            return SoftEtherHttpPackCodec.ParseBody(body);
        }

        /// <summary>
        /// Minimal HTTP/1.1 message reader over an <see cref="IByteStreamTransport"/>: reads headers until the
        /// <c>\r\n\r\n</c> separator, parses <c>Content-Length</c>, then reads exactly that many body bytes. Buffers
        /// any bytes already read past the header boundary so the body is reassembled correctly. Sufficient for the
        /// SoftEther control exchange, which always uses an explicit <c>Content-Length</c>.
        /// </summary>
        sealed class HttpMessageReader
        {
            const int HeaderCap = 16 * 1024;
            readonly IByteStreamTransport _transport;

            public HttpMessageReader(IByteStreamTransport transport) => _transport = transport;

            public async ValueTask<byte[]> ReadMessageBodyAsync(CancellationToken cancellationToken)
            {
                var buffer = new List<byte>(512);
                var chunk = new byte[2048];
                int headerEnd = -1;

                while (headerEnd < 0)
                {
                    int read = await _transport.ReadAsync(chunk, cancellationToken).ConfigureAwait(false);
                    if (read == 0)
                        throw new SoftEtherProtocolException("Connection closed before the HTTP header was complete.");
                    for (int i = 0; i < read; i++) buffer.Add(chunk[i]);
                    headerEnd = FindHeaderEnd(buffer);
                    if (buffer.Count > HeaderCap)
                        throw new SoftEtherProtocolException("HTTP header exceeded the size cap.");
                }

                string header = Encoding.ASCII.GetString(buffer.ToArray(), 0, headerEnd);
                int contentLength = ParseContentLength(header);

                int bodyStart = headerEnd + 4; // skip the "\r\n\r\n" separator
                var body = new byte[contentLength];
                int have = Math.Min(contentLength, buffer.Count - bodyStart);
                for (int i = 0; i < have; i++) body[i] = buffer[bodyStart + i];

                int filled = have;
                while (filled < contentLength)
                {
                    int read = await _transport.ReadAsync(
                        new Memory<byte>(body, filled, contentLength - filled), cancellationToken).ConfigureAwait(false);
                    if (read == 0)
                        throw new SoftEtherProtocolException("Connection closed before the HTTP body was complete.");
                    filled += read;
                }
                return body;
            }

            static int FindHeaderEnd(List<byte> buffer)
            {
                for (int i = 0; i + 3 < buffer.Count; i++)
                {
                    if (buffer[i] == (byte)'\r' && buffer[i + 1] == (byte)'\n' &&
                        buffer[i + 2] == (byte)'\r' && buffer[i + 3] == (byte)'\n')
                        return i;
                }
                return -1;
            }

            static int ParseContentLength(string header)
            {
                foreach (string line in header.Split(new[] { "\r\n" }, StringSplitOptions.None))
                {
                    int colon = line.IndexOf(':');
                    if (colon < 0) continue;
                    string name = line.Substring(0, colon).Trim();
                    if (!name.Equals("Content-Length", StringComparison.OrdinalIgnoreCase)) continue;
                    string value = line.Substring(colon + 1).Trim();
                    if (int.TryParse(value, NumberStyles.None, CultureInfo.InvariantCulture, out int length) && length >= 0)
                        return length;
                    throw new SoftEtherProtocolException($"Malformed Content-Length header: '{value}'.");
                }
                throw new SoftEtherProtocolException("HTTP response has no Content-Length header.");
            }
        }
    }
}
