// The control client runs HTTP/2 (h2c) over the Noise channel via SocketsHttpHandler.ConnectCallback +
// HttpVersionPolicy — all net5.0+ APIs (and h2c is impossible on netstandard2.0's HttpClient anyway). The codecs,
// handshake, frame layer and netmap mapping below this gate stay cross-TFM; only the orchestrator is net5+.
#if NET5_0_OR_GREATER
using System.Buffers.Binary;
using System.Net;
using System.Net.Http;
using System.Text;
using System.Text.Json;
using TqkLibrary.VpnClient.Crypto.Noise;
using TqkLibrary.VpnClient.Tailscale.Control.Messages;
using TqkLibrary.VpnClient.Tailscale.Control.Noise;
using TqkLibrary.VpnClient.Tailscale.Keys;

namespace TqkLibrary.VpnClient.Tailscale.Control
{
    /// <summary>
    /// The Tailscale ts2021 control-plane client. It logs a node into a coordination server (Headscale/Tailscale) and
    /// fetches the netmap, in three steps:
    /// <list type="number">
    /// <item><c>GET /key?v=&lt;capver&gt;</c> over plain HTTP(S) → the control server's machine public key.</item>
    /// <item><see cref="Ts2021Connector"/> opens the Noise IK control channel; an <see cref="HttpClient"/> then runs
    /// HTTP/2 (h2c, prior knowledge) inside it.</item>
    /// <item><c>POST /machine/register</c> (preauth key) authorizes the node, then <c>POST /machine/map</c> returns the
    /// netmap (<see cref="MapResponse"/>).</item>
    /// </list>
    /// The cryptographic identity is the 32-byte machine key (Noise static) and the 32-byte node key (the WireGuard
    /// key) — both X25519, generated and held by the caller. The data plane is not this client's concern: the netmap is
    /// projected onto a WireGuard config elsewhere.
    /// </summary>
    public sealed class TailscaleControlClient : IDisposable
    {
        // Enables HTTP/2 over a cleartext (non-TLS) custom stream — the Noise channel is already encrypted, but Go's
        // HttpClient does not know that, so it must be told to speak h2c. Set once, process-wide (idempotent).
        static readonly bool _h2cEnabled = EnableUnencryptedHttp2();

        static readonly JsonSerializerOptions JsonOptions = new JsonSerializerOptions
        {
            DefaultIgnoreCondition = System.Text.Json.Serialization.JsonIgnoreCondition.Never,
        };

        readonly Uri _serverUrl;
        readonly byte[] _machinePrivateKey;
        readonly byte[] _machinePublicKey;
        readonly byte[] _nodePrivateKey;
        readonly byte[] _nodePublicKey;
        readonly byte[]? _discoPublicKey;
        readonly string? _hostname;

        HttpClient? _http;
        Ts2021NoiseStream? _controlStream;

        /// <summary>
        /// Creates the control client. <paramref name="serverUrl"/> is the coordination server base URL (e.g.
        /// <c>http://headscale:8080</c>). <paramref name="machinePrivateKey"/> / <paramref name="nodePrivateKey"/> are
        /// the 32-byte X25519 machine and node private keys; <paramref name="discoPublicKey"/> is an optional disco
        /// public key advertised in the map request. <paramref name="hostname"/> is reported in <c>Hostinfo</c>.
        /// </summary>
        public TailscaleControlClient(Uri serverUrl, byte[] machinePrivateKey, byte[] nodePrivateKey,
            byte[]? discoPublicKey = null, string? hostname = null)
        {
            _serverUrl = serverUrl ?? throw new ArgumentNullException(nameof(serverUrl));
            if (machinePrivateKey is null || machinePrivateKey.Length != 32) throw new ArgumentException("Machine private key must be 32 bytes.", nameof(machinePrivateKey));
            if (nodePrivateKey is null || nodePrivateKey.Length != 32) throw new ArgumentException("Node private key must be 32 bytes.", nameof(nodePrivateKey));
            _machinePrivateKey = (byte[])machinePrivateKey.Clone();
            _nodePrivateKey = (byte[])nodePrivateKey.Clone();
            var dh = new Curve25519DhGroup();
            _machinePublicKey = dh.DerivePublicValue(_machinePrivateKey);
            _nodePublicKey = dh.DerivePublicValue(_nodePrivateKey);
            _discoPublicKey = discoPublicKey is null ? null : (byte[])discoPublicKey.Clone();
            _hostname = hostname;
        }

        /// <summary>This node's public key (<c>nodekey:&lt;hex&gt;</c>) — also the WireGuard public key.</summary>
        public byte[] NodePublicKey => (byte[])_nodePublicKey.Clone();

        /// <summary>
        /// Logs in with a preauth key and returns the first full netmap. Establishes the Noise control channel, fetches
        /// the control key, registers the node and runs one (non-streaming) map request. Throws
        /// <see cref="TailscaleControlException"/> on a rejected key or an unauthorised node.
        /// </summary>
        public async Task<MapResponse> LoginAsync(string preauthKey, CancellationToken cancellationToken = default)
        {
            if (string.IsNullOrEmpty(preauthKey)) throw new ArgumentException("A preauth key is required.", nameof(preauthKey));
            _ = _h2cEnabled; // force the static initializer

            byte[] controlKey = await FetchControlKeyAsync(cancellationToken).ConfigureAwait(false);
            await OpenControlChannelAsync(controlKey, cancellationToken).ConfigureAwait(false);

            RegisterResponse register = await RegisterAsync(preauthKey, cancellationToken).ConfigureAwait(false);
            if (!string.IsNullOrEmpty(register.Error))
                throw new TailscaleControlException("Registration rejected: " + register.Error);
            if (!register.MachineAuthorized)
            {
                string detail = string.IsNullOrEmpty(register.AuthURL) ? "node not authorized" : "interactive login required: " + register.AuthURL;
                throw new TailscaleControlException("Registration not authorized (" + detail + ").");
            }

            return await GetNetMapAsync(cancellationToken).ConfigureAwait(false);
        }

        // ---- step 1: GET /key ----

        async Task<byte[]> FetchControlKeyAsync(CancellationToken cancellationToken)
        {
            var keyUrl = new Uri(_serverUrl, $"/key?v={TailscaleCapability.CapabilityVersion}");
            using var http = new HttpClient();
            string json = await http.GetStringAsync(keyUrl).ConfigureAwait(false);
            OverTlsPublicKeyResponse? resp = JsonSerializer.Deserialize<OverTlsPublicKeyResponse>(json, JsonOptions);
            string? mkey = resp?.PublicKey;
            if (string.IsNullOrEmpty(mkey))
                throw new TailscaleControlException("Control server /key returned no publicKey (advertised capver may be too low).");
            return TailscaleKey.DecodeMachinePublic(mkey!);
        }

        // ---- step 2: open the Noise channel + an HttpClient over it ----

        async Task OpenControlChannelAsync(byte[] controlKey, CancellationToken cancellationToken)
        {
            bool useTls = string.Equals(_serverUrl.Scheme, "https", StringComparison.OrdinalIgnoreCase);
            int port = _serverUrl.Port > 0 ? _serverUrl.Port : (useTls ? 443 : 80);
            var connector = new Ts2021Connector(_machinePrivateKey, controlKey, TailscaleCapability.ControlProtocolVersion);
            Ts2021NoiseStream controlStream = await connector.ConnectAsync(_serverUrl.Host, port, useTls, cancellationToken).ConfigureAwait(false);
            _controlStream = controlStream;

            var handler = new SocketsHttpHandler
            {
                // Hand HttpClient the already-encrypted Noise stream; it runs h2c (prior knowledge) inside it.
                ConnectCallback = (_, _) => new ValueTask<Stream>(controlStream),
                PooledConnectionLifetime = Timeout.InfiniteTimeSpan,
            };
            _http = new HttpClient(handler)
            {
                // The control channel has no real wall-clock timeout (map long-poll); callers pass a CancellationToken.
                Timeout = Timeout.InfiniteTimeSpan,
                DefaultRequestVersion = HttpVersion.Version20,
                DefaultVersionPolicy = HttpVersionPolicy.RequestVersionExact,
            };
            // The authority is carried for HTTP/2 :authority; the scheme inside the Noise channel is http.
            _http.BaseAddress = new UriBuilder("http", _serverUrl.Host, port).Uri;
        }

        // ---- step 3a: POST /machine/register ----

        async Task<RegisterResponse> RegisterAsync(string preauthKey, CancellationToken cancellationToken)
        {
            var request = new RegisterRequest
            {
                Version = TailscaleCapability.CapabilityVersion,
                NodeKey = TailscaleKey.EncodeNodePublic(_nodePublicKey),
                Auth = new RegisterResponseAuth { AuthKey = preauthKey },
                Hostinfo = BuildHostinfo(),
            };
            byte[] body = JsonSerializer.SerializeToUtf8Bytes(request, JsonOptions);
            byte[] respBytes = await PostAsync("/machine/register", body, stream: false, cancellationToken).ConfigureAwait(false);
            RegisterResponse? resp = JsonSerializer.Deserialize<RegisterResponse>(respBytes, JsonOptions);
            return resp ?? throw new TailscaleControlException("Empty register response.");
        }

        // ---- step 3b: POST /machine/map (single, non-streaming) ----

        async Task<MapResponse> GetNetMapAsync(CancellationToken cancellationToken)
        {
            var request = new MapRequest
            {
                Version = TailscaleCapability.CapabilityVersion,
                NodeKey = TailscaleKey.EncodeNodePublic(_nodePublicKey),
                DiscoKey = _discoPublicKey is null ? null : TailscaleKey.EncodeDiscoPublic(_discoPublicKey),
                Stream = false,        // one full netmap, not a long-poll (lab brings the tunnel up once)
                Compress = string.Empty, // plain JSON
                Hostinfo = BuildHostinfo(),
                ReadOnly = false,
            };
            byte[] body = JsonSerializer.SerializeToUtf8Bytes(request, JsonOptions);
            byte[] respBytes = await PostAsync("/machine/map", body, stream: false, cancellationToken).ConfigureAwait(false);
            byte[] json = StripMapLengthPrefix(respBytes);
            MapResponse? resp = JsonSerializer.Deserialize<MapResponse>(json, JsonOptions);
            return resp ?? throw new TailscaleControlException("Empty map response.");
        }

        // The /machine/map body is framed as [4-byte little-endian length][JSON] (reservedResponseHeaderSize). Strip it.
        static byte[] StripMapLengthPrefix(byte[] body)
        {
            if (body.Length < 4) throw new TailscaleControlException("Map response too short for its length prefix.");
            int length = (int)BinaryPrimitives.ReadUInt32LittleEndian(body.AsSpan(0, 4));
            if (4 + length > body.Length) length = body.Length - 4; // be lenient if the server omitted/short-counted
            return body.AsSpan(4, length).ToArray();
        }

        async Task<byte[]> PostAsync(string path, byte[] body, bool stream, CancellationToken cancellationToken)
        {
            HttpClient http = _http ?? throw new InvalidOperationException("Control channel is not open.");
            using var content = new ByteArrayContent(body);
            content.Headers.ContentType = new System.Net.Http.Headers.MediaTypeHeaderValue("application/json");
            using var request = new HttpRequestMessage(HttpMethod.Post, path) { Content = content };
            request.Version = HttpVersion.Version20;
            request.VersionPolicy = HttpVersionPolicy.RequestVersionExact;

            HttpResponseMessage response = await http.SendAsync(request,
                stream ? HttpCompletionOption.ResponseHeadersRead : HttpCompletionOption.ResponseContentRead,
                cancellationToken).ConfigureAwait(false);
            if (response.StatusCode != HttpStatusCode.OK)
            {
                string text = await response.Content.ReadAsStringAsync().ConfigureAwait(false);
                response.Dispose();
                throw new TailscaleControlException($"{path} returned HTTP {(int)response.StatusCode}: {Truncate(text)}");
            }
            byte[] data = await response.Content.ReadAsByteArrayAsync().ConfigureAwait(false);
            response.Dispose();
            return data;
        }

        Hostinfo BuildHostinfo() => new Hostinfo
        {
            Hostname = _hostname ?? "tqk-vpnclient",
            OS = "linux",
            IPNVersion = "1.0.0-tqk",
        };

        static string Truncate(string s) => s is null ? "" : (s.Length <= 200 ? s : s.Substring(0, 200) + "...");

        static bool EnableUnencryptedHttp2()
        {
            AppContext.SetSwitch("System.Net.Http.SocketsHttpHandler.Http2UnencryptedSupport", true);
            return true;
        }

        /// <inheritdoc/>
        public void Dispose()
        {
            _http?.Dispose();
            _controlStream?.Dispose();
            _http = null;
            _controlStream = null;
        }
    }
}
#endif
