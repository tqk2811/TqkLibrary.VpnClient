using System.Net.Security;
using System.Net.Sockets;
using System.Text;
using TqkLibrary.VpnClient.Tailscale.Control.Noise;

namespace TqkLibrary.VpnClient.Tailscale.Control
{
    /// <summary>
    /// Establishes the ts2021 Noise control channel to a coordination server (Headscale/Tailscale). It performs the
    /// HTTP upgrade (control/controlhttp): <c>POST /ts2021</c> carrying the base64 Noise initiation in the
    /// <c>X-Tailscale-Handshake</c> header with <c>Upgrade: tailscale-control-protocol</c>, reads the
    /// <c>101 Switching Protocols</c> response, then runs the Noise IK handshake over the upgraded byte stream and
    /// returns an encrypted <see cref="Ts2021NoiseStream"/> ready for HTTP/2 (h2c) to run inside.
    /// <para>
    /// The control server's machine public key (the IK responder static) must be fetched separately from
    /// <c>GET /key?v=&lt;capver&gt;</c> and passed in; the connector is a pure transport + handshake step.
    /// </para>
    /// </summary>
    public sealed class Ts2021Connector
    {
        const string UpgradeHeaderValue = "tailscale-control-protocol";
        const string HandshakeHeaderName = "X-Tailscale-Handshake";
        const string UpgradePath = "/ts2021";

        readonly byte[] _machinePrivateKey;
        readonly byte[] _controlMachinePublicKey;
        readonly int _protocolVersion;

        /// <summary>
        /// Creates the connector. <paramref name="machinePrivateKey"/> is this client's 32-byte machine private key;
        /// <paramref name="controlMachinePublicKey"/> is the server's 32-byte machine public key (from <c>/key</c>);
        /// <paramref name="protocolVersion"/> is the ts2021 protocol version (Tailscale uses 1).
        /// </summary>
        public Ts2021Connector(byte[] machinePrivateKey, byte[] controlMachinePublicKey, int protocolVersion = 1)
        {
            _machinePrivateKey = machinePrivateKey ?? throw new ArgumentNullException(nameof(machinePrivateKey));
            _controlMachinePublicKey = controlMachinePublicKey ?? throw new ArgumentNullException(nameof(controlMachinePublicKey));
            _protocolVersion = protocolVersion;
        }

        /// <summary>
        /// Connects a TCP socket to <paramref name="host"/>:<paramref name="port"/> (wrapping it in TLS when
        /// <paramref name="useTls"/>, the <c>https</c> case), performs the <c>/ts2021</c> upgrade and the Noise IK
        /// handshake, and returns the encrypted control stream. The returned stream owns the socket. The optional
        /// early-noise payload is consumed and discarded.
        /// </summary>
        public async Task<Ts2021NoiseStream> ConnectAsync(string host, int port, bool useTls, CancellationToken cancellationToken = default)
        {
            var tcp = new TcpClient();
            Stream stream;
            try
            {
#if NET5_0_OR_GREATER
                await tcp.ConnectAsync(host, port, cancellationToken).ConfigureAwait(false);
#else
                await tcp.ConnectAsync(host, port).ConfigureAwait(false);
#endif
                tcp.NoDelay = true;
                stream = tcp.GetStream();
                if (useTls)
                {
                    var ssl = new SslStream(stream, leaveInnerStreamOpen: false, (s, c, ch, e) => true);
                    await ssl.AuthenticateAsClientAsync(host).ConfigureAwait(false);
                    stream = ssl;
                }
            }
            catch
            {
                tcp.Dispose();
                throw;
            }

            try
            {
                var handshake = new Ts2021NoiseHandshake(_machinePrivateKey, _controlMachinePublicKey, _protocolVersion);
                byte[] noiseInit = handshake.CreateInitiation(Array.Empty<byte>());
                byte[] initFrame = Ts2021FrameCodec.EncodeInitiation(_protocolVersion, noiseInit);

                await SendUpgradeRequestAsync(stream, host, port, initFrame, cancellationToken).ConfigureAwait(false);
                await ReadUpgradeResponseAsync(stream, cancellationToken).ConfigureAwait(false);

                byte[] responseFrame = await ReadResponseFrameAsync(stream, cancellationToken).ConfigureAwait(false);
                if (!handshake.ConsumeResponse(responseFrame, out _))
                    throw new IOException("ts2021 Noise response failed to authenticate (wrong control key or tampering).");

                (byte[] sendKey, byte[] receiveKey) = handshake.Split();
                var noiseStream = new Ts2021NoiseStream(stream,
                    new Ts2021Transport(sendKey), new Ts2021Transport(receiveKey));
                await noiseStream.SkipEarlyNoiseAsync(cancellationToken).ConfigureAwait(false);
                return noiseStream;
            }
            catch
            {
                stream.Dispose();
                tcp.Dispose();
                throw;
            }
        }

        // Send the HTTP/1.1 upgrade request: POST /ts2021 with the base64 initiation in X-Tailscale-Handshake.
        static async Task SendUpgradeRequestAsync(Stream stream, string host, int port, byte[] initFrame, CancellationToken cancellationToken)
        {
            string b64 = Convert.ToBase64String(initFrame);
            var sb = new StringBuilder();
            sb.Append("POST ").Append(UpgradePath).Append(" HTTP/1.1\r\n");
            sb.Append("Host: ").Append(host).Append(':').Append(port).Append("\r\n");
            sb.Append("Upgrade: ").Append(UpgradeHeaderValue).Append("\r\n");
            sb.Append("Connection: upgrade\r\n");
            sb.Append(HandshakeHeaderName).Append(": ").Append(b64).Append("\r\n");
            sb.Append("Content-Length: 0\r\n");
            sb.Append("\r\n");
            byte[] request = Encoding.ASCII.GetBytes(sb.ToString());
            await stream.WriteAsync(request, 0, request.Length, cancellationToken).ConfigureAwait(false);
            await stream.FlushAsync(cancellationToken).ConfigureAwait(false);
        }

        // Read the HTTP/1.1 status + headers up to the blank line, requiring 101 Switching Protocols.
        static async Task ReadUpgradeResponseAsync(Stream stream, CancellationToken cancellationToken)
        {
            string headers = await ReadHttpHeadersAsync(stream, cancellationToken).ConfigureAwait(false);
            int eol = headers.IndexOf("\r\n", StringComparison.Ordinal);
            string statusLine = eol < 0 ? headers : headers.Substring(0, eol);
            // Status line: "HTTP/1.1 101 Switching Protocols"
            string[] parts = statusLine.Split(new[] { ' ' }, 3);
            if (parts.Length < 2 || parts[1] != "101")
                throw new IOException("ts2021 upgrade rejected by the control server: " + statusLine);
        }

        // Read bytes until the CRLFCRLF header terminator; returns the header block as ASCII (no body follows a 101).
        static async Task<string> ReadHttpHeadersAsync(Stream stream, CancellationToken cancellationToken)
        {
            var buffer = new List<byte>(256);
            byte[] one = new byte[1];
            int matched = 0; // counts the CR LF CR LF terminator
            // Terminator = CR LF CR LF (0x0D 0x0A 0x0D 0x0A); a plain array (not stackalloc) so it survives the awaits.
            while (true)
            {
                int n = await stream.ReadAsync(one, 0, 1, cancellationToken).ConfigureAwait(false);
                if (n == 0) throw new EndOfStreamException("Control server closed the connection during the ts2021 upgrade.");
                buffer.Add(one[0]);
                byte expected = (matched & 1) == 0 ? (byte)0x0D : (byte)0x0A; // even index = CR, odd = LF
                matched = one[0] == expected ? matched + 1 : (one[0] == 0x0D ? 1 : 0);
                if (matched == 4) break;
                if (buffer.Count > 16 * 1024) throw new IOException("ts2021 upgrade response headers too large.");
            }
            return Encoding.ASCII.GetString(buffer.ToArray());
        }

        // Read one ts2021 response frame ([type=2][len:u16][noise message]) off the raw stream.
        static async Task<byte[]> ReadResponseFrameAsync(Stream stream, CancellationToken cancellationToken)
        {
            byte[] header = new byte[Ts2021FrameCodec.HeaderLength];
            await ReadExactAsync(stream, header, cancellationToken).ConfigureAwait(false);
            if (!Ts2021FrameCodec.TryDecodeHeader(header, out Ts2021FrameType type, out int length))
                throw new IOException("Malformed ts2021 response header.");
            byte[] body = new byte[length];
            await ReadExactAsync(stream, body, cancellationToken).ConfigureAwait(false);
            if (type == Ts2021FrameType.Error)
                throw new IOException("ts2021 handshake error: " + Encoding.ASCII.GetString(body));
            if (type != Ts2021FrameType.Response)
                throw new IOException($"Expected a ts2021 response frame, got type {(byte)type}.");
            return body;
        }

        static async Task ReadExactAsync(Stream stream, byte[] destination, CancellationToken cancellationToken)
        {
            int read = 0;
            while (read < destination.Length)
            {
                int n = await stream.ReadAsync(destination, read, destination.Length - read, cancellationToken).ConfigureAwait(false);
                if (n == 0) throw new EndOfStreamException("Truncated ts2021 handshake frame.");
                read += n;
            }
        }
    }
}
