using System;
using System.Collections.Generic;
using System.Globalization;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using TqkLibrary.VpnClient.Abstractions.Transport.Interfaces;
using TqkLibrary.VpnClient.OpenConnect;
using TqkLibrary.VpnClient.OpenConnect.Enums;
using TqkLibrary.VpnClient.OpenConnect.Models;
using Xunit;

namespace TqkLibrary.VpnClient.Drivers.OpenConnect.Tests
{
    /// <summary>
    /// A throwaway in-process ocserv-style responder for the offline driver tests. It serves the OpenConnect HTTPS
    /// auth handshake (init → a single username/password form → success carrying the <c>webvpn</c> cookie), answers the
    /// HTTP <c>CONNECT /CSCOSSLC/tunnel</c> with a set of <c>X-CSTP-*</c> tunnel headers, then switches the same byte
    /// stream to CSTP framing: it echoes inbound DATA packets, answers a DPD-REQUEST with a DPD-RESPONSE, and can send
    /// an unsolicited DPD-REQUEST / DATA packet to the client on demand. Re-implemented from the published CSTP/ocserv
    /// behaviour — not copied from the GPL source.
    /// </summary>
    sealed class SimulatedOpenConnectServer
    {
        readonly IByteStreamTransport _stream;
        readonly string? _expectedUser;
        readonly string? _expectedPassword;
        readonly int _dpdSeconds;
        readonly int _keepaliveSeconds;
        readonly string _address;
        readonly int _dtlsPort;
        readonly CstpFraming _framing = new();
        readonly object _writeLock = new();

        /// <summary>Count of inbound DATA packets the server received (test assertion hook).</summary>
        public int DataPacketsReceived { get; private set; }

        /// <summary>Count of DPD-RESPONSE packets the server received in answer to its probes (test assertion hook).</summary>
        public int DpdResponsesReceived { get; private set; }

        /// <summary>Count of DPD-REQUEST packets the server received from the client (its idle probe; test assertion hook).</summary>
        public int DpdRequestsReceived { get; private set; }

        /// <summary>Set once the CSTP tunnel is up (auth + CONNECT done); the test waits on this before sending stimulus.</summary>
        public TaskCompletionSource<bool> TunnelUp { get; } = new(TaskCreationOptions.RunContinuationsAsynchronously);

        public SimulatedOpenConnectServer(IByteStreamTransport stream,
            string? expectedUser = null, string? expectedPassword = null,
            int dpdSeconds = 30, int keepaliveSeconds = 20, string address = "10.10.0.5",
            int dtlsPort = 0)
        {
            _stream = stream;
            _expectedUser = expectedUser;
            _expectedPassword = expectedPassword;
            _dpdSeconds = dpdSeconds;
            _keepaliveSeconds = keepaliveSeconds;
            _address = address;
            _dtlsPort = dtlsPort; // 0 = do not advertise the DTLS data path (client stays on CSTP-over-TLS)
        }

        /// <summary>Runs the responder until the stream closes or cancellation.</summary>
        public async Task RunAsync(CancellationToken cancellationToken)
        {
            try
            {
                await ServeHttpAsync(cancellationToken).ConfigureAwait(false);
                await ServeCstpAsync(cancellationToken).ConfigureAwait(false);
            }
            catch (OperationCanceledException) { }
            catch (System.IO.IOException) { /* stream closed by the client teardown — normal */ }
        }

        // ---- HTTP phase: auth POSTs then CONNECT ----

        async Task ServeHttpAsync(CancellationToken cancellationToken)
        {
            bool authed = false;
            while (true)
            {
                HttpRequest req = await ReadRequestAsync(cancellationToken).ConfigureAwait(false);
                if (req.Method == "POST")
                {
                    string response = HandleAuthPost(req.Body, ref authed);
                    await WriteAsciiAsync(response, cancellationToken).ConfigureAwait(false);
                }
                else if (req.Method == "CONNECT")
                {
                    await WriteAsciiAsync(BuildConnectResponse(), cancellationToken).ConfigureAwait(false);
                    TunnelUp.TrySetResult(true);
                    return; // the stream is now a CSTP tunnel
                }
                else
                {
                    await WriteAsciiAsync("HTTP/1.1 405 Method Not Allowed\r\nContent-Length: 0\r\n\r\n", cancellationToken).ConfigureAwait(false);
                }
            }
        }

        string HandleAuthPost(string body, ref bool authed)
        {
            // init / first POST ⇒ serve a username+password form. A reply with the right credentials ⇒ success + cookie.
            bool isReply = body.IndexOf("type=\"auth-reply\"", StringComparison.OrdinalIgnoreCase) >= 0;
            if (!isReply)
                return HttpBody(200, "OK", AuthFormXml(), setCookie: null);

            // It is a reply — validate the submitted username/password from the XML.
            string? user = ExtractElement(body, "username");
            string? pass = ExtractElement(body, "password");
            bool ok = (_expectedUser == null || string.Equals(user, _expectedUser, StringComparison.Ordinal))
                   && (_expectedPassword == null || string.Equals(pass, _expectedPassword, StringComparison.Ordinal));
            if (!ok)
                return HttpBody(200, "OK", "<auth id=\"failure\"><message>bad credentials</message></auth>", setCookie: null);

            authed = true;
            return HttpBody(200, "OK", "<auth id=\"success\"><message>welcome</message></auth>",
                setCookie: "webvpn=TESTCOOKIE123; Secure; HttpOnly");
        }

        static string AuthFormXml() =>
            "<auth id=\"main\"><message>Please authenticate</message><form method=\"post\" action=\"/auth\">"
            + "<input type=\"text\" name=\"username\" label=\"Username:\"/>"
            + "<input type=\"password\" name=\"password\" label=\"Password:\"/>"
            + "</form></auth>";

        string BuildConnectResponse()
        {
            var sb = new StringBuilder();
            sb.Append("HTTP/1.1 200 CONNECTED\r\n");
            sb.Append("X-CSTP-Version: 1\r\n");
            sb.Append("X-CSTP-Address: ").Append(_address).Append("\r\n");
            sb.Append("X-CSTP-Netmask: 255.255.255.0\r\n");
            sb.Append("X-CSTP-DNS: 10.10.0.1\r\n");
            sb.Append("X-CSTP-Split-Include: 10.10.0.0/16\r\n");
            sb.Append("X-CSTP-MTU: 1400\r\n");
            sb.Append("X-CSTP-DPD: ").Append(_dpdSeconds.ToString(CultureInfo.InvariantCulture)).Append("\r\n");
            sb.Append("X-CSTP-Keepalive: ").Append(_keepaliveSeconds.ToString(CultureInfo.InvariantCulture)).Append("\r\n");
            sb.Append("X-CSTP-Rekey-Method: ssl\r\n");
            if (_dtlsPort > 0)
            {
                // Advertise the parallel DTLS data path. The session id is the cookie tying the UDP/DTLS session to CSTP.
                sb.Append("X-DTLS-Session-ID: 0123456789abcdef0123456789abcdef\r\n");
                sb.Append("X-DTLS-CipherSuite: AES256-GCM-SHA384\r\n");
                sb.Append("X-DTLS-Port: ").Append(_dtlsPort.ToString(CultureInfo.InvariantCulture)).Append("\r\n");
                sb.Append("X-DTLS-DPD: ").Append(_dpdSeconds.ToString(CultureInfo.InvariantCulture)).Append("\r\n");
                sb.Append("X-DTLS-Keepalive: ").Append(_keepaliveSeconds.ToString(CultureInfo.InvariantCulture)).Append("\r\n");
            }
            sb.Append("\r\n");
            return sb.ToString();
        }

        // ---- CSTP phase ----

        async Task ServeCstpAsync(CancellationToken cancellationToken)
        {
            byte[] buffer = new byte[4096];
            while (!cancellationToken.IsCancellationRequested)
            {
                int read = await _stream.ReadAsync(buffer, cancellationToken).ConfigureAwait(false);
                if (read <= 0) return;
                _framing.Append(buffer.AsSpan(0, read));
                while (_framing.TryReadPacket(out CstpPacket packet))
                {
                    switch (packet.Type)
                    {
                        case CstpPacketType.Data:
                            DataPacketsReceived++;
                            await SendFrameAsync(CstpPacketType.Data, packet.Payload, cancellationToken).ConfigureAwait(false); // echo
                            break;
                        case CstpPacketType.DpdRequest:
                            DpdRequestsReceived++;
                            await SendFrameAsync(CstpPacketType.DpdResponse, Array.Empty<byte>(), cancellationToken).ConfigureAwait(false);
                            break;
                        case CstpPacketType.DpdResponse:
                            DpdResponsesReceived++;
                            break;
                        case CstpPacketType.KeepAlive:
                            break;
                    }
                }
            }
        }

        /// <summary>Test stimulus: the server sends an unsolicited DATA packet to the client.</summary>
        public async Task SendDataAsync(byte[] inner, CancellationToken cancellationToken)
            => await SendFrameAsync(CstpPacketType.Data, inner, cancellationToken).ConfigureAwait(false);

        /// <summary>Test stimulus: the server sends a DPD-REQUEST to the client (expects a DPD-RESPONSE back).</summary>
        public async Task SendDpdRequestAsync(CancellationToken cancellationToken)
            => await SendFrameAsync(CstpPacketType.DpdRequest, Array.Empty<byte>(), cancellationToken).ConfigureAwait(false);

        /// <summary>Test stimulus: the server tears the session down with a CSTP DISCONNECT.</summary>
        public async Task SendDisconnectAsync(CancellationToken cancellationToken)
            => await SendFrameAsync(CstpPacketType.Disconnect, Array.Empty<byte>(), cancellationToken).ConfigureAwait(false);

        ValueTask SendFrameAsync(CstpPacketType type, ReadOnlyMemory<byte> payload, CancellationToken cancellationToken)
        {
            byte[] framed = CstpFraming.Encode(type, payload.Span);
            return _stream.WriteAsync(framed, cancellationToken);
        }

        async Task WriteAsciiAsync(string text, CancellationToken cancellationToken)
            => await _stream.WriteAsync(Encoding.ASCII.GetBytes(text), cancellationToken).ConfigureAwait(false);

        // ---- minimal HTTP request reader (byte-exact, never over-reads into the next request/tunnel) ----

        sealed class HttpRequest
        {
            public string Method = string.Empty;
            public string Body = string.Empty;
        }

        async Task<HttpRequest> ReadRequestAsync(CancellationToken cancellationToken)
        {
            string headerText = await ReadHeaderBlockAsync(cancellationToken).ConfigureAwait(false);
            string[] lines = headerText.Split(new[] { "\r\n" }, StringSplitOptions.None);
            string requestLine = lines.Length > 0 ? lines[0] : string.Empty;
            string method = requestLine.Split(' ')[0];

            int contentLength = 0;
            foreach (string line in lines)
            {
                int colon = line.IndexOf(':');
                if (colon <= 0) continue;
                if (string.Equals(line.Substring(0, colon).Trim(), "Content-Length", StringComparison.OrdinalIgnoreCase))
                    int.TryParse(line.Substring(colon + 1).Trim(), out contentLength);
            }

            string body = string.Empty;
            if (contentLength > 0)
            {
                byte[] bodyBytes = await ReadExactAsync(contentLength, cancellationToken).ConfigureAwait(false);
                body = Encoding.UTF8.GetString(bodyBytes);
            }
            return new HttpRequest { Method = method, Body = body };
        }

        async Task<string> ReadHeaderBlockAsync(CancellationToken cancellationToken)
        {
            var buffer = new List<byte>(256);
            byte[] one = new byte[1];
            while (true)
            {
                int read = await _stream.ReadAsync(one, cancellationToken).ConfigureAwait(false);
                if (read <= 0) throw new System.IO.IOException("client closed before request headers completed");
                buffer.Add(one[0]);
                int n = buffer.Count;
                if (n >= 4 && buffer[n - 4] == (byte)'\r' && buffer[n - 3] == (byte)'\n'
                           && buffer[n - 2] == (byte)'\r' && buffer[n - 1] == (byte)'\n')
                    return Encoding.ASCII.GetString(buffer.ToArray(), 0, n - 4);
            }
        }

        async Task<byte[]> ReadExactAsync(int count, CancellationToken cancellationToken)
        {
            byte[] buffer = new byte[count];
            int offset = 0;
            while (offset < count)
            {
                int read = await _stream.ReadAsync(buffer.AsMemory(offset, count - offset), cancellationToken).ConfigureAwait(false);
                if (read <= 0) throw new System.IO.IOException("client closed mid-body");
                offset += read;
            }
            return buffer;
        }

        // ---- tiny helpers ----

        static string HttpBody(int status, string reason, string body, string? setCookie)
        {
            byte[] bodyBytes = Encoding.UTF8.GetBytes(body);
            var sb = new StringBuilder();
            sb.Append("HTTP/1.1 ").Append(status).Append(' ').Append(reason).Append("\r\n");
            sb.Append("Content-Type: text/xml\r\n");
            if (setCookie != null) sb.Append("Set-Cookie: ").Append(setCookie).Append("\r\n");
            sb.Append("Content-Length: ").Append(bodyBytes.Length.ToString(CultureInfo.InvariantCulture)).Append("\r\n");
            sb.Append("\r\n");
            sb.Append(body);
            return sb.ToString();
        }

        static string? ExtractElement(string xml, string name)
        {
            string open = "<" + name + ">";
            string close = "</" + name + ">";
            int start = xml.IndexOf(open, StringComparison.OrdinalIgnoreCase);
            if (start < 0) return null;
            start += open.Length;
            int end = xml.IndexOf(close, start, StringComparison.OrdinalIgnoreCase);
            return end < 0 ? null : xml.Substring(start, end - start);
        }
    }
}
