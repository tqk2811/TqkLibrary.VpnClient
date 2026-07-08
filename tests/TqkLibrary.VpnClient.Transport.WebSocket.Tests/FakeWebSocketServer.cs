using System;
using System.Collections.Generic;
using System.IO;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using TqkLibrary.VpnClient.Abstractions.Transport.Interfaces;
using TqkLibrary.VpnClient.Transport.WebSocket;

namespace TqkLibrary.VpnClient.Transport.WebSocket.Tests
{
    /// <summary>
    /// A minimal in-test RFC 6455 <b>server</b> over one end of an in-memory byte-stream pipe: reads the client's HTTP
    /// Upgrade request, replies <c>101</c> with the correct <c>Sec-WebSocket-Accept</c> (or a non-101 status to exercise
    /// the failure path), then sends unmasked frames and receives+un-masks the client's masked frames. Pure test
    /// scaffolding — no product server code.
    /// </summary>
    sealed class FakeWebSocketServer
    {
        readonly IByteStreamTransport _server;
        readonly Rfc6455FrameReassembler _reassembler = new();
        readonly byte[] _readBuffer = new byte[8192];

        public FakeWebSocketServer(IByteStreamTransport server) { _server = server; }

        /// <summary>The <c>Sec-WebSocket-Key</c> the client sent (captured during <see cref="AcceptAsync"/>).</summary>
        public string? ReceivedKey { get; private set; }

        public async Task AcceptAsync(CancellationToken ct, bool respond101 = true)
        {
            var buffer = new List<byte>();
            int end;
            while ((end = IndexOfTerminator(buffer)) < 0)
            {
                int n = await _server.ReadAsync(_readBuffer, ct);
                if (n == 0) throw new IOException("client closed before completing the handshake request");
                for (int i = 0; i < n; i++) buffer.Add(_readBuffer[i]);
            }

            int headerLength = end + 4;
            string headers = Encoding.ASCII.GetString(buffer.GetRange(0, end).ToArray());
            // Anything after CRLFCRLF is already framed data the client pipelined.
            if (buffer.Count > headerLength)
                _reassembler.Append(buffer.GetRange(headerLength, buffer.Count - headerLength).ToArray());

            foreach (string line in headers.Split(new[] { "\r\n" }, StringSplitOptions.None))
            {
                int colon = line.IndexOf(':');
                if (colon > 0 && line.Substring(0, colon).Trim().Equals("Sec-WebSocket-Key", StringComparison.OrdinalIgnoreCase))
                    ReceivedKey = line.Substring(colon + 1).Trim();
            }

            string response;
            if (respond101)
            {
                string accept = WebSocketHandshake.ComputeAccept(ReceivedKey!);
                response = "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n" +
                           "Sec-WebSocket-Accept: " + accept + "\r\n\r\n";
            }
            else
            {
                response = "HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n";
            }
            await _server.WriteAsync(Encoding.ASCII.GetBytes(response), ct);
        }

        public async Task<(bool fin, Rfc6455Opcode opcode, byte[] payload)> ReceiveFrameAsync(CancellationToken ct)
        {
            bool fin;
            Rfc6455Opcode opcode;
            byte[] payload;
            while (!_reassembler.TryReadFrame(out fin, out opcode, out payload))
            {
                int n = await _server.ReadAsync(_readBuffer, ct);
                if (n == 0) throw new IOException("client closed the stream");
                _reassembler.Append(_readBuffer.AsSpan(0, n));
            }
            return (fin, opcode, payload);
        }

        /// <summary>Reassembles the next binary message (data + continuation frames), skipping any control frames.</summary>
        public async Task<byte[]> ReceiveBinaryMessageAsync(CancellationToken ct)
        {
            var message = new List<byte>();
            while (true)
            {
                var (fin, opcode, payload) = await ReceiveFrameAsync(ct);
                if (opcode == Rfc6455Opcode.Binary || opcode == Rfc6455Opcode.Continuation)
                {
                    message.AddRange(payload);
                    if (fin) return message.ToArray();
                }
                // control frames (ping/pong/close) are ignored for message reassembly
            }
        }

        public Task SendBinaryAsync(byte[] payload, CancellationToken ct)
            => _server.WriteAsync(Rfc6455Frame.EncodeServerFrame(Rfc6455Opcode.Binary, payload), ct).AsTask();

        public async Task SendFragmentedBinaryAsync(byte[][] parts, CancellationToken ct)
        {
            for (int i = 0; i < parts.Length; i++)
            {
                Rfc6455Opcode opcode = i == 0 ? Rfc6455Opcode.Binary : Rfc6455Opcode.Continuation;
                bool fin = i == parts.Length - 1;
                await _server.WriteAsync(Rfc6455Frame.EncodeServerFrame(opcode, parts[i], fin), ct);
            }
        }

        public Task SendPingAsync(byte[] payload, CancellationToken ct)
            => _server.WriteAsync(Rfc6455Frame.EncodeServerFrame(Rfc6455Opcode.Ping, payload), ct).AsTask();

        public Task SendCloseAsync(CancellationToken ct)
            => _server.WriteAsync(Rfc6455Frame.EncodeServerFrame(Rfc6455Opcode.Close, Array.Empty<byte>()), ct).AsTask();

        static int IndexOfTerminator(List<byte> data)
        {
            for (int i = 0; i + 3 < data.Count; i++)
                if (data[i] == 0x0D && data[i + 1] == 0x0A && data[i + 2] == 0x0D && data[i + 3] == 0x0A)
                    return i;
            return -1;
        }
    }
}
