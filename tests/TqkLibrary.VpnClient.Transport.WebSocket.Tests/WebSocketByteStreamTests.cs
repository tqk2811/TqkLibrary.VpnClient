using System;
using System.IO;
using System.Threading;
using System.Threading.Tasks;
using TqkLibrary.VpnClient.Transport.WebSocket;
using Xunit;

namespace TqkLibrary.VpnClient.Transport.WebSocket.Tests
{
    /// <summary>
    /// End-to-end tests for <see cref="WebSocketByteStream"/> over a lossless in-memory byte-stream pipe: the client's
    /// inner transport is one end of an <see cref="InMemoryByteStreamPair"/>, the other end drives a
    /// <see cref="FakeWebSocketServer"/>. They exercise the full RFC 6455 client path — §4 HTTP Upgrade handshake,
    /// §5.3 masked outbound binary frames, §5 inbound un-masking, §5.4 fragment reassembly, §5.5.2 auto-pong, and §5.5.1
    /// close ⇒ end-of-stream — plus the handshake failure path. A 5-second timeout guards every case against a hang.
    /// </summary>
    public class WebSocketByteStreamTests
    {
        static CancellationToken Timeout() => new CancellationTokenSource(TimeSpan.FromSeconds(5)).Token;

        static byte[] Pattern(int length, byte seed)
        {
            byte[] b = new byte[length];
            for (int i = 0; i < length; i++) b[i] = (byte)(seed + i * 7);
            return b;
        }

        // Runs the client handshake in parallel with the server accept, returning both once §4 completes.
        static async Task<(WebSocketByteStream client, FakeWebSocketServer server)> ConnectedPairAsync(CancellationToken ct)
        {
            var pair = new InMemoryByteStreamPair();
            var client = new WebSocketByteStream(pair.Client, "example.org", "/tunnel", subProtocol: null,
                random: new FakeWebSocketRandom());
            var server = new FakeWebSocketServer(pair.Server);

            Task accept = server.AcceptAsync(ct);
            Task connect = client.ConnectAsync(ct).AsTask();
            await Task.WhenAll(accept, connect);
            return (client, server);
        }

        // Reads exactly count bytes from the client, following the transport's arbitrary read boundaries.
        static async Task<byte[]> ReadExactAsync(WebSocketByteStream client, int count, CancellationToken ct)
        {
            byte[] buffer = new byte[count];
            int offset = 0;
            while (offset < count)
            {
                int n = await client.ReadAsync(buffer.AsMemory(offset), ct);
                if (n == 0) throw new IOException("client stream closed before the expected bytes arrived");
                offset += n;
            }
            return buffer;
        }

        [Fact]
        public async Task Handshake_Completes_AndServerReceivesClientKey()
        {
            CancellationToken ct = Timeout();
            var (client, server) = await ConnectedPairAsync(ct);

            // FakeWebSocketRandom is a deterministic counter, so the 16-byte Sec-WebSocket-Key is predictable.
            string expectedKey = Convert.ToBase64String(new FakeWebSocketRandom().NextBytes(16));
            Assert.Equal(expectedKey, server.ReceivedKey);

            await client.DisposeAsync();
        }

        [Fact]
        public async Task Handshake_Fails_WhenServerDoesNotSwitchProtocols()
        {
            CancellationToken ct = Timeout();
            var pair = new InMemoryByteStreamPair();
            var client = new WebSocketByteStream(pair.Client, "example.org", "/", random: new FakeWebSocketRandom());
            var server = new FakeWebSocketServer(pair.Server);

            Task accept = server.AcceptAsync(ct, respond101: false);
            await Assert.ThrowsAsync<IOException>(async () => await client.ConnectAsync(ct));
            await accept;

            await client.DisposeAsync();
        }

        [Fact]
        public async Task WriteAsync_SendsMaskedBinaryFrame_ServerRecoversBytesExact()
        {
            CancellationToken ct = Timeout();
            var (client, server) = await ConnectedPairAsync(ct);

            byte[] data = Pattern(300, 0x40);
            await client.WriteAsync(data, ct);

            byte[] received = await server.ReceiveBinaryMessageAsync(ct); // decodes + un-masks the client frame
            Assert.Equal(data, received);

            await client.DisposeAsync();
        }

        [Fact]
        public async Task ReadAsync_RecoversServerBinaryMessage_ByteExact()
        {
            CancellationToken ct = Timeout();
            var (client, server) = await ConnectedPairAsync(ct);

            byte[] data = Pattern(500, 0x11);
            await server.SendBinaryAsync(data, ct);

            byte[] got = await ReadExactAsync(client, data.Length, ct);
            Assert.Equal(data, got);

            await client.DisposeAsync();
        }

        [Fact]
        public async Task ReadAsync_ReassemblesFragmentedMessage()
        {
            CancellationToken ct = Timeout();
            var (client, server) = await ConnectedPairAsync(ct);

            byte[] a = Pattern(40, 0x01);
            byte[] b = Pattern(60, 0x02);
            byte[] c = Pattern(50, 0x03);
            await server.SendFragmentedBinaryAsync(new[] { a, b, c }, ct); // binary + continuation + FIN continuation

            byte[] expected = new byte[a.Length + b.Length + c.Length];
            Array.Copy(a, 0, expected, 0, a.Length);
            Array.Copy(b, 0, expected, a.Length, b.Length);
            Array.Copy(c, 0, expected, a.Length + b.Length, c.Length);

            byte[] got = await ReadExactAsync(client, expected.Length, ct);
            Assert.Equal(expected, got);

            await client.DisposeAsync();
        }

        [Fact]
        public async Task Ping_IsAnsweredWithPong_CarryingSamePayload()
        {
            CancellationToken ct = Timeout();
            var (client, server) = await ConnectedPairAsync(ct);

            byte[] pingPayload = { 0x10, 0x20, 0x30, 0x40, 0x50 };
            await server.SendPingAsync(pingPayload, ct);

            // Control frames are handled inside the read loop: drive a read so the client processes the ping and pongs.
            var buffer = new byte[64];
            Task<int> readTask = client.ReadAsync(buffer, ct).AsTask();

            (bool _, Rfc6455Opcode opcode, byte[] payload) = await server.ReceiveFrameAsync(ct);
            Assert.Equal(Rfc6455Opcode.Pong, opcode);
            Assert.Equal(pingPayload, payload);

            // Unblock the still-pending read cleanly: a close makes it return 0 (end of stream).
            await server.SendCloseAsync(ct);
            Assert.Equal(0, await readTask);

            await client.DisposeAsync();
        }

        [Fact]
        public async Task Close_MakesReadReturnZero()
        {
            CancellationToken ct = Timeout();
            var (client, server) = await ConnectedPairAsync(ct);

            await server.SendCloseAsync(ct);
            int n = await client.ReadAsync(new byte[16], ct);
            Assert.Equal(0, n);

            await client.DisposeAsync();
        }

        [Theory]
        [InlineData(0)]       // empty payload
        [InlineData(1)]
        [InlineData(125)]     // largest 7-bit length
        [InlineData(126)]     // smallest 16-bit extended length
        [InlineData(8192)]    // == inner read buffer
        [InlineData(20000)]   // several inner reads
        public async Task ClientToServer_RoundTrips_ByteExact(int size)
        {
            CancellationToken ct = Timeout();
            var (client, server) = await ConnectedPairAsync(ct);

            byte[] data = Pattern(size, 0x55);
            await client.WriteAsync(data, ct);

            byte[] received = await server.ReceiveBinaryMessageAsync(ct);
            Assert.Equal(data, received);

            await client.DisposeAsync();
        }

        [Theory]
        [InlineData(1)]
        [InlineData(125)]
        [InlineData(126)]
        [InlineData(8192)]
        [InlineData(20000)]
        public async Task ServerToClient_RoundTrips_ByteExact(int size)
        {
            CancellationToken ct = Timeout();
            var (client, server) = await ConnectedPairAsync(ct);

            byte[] data = Pattern(size, 0x66);
            await server.SendBinaryAsync(data, ct);

            byte[] got = await ReadExactAsync(client, data.Length, ct);
            Assert.Equal(data, got);

            await client.DisposeAsync();
        }
    }
}
