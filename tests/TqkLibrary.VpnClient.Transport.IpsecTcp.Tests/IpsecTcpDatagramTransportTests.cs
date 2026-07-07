using System;
using System.IO;
using System.Threading;
using System.Threading.Tasks;
using TqkLibrary.VpnClient.Abstractions.Transport.Interfaces;
using Xunit;

namespace TqkLibrary.VpnClient.Transport.IpsecTcp.Tests
{
    /// <summary>
    /// End-to-end tests for <see cref="IpsecTcpDatagramTransport"/> over an in-memory byte-stream loopback: initiator
    /// (sends the stream prefix) wired to a responder (consumes it), datagrams round-tripping byte-exact in both
    /// directions, plus the connection-close and buffer-size edge cases.
    /// </summary>
    public class IpsecTcpDatagramTransportTests
    {
        static CancellationToken Ct => TestContext.Current.CancellationToken;

        static byte[] Pattern(int length, byte seed)
        {
            byte[] b = new byte[length];
            for (int i = 0; i < length; i++) b[i] = (byte)(seed + i * 3);
            return b;
        }

        // Builds a connected initiator⇄responder pair over one in-memory byte-stream loopback.
        static async Task<(IpsecTcpDatagramTransport client, IpsecTcpDatagramTransport server)> ConnectedPairAsync()
        {
            var pipe = new InMemoryByteStreamPair();
            var client = new IpsecTcpDatagramTransport(pipe.Client, sendStreamPrefix: true);
            var server = new IpsecTcpDatagramTransport(pipe.Server, sendStreamPrefix: false);
            await client.ConnectAsync(Ct);
            await server.ConnectAsync(Ct);
            return (client, server);
        }

        static async Task<byte[]> ReceiveOneAsync(IDatagramTransport transport, int bufferSize = 70000)
        {
            byte[] buffer = new byte[bufferSize];
            int n = await transport.ReceiveAsync(buffer, Ct);
            return buffer.AsSpan(0, n).ToArray();
        }

        [Fact]
        public async Task Loopback_RoundTripsDatagrams_BothDirections()
        {
            var (client, server) = await ConnectedPairAsync();
            await using var _ = client;
            await using var __ = server;

            // client -> server, twice (the responder must first strip the "IKETCP" prefix)
            byte[] up1 = Pattern(30, 0x01);
            byte[] up2 = Pattern(45, 0x11);
            await client.SendAsync(up1, Ct);
            await client.SendAsync(up2, Ct);
            Assert.Equal(up1, await ReceiveOneAsync(server));
            Assert.Equal(up2, await ReceiveOneAsync(server));

            // server -> client (no prefix in this direction)
            byte[] down = Pattern(60, 0x21);
            await server.SendAsync(down, Ct);
            Assert.Equal(down, await ReceiveOneAsync(client));
        }

        [Theory]
        [InlineData(1)]
        [InlineData(64)]
        [InlineData(1400)]
        [InlineData(65533)]   // largest framable datagram
        public async Task Loopback_RoundTripsDatagramOfSize(int size)
        {
            var (client, server) = await ConnectedPairAsync();
            await using var _ = client;
            await using var __ = server;

            byte[] datagram = Pattern(size, 0x07);
            await client.SendAsync(datagram, Ct);

            Assert.Equal(datagram, await ReceiveOneAsync(server));
        }

        [Fact]
        public async Task Connect_WritesStreamPrefix_ForInitiator()
        {
            var pipe = new InMemoryByteStreamPair();
            var client = new IpsecTcpDatagramTransport(pipe.Client, sendStreamPrefix: true);
            await using var _ = client;

            await client.ConnectAsync(Ct);

            // The responder side sees exactly the six-byte "IKETCP" prefix first (written as one chunk on connect).
            byte[] prefix = new byte[Rfc8229Framing.StreamPrefixLength];
            int read = await pipe.Server.ReadAsync(prefix, Ct);
            Assert.Equal(Rfc8229Framing.StreamPrefixLength, read);
            Assert.Equal(Rfc8229Framing.StreamPrefix.ToArray(), prefix);
        }

        [Fact]
        public async Task Connect_WritesNothing_ForResponder()
        {
            var pipe = new InMemoryByteStreamPair();
            var server = new IpsecTcpDatagramTransport(pipe.Server, sendStreamPrefix: false);
            await using var _ = server;

            await server.ConnectAsync(Ct);
            // Nothing was written toward the client; a subsequent send is the only inbound data.
            await server.SendAsync(new byte[] { 0xAA, 0xBB }, Ct);

            // The first bytes the client sees are the frame (Length=4), NOT a prefix.
            byte[] head = new byte[2];
            await pipe.Client.ReadAsync(head, Ct);
            Assert.Equal(new byte[] { 0x00, 0x04 }, head);   // 2-byte message + 2-byte Length field
        }

        [Fact]
        public async Task SendAsync_EmptyDatagram_RoundTrips()
        {
            var (client, server) = await ConnectedPairAsync();
            await using var _ = client;
            await using var __ = server;

            await client.SendAsync(Array.Empty<byte>(), Ct);

            byte[] received = await ReceiveOneAsync(server);
            Assert.Empty(received);
        }

        [Fact]
        public async Task LargeDatagram_SpansMultipleInnerReads()
        {
            // 20000 bytes > the transport's 8192-byte read buffer, so ReceiveAsync must loop several inner reads.
            var (client, server) = await ConnectedPairAsync();
            await using var _ = client;
            await using var __ = server;

            byte[] datagram = Pattern(20000, 0x33);
            await client.SendAsync(datagram, Ct);

            Assert.Equal(datagram, await ReceiveOneAsync(server));
        }

        [Fact]
        public async Task ReceiveAsync_ThrowsEndOfStream_WhenInnerClosesMidFrame()
        {
            var pipe = new InMemoryByteStreamPair();
            var client = new IpsecTcpDatagramTransport(pipe.Client, sendStreamPrefix: true);
            await using var _ = client;
            await client.ConnectAsync(Ct);

            // Server writes a Length header claiming 10 bytes but only 3 bytes of body, then closes.
            await pipe.Server.WriteAsync(new byte[] { 0x00, 0x0A, 0x01, 0x02, 0x03 }, Ct);
            await pipe.Server.DisposeAsync();

            await Assert.ThrowsAsync<EndOfStreamException>(async () => await client.ReceiveAsync(new byte[100], Ct));
        }

        [Fact]
        public async Task ReceiveAsync_ThrowsEndOfStream_WhenInnerClosesAtBoundary()
        {
            var pipe = new InMemoryByteStreamPair();
            var client = new IpsecTcpDatagramTransport(pipe.Client, sendStreamPrefix: true);
            await using var _ = client;
            await client.ConnectAsync(Ct);

            await pipe.Server.DisposeAsync();   // clean close, no buffered data

            await Assert.ThrowsAsync<EndOfStreamException>(async () => await client.ReceiveAsync(new byte[100], Ct));
        }

        [Fact]
        public async Task ReceiveAsync_ThrowsWhenBufferTooSmall()
        {
            var (client, server) = await ConnectedPairAsync();
            await using var _ = client;
            await using var __ = server;

            await client.SendAsync(Pattern(100, 0x44), Ct);

            await Assert.ThrowsAsync<ArgumentException>(async () => await server.ReceiveAsync(new byte[10], Ct));
        }
    }
}
