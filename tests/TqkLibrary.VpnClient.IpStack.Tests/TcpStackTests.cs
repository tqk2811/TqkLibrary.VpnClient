using System.Net;
using System.Text;
using System.Threading.Channels;
using TqkLibrary.VpnClient.Abstractions.Channels.Enums;
using TqkLibrary.VpnClient.Abstractions.Channels.Interfaces;
using TqkLibrary.VpnClient.IpStack;
using TqkLibrary.VpnClient.IpStack.Tcp;
using TqkLibrary.VpnClient.IpStack.Tcp.Enums;
using TqkLibrary.VpnClient.Sockets;
using Xunit;

namespace TqkLibrary.VpnClient.IpStack.Tests
{
    /// <summary>
    /// In-process loopback tests for the userspace TCP stack. <see cref="TcpIpStack"/>/<see cref="TcpConnection"/>
    /// only does active-open, so the peer side is a minimal hand-written passive TCP responder (mirroring the
    /// simulated-responder pattern used for the IKE handshake tests) that talks to the real client over two
    /// back-to-back packet channels: SYN→SYN/ACK handshake, in-order data echo, the client's cumulative ACK, and FIN.
    /// Loopback delivery is FIFO per direction (a serialized pump) so it matches the stack's "reliable, in-order"
    /// contract and the ACK assertions are deterministic.
    /// </summary>
    public class TcpStackTests
    {
        static readonly IPAddress ClientIp = IPAddress.Parse("10.0.0.1");
        static readonly IPAddress ServerIp = IPAddress.Parse("10.0.0.2");

        [Fact]
        public async Task Handshake_DataEcho_CumulativeAck_AndActiveClose()
        {
            var link = new LoopbackPair();
            var stack = new TcpIpStack(link.A, ClientIp);
            var server = new PassiveTcpServer(link.B, ServerIp);

            using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(5));
            TcpConnection connection = await stack.ConnectAsync(ServerIp, 80, cts.Token);

            connection.Enqueue(Encoding.ASCII.GetBytes("ping"));
            string echoed = await ReadStringAsync(connection, 4, cts.Token);
            Assert.Equal("ping", echoed);
            Assert.Equal(1, server.AcceptedConnections);

            // The client must cumulatively ACK the server's echoed bytes: SYN(1) + the 4 echoed data bytes.
            uint expectedAck = PassiveTcpServer.ServerIss + 1 + 4;
            await WaitUntilAsync(() => server.LastAck == expectedAck, cts.Token);
            Assert.Equal(expectedAck, server.LastAck);

            // Active close: our FIN → the server replies with its FIN → the next read sees end-of-stream.
            connection.CloseSend();
            byte[] buffer = new byte[8];
            int n = await connection.ReadAsync(buffer, 0, buffer.Length, cts.Token);
            Assert.Equal(0, n);
            await WaitUntilAsync(() => server.ClientFinReceived, cts.Token);
            Assert.True(server.ClientFinReceived);
        }

        [Fact]
        public async Task PassiveClose_ServerFinFirst_ReadsEof_ThenClientCanClose()
        {
            var link = new LoopbackPair();
            var stack = new TcpIpStack(link.A, ClientIp);
            var server = new PassiveTcpServer(link.B, ServerIp);

            using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(5));
            TcpConnection connection = await stack.ConnectAsync(ServerIp, 80, cts.Token);

            // The peer closes first: client (Established) sees the FIN → CloseWait, read returns end-of-stream.
            server.CloseFromServer();
            byte[] buffer = new byte[8];
            int n = await connection.ReadAsync(buffer, 0, buffer.Length, cts.Token);
            Assert.Equal(0, n);

            // The client then closes its own side from CloseWait → the server observes the client's FIN.
            connection.CloseSend();
            await WaitUntilAsync(() => server.ClientFinReceived, cts.Token);
            Assert.True(server.ClientFinReceived);
        }

        [Fact]
        public async Task VpnTcpClient_Stream_RoundTripsThroughTunnel()
        {
            var link = new LoopbackPair();
            var stack = new TcpIpStack(link.A, ClientIp);
            _ = new PassiveTcpServer(link.B, ServerIp);

            using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(5));
            VpnTcpClient client = await VpnTcpClient.ConnectAsync(stack, ServerIp, 443, cts.Token);
            System.IO.Stream stream = client.GetStream();

            byte[] message = Encoding.ASCII.GetBytes("hello-tunnel");
            await stream.WriteAsync(message, 0, message.Length, cts.Token);

            byte[] buffer = new byte[message.Length];
            int offset = 0;
            while (offset < buffer.Length)
            {
                int read = await stream.ReadAsync(buffer, offset, buffer.Length - offset, cts.Token);
                Assert.True(read > 0, "stream closed before the echo arrived");
                offset += read;
            }
            Assert.Equal("hello-tunnel", Encoding.ASCII.GetString(buffer));
        }

        [Fact]
        public async Task VpnTcpClient_Stream_SyncReadWrite_RoundTripsThroughTunnel()
        {
            var link = new LoopbackPair();
            var stack = new TcpIpStack(link.A, ClientIp);
            _ = new PassiveTcpServer(link.B, ServerIp);

            using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(5));
            VpnTcpClient client = await VpnTcpClient.ConnectAsync(stack, ServerIp, 443, cts.Token);
            System.IO.Stream stream = client.GetStream();
            stream.ReadTimeout = 5000;      // guard: a broken wake-up fails the test instead of hanging it
            stream.WriteTimeout = 5000;

            byte[] message = Encoding.ASCII.GetBytes("hello-sync");
            stream.Write(message, 0, message.Length);
            stream.Flush();

            byte[] buffer = new byte[message.Length];
            int offset = 0;
            while (offset < buffer.Length)
            {
                int read = stream.Read(buffer, offset, buffer.Length - offset);
                Assert.True(read > 0, "stream closed before the echo arrived");
                offset += read;
            }
            Assert.Equal("hello-sync", Encoding.ASCII.GetString(buffer));

            // Nothing more is coming: the sync read honours ReadTimeout.
            stream.ReadTimeout = 100;
            Assert.Throws<System.IO.IOException>(() => stream.Read(buffer, 0, buffer.Length));
        }

        [Fact]
        public async Task VpnTcpClient_Stream_Timeouts_ValidateLikeNetworkStream()
        {
            var link = new LoopbackPair();
            var stack = new TcpIpStack(link.A, ClientIp);
            _ = new PassiveTcpServer(link.B, ServerIp);

            using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(5));
            VpnTcpClient client = await VpnTcpClient.ConnectAsync(stack, ServerIp, 443, cts.Token);
            System.IO.Stream stream = client.GetStream();

            Assert.True(stream.CanTimeout);
            Assert.Equal(Timeout.Infinite, stream.ReadTimeout);
            Assert.Equal(Timeout.Infinite, stream.WriteTimeout);
            Assert.Throws<ArgumentOutOfRangeException>(() => stream.ReadTimeout = 0);
            Assert.Throws<ArgumentOutOfRangeException>(() => stream.ReadTimeout = -2);
            Assert.Throws<ArgumentOutOfRangeException>(() => stream.WriteTimeout = 0);
            stream.ReadTimeout = 250;
            stream.WriteTimeout = Timeout.Infinite;
            Assert.Equal(250, stream.ReadTimeout);
            Assert.Equal(Timeout.Infinite, stream.WriteTimeout);
        }

        [Fact]
        public async Task Dispose_WhileReadPending_ReleasesReaderWithEndOfStream()
        {
            var link = new LoopbackPair();
            var stack = new TcpIpStack(link.A, ClientIp);
            _ = new PassiveTcpServer(link.B, ServerIp);

            using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(5));
            TcpConnection connection = await stack.ConnectAsync(ServerIp, 80, cts.Token);

            // Park a reader with no data and no cancellation token, then dispose: the read must complete (EOF),
            // not hang forever on the never-signalled waiter.
            byte[] buffer = new byte[8];
            Task<int> pendingRead = connection.ReadAsync(buffer, 0, buffer.Length, CancellationToken.None);
            Assert.False(pendingRead.IsCompleted);

            connection.Dispose();

            Task winner = await Task.WhenAny(pendingRead, Task.Delay(TimeSpan.FromSeconds(5)));
            Assert.Same(pendingRead, winner);
            Assert.Equal(0, await pendingRead);
        }

        static async Task<string> ReadStringAsync(TcpConnection connection, int count, CancellationToken cancellationToken)
        {
            byte[] buffer = new byte[count];
            int offset = 0;
            while (offset < count)
            {
                int read = await connection.ReadAsync(buffer, offset, count - offset, cancellationToken);
                if (read == 0) break;
                offset += read;
            }
            return Encoding.ASCII.GetString(buffer, 0, offset);
        }

        static async Task WaitUntilAsync(Func<bool> condition, CancellationToken cancellationToken)
        {
            try
            {
                while (!condition())
                {
                    cancellationToken.ThrowIfCancellationRequested();
                    await Task.Delay(5, cancellationToken);
                }
            }
            catch (OperationCanceledException) { /* let the caller's assertion report the actual value */ }
        }

        /// <summary>A minimal passive (listen-side) TCP endpoint built directly on the codecs, for loopback tests.</summary>
        sealed class PassiveTcpServer
        {
            public const uint ServerIss = 5000;
            readonly IPacketChannel _channel;
            readonly IPAddress _localIp;
            IPAddress _remoteIp = IPAddress.Any;
            ushort _localPort, _remotePort, _ipId = 1;
            uint _sndNxt, _rcvNxt;
            bool _synced;

            public PassiveTcpServer(IPacketChannel channel, IPAddress localIp)
            {
                _channel = channel;
                _localIp = localIp;
                _channel.InboundIpPacket += OnInbound;
            }

            /// <summary>Number of SYNs accepted (diagnostic).</summary>
            public int AcceptedConnections { get; private set; }

            /// <summary>The acknowledgment number of the most recent inbound segment (for cumulative-ACK checks).</summary>
            public uint LastAck { get; private set; }

            /// <summary>True once the client's FIN has been observed.</summary>
            public bool ClientFinReceived { get; private set; }

            /// <summary>Sends an unsolicited FIN to drive the client into a passive close (CloseWait).</summary>
            public void CloseFromServer()
            {
                Send(TcpFlags.Fin | TcpFlags.Ack, ReadOnlySpan<byte>.Empty);
                _sndNxt += 1;
            }

            void OnInbound(ReadOnlyMemory<byte> ipPacket)
            {
                ReadOnlySpan<byte> ip = ipPacket.Span;
                if (ip.Length < 20 || Ipv4.Protocol(ip) != Ipv4.ProtocolTcp) return;

                ReadOnlyMemory<byte> tcp = Ipv4.Payload(ipPacket);
                ReadOnlySpan<byte> seg = tcp.Span;
                if (seg.Length < 20) return;

                TcpFlags flags = TcpSegment.Flags(seg);
                uint seq = TcpSegment.Sequence(seg);
                LastAck = TcpSegment.Acknowledgment(seg);
                ReadOnlyMemory<byte> payload = TcpSegment.Payload(tcp);
                int len = payload.Length;

                _remoteIp = Ipv4.Source(ip);
                _remotePort = TcpSegment.SourcePort(seg);
                _localPort = TcpSegment.DestinationPort(seg);

                if ((flags & TcpFlags.Syn) != 0)
                {
                    _rcvNxt = seq + 1;
                    _sndNxt = ServerIss;
                    Send(TcpFlags.Syn | TcpFlags.Ack, ReadOnlySpan<byte>.Empty, mss: 1360);
                    _sndNxt += 1;
                    _synced = true;
                    AcceptedConnections++;
                    return;
                }

                if (!_synced) return;

                if (len > 0 && seq == _rcvNxt)
                {
                    _rcvNxt += (uint)len;
                    Send(TcpFlags.Psh | TcpFlags.Ack, payload.Span); // echo (carries the ACK)
                    _sndNxt += (uint)len;
                }

                if ((flags & TcpFlags.Fin) != 0 && seq + (uint)len == _rcvNxt)
                {
                    _rcvNxt += 1;
                    ClientFinReceived = true;
                    Send(TcpFlags.Fin | TcpFlags.Ack, ReadOnlySpan<byte>.Empty);
                    _sndNxt += 1;
                }
            }

            void Send(TcpFlags flags, ReadOnlySpan<byte> payload, ushort mss = 0)
            {
                byte[] tcp = TcpSegment.Build(_localIp, _remoteIp, _localPort, _remotePort, _sndNxt, _rcvNxt, flags, 65535, payload, mss);
                byte[] ip = Ipv4.Build(_localIp, _remoteIp, Ipv4.ProtocolTcp, tcp, _ipId++);
                _ = _channel.WriteIpPacketAsync(ip);
            }
        }

        /// <summary>
        /// Two in-memory IP packet channels wired back to back. Each direction has a single serialized delivery pump,
        /// so packets arrive in FIFO order (matching the stack's reliable in-order contract) yet off the writer's
        /// thread — which is required, since synchronous re-entrant delivery would deadlock on TcpConnection's lock.
        /// </summary>
        sealed class LoopbackPair
        {
            public LoopbackPair()
            {
                var a = new Channel();
                var b = new Channel();
                a.Peer = b;
                b.Peer = a;
                A = a;
                B = b;
            }

            public IPacketChannel A { get; }
            public IPacketChannel B { get; }

            sealed class Channel : IPacketChannel
            {
                readonly Channel<byte[]> _queue = System.Threading.Channels.Channel.CreateUnbounded<byte[]>(
                    new UnboundedChannelOptions { SingleReader = true });

                public Channel()
                {
                    _ = Task.Run(DrainAsync);
                }

                public Channel? Peer;
                public LinkMedium Medium => LinkMedium.Ip;
                public int Mtu => 1400;
                public int MaxHeaderLength => 0;
                public bool RequiresLinkAddressResolution => false;
                public event Action<ReadOnlyMemory<byte>>? InboundIpPacket;

                public ValueTask WriteIpPacketAsync(ReadOnlyMemory<byte> ipPacket, CancellationToken cancellationToken = default)
                {
                    Peer?._queue.Writer.TryWrite(ipPacket.ToArray());
                    return default;
                }

                async Task DrainAsync()
                {
                    while (await _queue.Reader.WaitToReadAsync().ConfigureAwait(false))
                        while (_queue.Reader.TryRead(out byte[]? packet))
                            InboundIpPacket?.Invoke(packet);
                }

                public ValueTask DisposeAsync()
                {
                    _queue.Writer.TryComplete();
                    return default;
                }
            }
        }
    }
}
