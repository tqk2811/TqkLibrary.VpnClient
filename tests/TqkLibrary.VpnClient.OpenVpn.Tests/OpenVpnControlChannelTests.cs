using System.Net.Security;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using TqkLibrary.VpnClient.OpenVpn;
using TqkLibrary.VpnClient.OpenVpn.Enums;
using TqkLibrary.VpnClient.OpenVpn.Models;
using Xunit;

namespace TqkLibrary.VpnClient.OpenVpn.Tests
{
    /// <summary>
    /// Drives the real <see cref="OpenVpnControlChannel"/> against an in-process responder so the reset exchange, the
    /// reliability layer and a genuine TLS handshake-over-reliability are validated without a socket: the client does
    /// HARD_RESET_CLIENT_V2 ⇄ HARD_RESET_SERVER_V2, completes <see cref="SslStream"/> AuthenticateAsClient, then a
    /// duplex application-data echo flows through the TLS pipe. The responder is a throwaway test harness (this is a
    /// client library — no server product code).
    /// </summary>
    public class OpenVpnControlChannelTests
    {
        /// <summary>The control-channel wrap variants V2.c adds: none, tls-auth (HMAC) and tls-crypt (HMAC + encrypt).</summary>
        public enum WrapMode { None, TlsAuth, TlsCrypt }

        static OpenVpnStaticKey SharedStaticKey()
        {
            byte[] material = new byte[OpenVpnStaticKey.KeyLength];
            for (int i = 0; i < material.Length; i++) material[i] = (byte)(i * 5 + 9);
            return OpenVpnStaticKey.FromBytes(material);
        }

        static IOpenVpnControlWrap? ClientWrap(WrapMode mode) => mode switch
        {
            WrapMode.TlsAuth => new OpenVpnTlsAuthWrap(SharedStaticKey(), OpenVpnKeyDirection.Inverse, HashAlgorithmName.SHA256),
            WrapMode.TlsCrypt => new OpenVpnTlsCryptWrap(SharedStaticKey(), isServer: false),
            _ => null,
        };

        static IOpenVpnControlWrap? ServerWrap(WrapMode mode) => mode switch
        {
            WrapMode.TlsAuth => new OpenVpnTlsAuthWrap(SharedStaticKey(), OpenVpnKeyDirection.Normal, HashAlgorithmName.SHA256),
            WrapMode.TlsCrypt => new OpenVpnTlsCryptWrap(SharedStaticKey(), isServer: true),
            _ => null,
        };

        [Theory]
        [InlineData(WrapMode.None)]
        [InlineData(WrapMode.TlsAuth)]
        [InlineData(WrapMode.TlsCrypt)]
        public async Task ConnectAsync_CompletesTlsHandshakeThroughReliability_AndEchoesAppData(WrapMode mode)
        {
            var link = new LoopbackLink();
            using var serverCert = CreateSelfSignedServerCert();
            var server = new SimulatedOpenVpnServer(link.Server, serverCert, ServerWrap(mode));

            // A long retransmit interval so the lossless in-memory path never triggers a spurious resend mid-handshake.
            var client = new OpenVpnControlChannel(link.Client,
                options: new OpenVpnReliabilityOptions { Interval = TimeSpan.FromSeconds(30) },
                controlWrap: ClientWrap(mode));

            using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(20));
            await client.ConnectAsync("test-openvpn-server", serverCertificateValidation: (_, _, _, _) => true, cancellationToken: cts.Token);

            Assert.True(client.TlsStream.IsAuthenticated);
            Assert.NotEqual(0UL, client.RemoteSessionId);
            Assert.Equal(server.SessionId, client.RemoteSessionId);

            // Duplex app data over the TLS-in-control pipe: client → server echo → client.
            byte[] payload = Encoding.ASCII.GetBytes("hello openvpn control channel");
            await client.TlsStream.WriteAsync(payload, 0, payload.Length, cts.Token);

            byte[] buffer = new byte[payload.Length];
            int read = 0;
            while (read < buffer.Length)
            {
                int n = await client.TlsStream.ReadAsync(buffer, read, buffer.Length - read, cts.Token);
                Assert.NotEqual(0, n);
                read += n;
            }
            Assert.Equal(payload, buffer);

            client.Dispose();
            server.Dispose();
        }

        [Fact]
        public async Task SendTls_BlocksOnFullWindowOnCallingThread_AndDisposeReleasesIt()
        {
            // No responder ⇒ nothing is ever acked: with a 1-slot window the 2nd fragment must block (sync backpressure).
            var link = new LoopbackLink();
            var client = new OpenVpnControlChannel(link.Client,
                options: new OpenVpnReliabilityOptions { Interval = TimeSpan.FromSeconds(30), WindowSize = 1 });

            Task send = Task.Run(() => client.SendTls(new byte[1500])); // 1200 + 300 ⇒ two fragments
            await Task.Delay(200);
            Assert.False(send.IsCompleted);

            client.Dispose();
            Assert.Same(send, await Task.WhenAny(send, Task.Delay(TimeSpan.FromSeconds(5))));
            await Assert.ThrowsAsync<ObjectDisposedException>(() => send);
            Assert.Throws<ObjectDisposedException>(() => client.SendTls(new byte[1]));
        }

        static X509Certificate2 CreateSelfSignedServerCert()
        {
            using var rsa = RSA.Create(2048);
            var request = new CertificateRequest("CN=test-openvpn-server", rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
            using X509Certificate2 cert = request.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddDays(1));
            // Re-import via PFX so the private key is persisted in a form SslStream can use as a server on every platform.
            return new X509Certificate2(cert.Export(X509ContentType.Pfx));
        }

        /// <summary>An in-memory OpenVPN packet link; each side delivers to the other in send order on the thread pool.</summary>
        sealed class LoopbackLink
        {
            readonly Endpoint _client = new();
            readonly Endpoint _server = new();

            public LoopbackLink()
            {
                _client.Peer = _server;
                _server.Peer = _client;
            }

            public IOpenVpnTransport Client => _client;
            public IOpenVpnTransport Server => _server;

            sealed class Endpoint : IOpenVpnTransport
            {
                public Endpoint? Peer;
                public event Action<ReadOnlyMemory<byte>>? DatagramReceived;
                readonly object _lock = new();
                Task _tail = Task.CompletedTask;

                public Task SendAsync(ReadOnlyMemory<byte> packet)
                {
                    byte[] copy = packet.ToArray();
                    Endpoint? peer = Peer;
                    if (peer != null)
                        lock (peer._lock)
                            peer._tail = peer._tail.ContinueWith(_ => peer.DatagramReceived?.Invoke(copy), TaskScheduler.Default);
                    return Task.CompletedTask;
                }
            }
        }

        /// <summary>
        /// A throwaway OpenVPN responder: answers HARD_RESET_CLIENT_V2 with HARD_RESET_SERVER_V2, acks every client
        /// control packet (so the client's send window drains), and runs a server <see cref="SslStream"/> over its own
        /// in-order bridge. The in-memory link is lossless and ordered, so it needs no retransmit/reorder logic.
        /// </summary>
        sealed class SimulatedOpenVpnServer : IDisposable
        {
            readonly IOpenVpnTransport _transport;
            readonly IOpenVpnControlWrap? _wrap;
            readonly object _sync = new();
            readonly ServerBridge _bridge = new();
            readonly SslStream _ssl;
            ulong _clientSessionId;
            uint _sendNext;     // our reliability packet-id stream (0 = our reset)
            uint _recvNext;     // next client packet-id we expect
            bool _resetSent;

            public ulong SessionId { get; } = 0x1122334455667788UL;

            public SimulatedOpenVpnServer(IOpenVpnTransport transport, X509Certificate2 certificate, IOpenVpnControlWrap? wrap = null)
            {
                _transport = transport;
                _wrap = wrap;
                _transport.DatagramReceived += OnDatagram;
                _bridge.Send = SendTls;
                _ssl = new SslStream(_bridge, leaveInnerStreamOpen: false);
                _ = RunAsync(certificate);
            }

            async Task RunAsync(X509Certificate2 certificate)
            {
                try
                {
                    await _ssl.AuthenticateAsServerAsync(certificate, clientCertificateRequired: false,
                        System.Security.Authentication.SslProtocols.None, checkCertificateRevocation: false);
                    // Echo loop: read app data and write it straight back over TLS.
                    byte[] buffer = new byte[4096];
                    while (true)
                    {
                        int n = await _ssl.ReadAsync(buffer, 0, buffer.Length);
                        if (n == 0) break;
                        await _ssl.WriteAsync(buffer, 0, n);
                    }
                }
                catch { /* test harness: connection torn down at end of test */ }
            }

            void OnDatagram(ReadOnlyMemory<byte> datagram)
            {
                ReadOnlySpan<byte> controlBytes;
                byte[]? unwrapped = null;
                if (_wrap != null)
                {
                    if (!_wrap.TryUnwrap(datagram.Span, out unwrapped)) return;
                    controlBytes = unwrapped;
                }
                else controlBytes = datagram.Span;

                if (!OpenVpnPacketCodec.TryDecodeControl(controlBytes, out OpenVpnControlPacket packet)) return;

                byte[]? wire = null;
                byte[]? deliver = null;
                lock (_sync)
                {
                    if (_clientSessionId == 0 && packet.SessionId != 0) _clientSessionId = packet.SessionId;

                    if (packet.Opcode == OpenVpnOpcode.ControlHardResetClientV2)
                    {
                        if (!_resetSent)
                        {
                            _resetSent = true;
                            _recvNext = packet.PacketId + 1;
                            wire = Encode(OpenVpnOpcode.ControlHardResetServerV2, _sendNext++, new[] { packet.PacketId }, Array.Empty<byte>());
                        }
                        else
                        {
                            wire = EncodeAck(new[] { packet.PacketId });
                        }
                    }
                    else if (!packet.IsAckOnly && packet.PacketId == _recvNext)
                    {
                        _recvNext++;
                        deliver = packet.Payload;
                        wire = EncodeAck(new[] { packet.PacketId });
                    }
                    else if (!packet.IsAckOnly)
                    {
                        wire = EncodeAck(new[] { packet.PacketId }); // duplicate/out-of-order: re-ack only
                    }
                }

                if (deliver is { Length: > 0 }) _bridge.EnqueueInbound(deliver);
                if (wire != null) Send(wire);
            }

            // Apply the same tls-auth/tls-crypt wrap the client uses (symmetric crypto, complementary direction).
            void Send(byte[] wire) => _ = _transport.SendAsync(_wrap != null ? _wrap.Wrap(wire) : wire);

            void SendTls(byte[] data)
            {
                int offset = 0;
                while (offset < data.Length)
                {
                    int len = Math.Min(1200, data.Length - offset);
                    byte[] chunk = new byte[len];
                    Array.Copy(data, offset, chunk, 0, len);
                    byte[] wire;
                    lock (_sync) wire = Encode(OpenVpnOpcode.ControlV1, _sendNext++, Array.Empty<uint>(), chunk);
                    Send(wire);
                    offset += len;
                }
            }

            byte[] Encode(OpenVpnOpcode opcode, uint id, uint[] acks, byte[] payload) => OpenVpnPacketCodec.EncodeControl(new OpenVpnControlPacket
            {
                Opcode = opcode,
                SessionId = SessionId,
                AckPacketIds = acks,
                RemoteSessionId = acks.Length > 0 ? _clientSessionId : 0,
                PacketId = id,
                Payload = payload,
            });

            byte[] EncodeAck(uint[] acks) => OpenVpnPacketCodec.EncodeControl(new OpenVpnControlPacket
            {
                Opcode = OpenVpnOpcode.AckV1,
                SessionId = SessionId,
                AckPacketIds = acks,
                RemoteSessionId = _clientSessionId,
            });

            public void Dispose()
            {
                _transport.DatagramReceived -= OnDatagram;
                try { _ssl.Dispose(); } catch { }
                _bridge.CompleteInbound();
            }
        }

        /// <summary>The server side's in-memory stream for its SslStream — mirror of the client's bridge, test-local.</summary>
        sealed class ServerBridge : Stream
        {
            readonly object _gate = new();
            readonly Queue<byte[]> _inbound = new();
            byte[]? _partial;
            int _partialPos;
            bool _completed;
            TaskCompletionSource<bool>? _waiter;

            public Action<byte[]>? Send;

            public void EnqueueInbound(byte[] data)
            {
                TaskCompletionSource<bool>? signal;
                lock (_gate) { _inbound.Enqueue(data); signal = _waiter; _waiter = null; }
                signal?.TrySetResult(true);
            }

            public void CompleteInbound()
            {
                TaskCompletionSource<bool>? signal;
                lock (_gate) { _completed = true; signal = _waiter; _waiter = null; }
                signal?.TrySetResult(true);
            }

            async Task<int> ReadCoreAsync(byte[] buffer, int offset, int count, CancellationToken ct)
            {
                while (true)
                {
                    TaskCompletionSource<bool> tcs;
                    lock (_gate)
                    {
                        if (_partial is null && _inbound.Count > 0) { _partial = _inbound.Dequeue(); _partialPos = 0; }
                        if (_partial is not null)
                        {
                            int n = Math.Min(count, _partial.Length - _partialPos);
                            Array.Copy(_partial, _partialPos, buffer, offset, n);
                            _partialPos += n;
                            if (_partialPos >= _partial.Length) _partial = null;
                            return n;
                        }
                        if (_completed) return 0;
                        _waiter ??= new TaskCompletionSource<bool>(TaskCreationOptions.RunContinuationsAsynchronously);
                        tcs = _waiter;
                    }
                    using (ct.Register(() => tcs.TrySetCanceled())) await tcs.Task.ConfigureAwait(false);
                }
            }

            public override bool CanRead => true;
            public override bool CanWrite => true;
            public override bool CanSeek => false;
            public override void Flush() { }
            public override Task FlushAsync(CancellationToken cancellationToken) => Task.CompletedTask;
            public override int Read(byte[] buffer, int offset, int count) => ReadCoreAsync(buffer, offset, count, CancellationToken.None).GetAwaiter().GetResult();
            public override Task<int> ReadAsync(byte[] buffer, int offset, int count, CancellationToken cancellationToken) => ReadCoreAsync(buffer, offset, count, cancellationToken);
            public override void Write(byte[] buffer, int offset, int count) { byte[] c = new byte[count]; Array.Copy(buffer, offset, c, 0, count); Send?.Invoke(c); }
            public override Task WriteAsync(byte[] buffer, int offset, int count, CancellationToken cancellationToken) { Write(buffer, offset, count); return Task.CompletedTask; }
            public override async ValueTask<int> ReadAsync(Memory<byte> buffer, CancellationToken cancellationToken = default)
            {
                byte[] tmp = new byte[buffer.Length];
                int n = await ReadCoreAsync(tmp, 0, buffer.Length, cancellationToken).ConfigureAwait(false);
                new ReadOnlyMemory<byte>(tmp, 0, n).CopyTo(buffer);
                return n;
            }
            public override ValueTask WriteAsync(ReadOnlyMemory<byte> buffer, CancellationToken cancellationToken = default) { Write(buffer.ToArray(), 0, buffer.Length); return default; }
            public override long Length => throw new NotSupportedException();
            public override long Position { get => throw new NotSupportedException(); set => throw new NotSupportedException(); }
            public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();
            public override void SetLength(long value) => throw new NotSupportedException();
        }
    }
}
