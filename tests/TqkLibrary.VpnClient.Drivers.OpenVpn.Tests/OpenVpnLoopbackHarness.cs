using System.Collections.Generic;
using System.IO;
using System.Net;
using System.Net.Security;
using System.Security.Authentication;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using TqkLibrary.VpnClient.Drivers.OpenVpn.Transport;
using TqkLibrary.VpnClient.OpenVpn;
using TqkLibrary.VpnClient.OpenVpn.DataChannel;
using TqkLibrary.VpnClient.OpenVpn.Enums;
using TqkLibrary.VpnClient.OpenVpn.Models;

namespace TqkLibrary.VpnClient.Drivers.OpenVpn.Tests
{
    /// <summary>
    /// Shared offline harness for driving the real <see cref="OpenVpnConnection"/> against an in-process responder:
    /// a lossless ordered loopback link, an in-process transport factory, and a base OpenVPN server that runs the whole
    /// control plane (reset → TLS → key-method-2 → PUSH_REPLY). Subclasses only override how the negotiated data channel
    /// is used — tun echoes the IP packet, tap bridges Ethernet/ARP. This is throwaway test scaffolding: the library is a
    /// client, the responder role exists only here.
    /// </summary>
    static class OpenVpnTestPki
    {
        public static X509Certificate2 CreateSelfSignedServerCert()
        {
            using var rsa = RSA.Create(2048);
            var request = new CertificateRequest("CN=test-openvpn-server", rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
            using X509Certificate2 cert = request.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddDays(1));
            return new X509Certificate2(cert.Export(X509ContentType.Pfx));
        }
    }

    /// <summary>An <see cref="IOpenVpnTransportFactory"/> that hands back a fixed in-process transport (self-pumping loopback).</summary>
    sealed class InProcessTransportFactory : IOpenVpnTransportFactory
    {
        readonly IOpenVpnTransport _transport;
        public InProcessTransportFactory(IOpenVpnTransport transport) => _transport = transport;
        public Task<OpenVpnTransportHandle> ConnectAsync(IPEndPoint remote, CancellationToken cancellationToken)
            => Task.FromResult(new OpenVpnTransportHandle(_transport, receivePump: null, underlying: null));
    }

    /// <summary>An in-memory OpenVPN packet link; each side delivers to the other in send order on the thread pool.</summary>
    sealed class LoopbackLink
    {
        readonly Endpoint _client = new();
        readonly Endpoint _server = new();
        public LoopbackLink() { _client.Peer = _server; _server.Peer = _client; }
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
    /// A throwaway OpenVPN responder: drains the client's control packets through a server <see cref="SslStream"/>
    /// (reset → TLS), answers key-method-2, replies to PUSH_REQUEST with the configured <see cref="PushReply"/>, then
    /// decrypts inbound P_DATA_V2 and hands each payload to <see cref="OnData"/>. The in-memory link is lossless and
    /// ordered, so it needs no retransmit/reorder logic. No tls-auth/tls-crypt wrap in this scenario.
    /// </summary>
    abstract class SimulatedOpenVpnServerBase : IDisposable
    {
        protected const uint PeerId = 7;
        readonly IOpenVpnTransport _transport;
        readonly object _sync = new();
        readonly ServerBridge _bridge = new();
        readonly SslStream _ssl;
        ulong _clientSessionId;
        uint _sendNext;     // our reliability packet-id stream (0 = our reset)
        uint _recvNext;     // next client control packet-id we expect
        bool _resetSent;
        volatile OpenVpnDataChannel? _serverDc;

        public ulong SessionId { get; } = 0x1122334455667788UL;

        /// <summary>The raw peer-info block the client sent in key-method-2 (captured for assertions).</summary>
        public string? ReceivedPeerInfo { get; private set; }

        readonly TaskCompletionSource<string> _exitNotify = new(TaskCreationOptions.RunContinuationsAsynchronously);

        /// <summary>Completes with the OCC control message (e.g. <c>EXIT_NOTIFY</c>) the client sends after PUSH_REPLY.</summary>
        public Task<string> ExitNotifyReceived => _exitNotify.Task;

        protected SimulatedOpenVpnServerBase(IOpenVpnTransport transport, X509Certificate2 certificate)
        {
            _transport = transport;
            _transport.DatagramReceived += OnDatagram;
            _bridge.Send = SendTls;
            _ssl = new SslStream(_bridge, leaveInnerStreamOpen: false);
            _ = RunAsync(certificate);
        }

        /// <summary>The data-channel AEAD the server "selects" (override to exercise NCP; default AES-256-GCM).</summary>
        protected virtual OpenVpnDataCipher DataCipher => OpenVpnDataCipher.Aes256Gcm;

        /// <summary>The PUSH_REPLY options string (override per scenario). Default: a /24 subnet pool + peer-id + the selected cipher.</summary>
        protected virtual string PushReply => $"PUSH_REPLY,ifconfig 10.8.0.2 255.255.255.0,topology subnet,peer-id {PeerId},cipher {DataCipher.Name}";

        /// <summary>The OCC options string the server returns in its key-method-2 reply (override to echo IV_CIPHERS for NCP-less tests).</summary>
        protected virtual string ServerKeyMethodOptions => $"V4,cipher {DataCipher.Name}";

        /// <summary>Handles one decrypted data-channel payload from the client (tun: a bare IP packet; tap: an Ethernet frame).</summary>
        protected abstract void OnData(byte[] plaintext);

        /// <summary>Seals <paramref name="plaintext"/> on the server data channel and pushes it to the client.</summary>
        protected void SendData(byte[] plaintext)
        {
            OpenVpnDataChannel? dc = _serverDc;
            if (dc != null) _ = _transport.SendAsync(dc.Protect(plaintext));
        }

        /// <summary>Test stimulus: send a raw server-originated data payload to the client (used to inject a keepalive ping).</summary>
        public void SendDataToClient(byte[] plaintext) => SendData(plaintext);

        async Task RunAsync(X509Certificate2 certificate)
        {
            try
            {
                await _ssl.AuthenticateAsServerAsync(certificate, clientCertificateRequired: false,
                    SslProtocols.None, checkCertificateRevocation: false);

                // key-method-2: 117 fixed bytes (uint32 0 + key_method + pre-master 48 + 2×random 32) + 4 P_strings.
                byte[] fixedPart = await ReadExactAsync(117);
                var clientKs = new OpenVpnKeySource2(
                    fixedPart.AsSpan(5, 48).ToArray(), fixedPart.AsSpan(53, 32).ToArray(), fixedPart.AsSpan(85, 32).ToArray());
                await ReadStringAsync(); // options
                await ReadStringAsync(); // username
                await ReadStringAsync(); // password
                ReceivedPeerInfo = await ReadStringAsync(); // peer-info (the connection always sends IV_* peer-info)

                var serverKs = ServerKeySource();
                byte[] reply = BuildServerKeyMethod2(serverKs, ServerKeyMethodOptions);
                await _ssl.WriteAsync(reply, 0, reply.Length);
                await _ssl.FlushAsync();

                byte[] key2 = OpenVpnKeyMethod2.DeriveKey2(clientKs, serverKs, _clientSessionId, SessionId);
                OpenVpnDataChannelKeys serverKeys = OpenVpnKeyMethod2.SliceDataKeys(key2, DataCipher, isServer: true);
                _serverDc = new OpenVpnDataChannel(serverKeys, keyId: 0, peerId: PeerId, cipher: DataCipher.CreateCipher());

                // PUSH: read PUSH_REQUEST, push the tunnel config (address /24, peer-id, cipher).
                await OpenVpnControlMessage.ReadAsync(_ssl);
                byte[] push = OpenVpnControlMessage.Build(PushReply);
                await _ssl.WriteAsync(push, 0, push.Length);
                await _ssl.FlushAsync();

                // Keep draining control messages: the client sends explicit-exit-notify (EXIT_NOTIFY) on teardown.
                while (true)
                {
                    string message = await OpenVpnControlMessage.ReadAsync(_ssl);
                    if (message.StartsWith("EXIT_NOTIFY", StringComparison.Ordinal)) _exitNotify.TrySetResult(message);
                }
            }
            catch { /* test harness: connection torn down at end of test (the EXIT_NOTIFY read throws on close) */ }
        }

        void OnDatagram(ReadOnlyMemory<byte> datagram)
        {
            ReadOnlySpan<byte> span = datagram.Span;
            if (span.Length >= 1 && OpenVpnPacketCodec.ReadOpcode(span[0]) == OpenVpnOpcode.DataV2)
            {
                OpenVpnDataChannel? dc = _serverDc;
                if (dc != null && dc.TryUnprotect(span, out byte[] plaintext))
                    OnData(plaintext);
                return;
            }

            if (!OpenVpnPacketCodec.TryDecodeControl(span, out OpenVpnControlPacket packet)) return;

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
                    else wire = EncodeAck(new[] { packet.PacketId });
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
            if (wire != null) _ = _transport.SendAsync(wire);
        }

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
                _ = _transport.SendAsync(wire);
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

        static OpenVpnKeySource2 ServerKeySource()
        {
            byte[] r1 = new byte[OpenVpnKeySource2.RandomSize], r2 = new byte[OpenVpnKeySource2.RandomSize];
            for (int i = 0; i < r1.Length; i++) { r1[i] = (byte)(0x30 + i); r2[i] = (byte)(0x80 + i); }
            return new OpenVpnKeySource2(Array.Empty<byte>(), r1, r2);
        }

        static byte[] BuildServerKeyMethod2(OpenVpnKeySource2 server, string options)
        {
            var buf = new List<byte> { 0, 0, 0, 0, 2 };
            buf.AddRange(server.Random1);
            buf.AddRange(server.Random2);
            byte[] opt = Encoding.ASCII.GetBytes(options);
            int len = opt.Length + 1;
            buf.Add((byte)(len >> 8));
            buf.Add((byte)len);
            buf.AddRange(opt);
            buf.Add(0);
            return buf.ToArray();
        }

        async Task<byte[]> ReadExactAsync(int count)
        {
            byte[] buf = new byte[count];
            int read = 0;
            while (read < count)
            {
                int n = await _ssl.ReadAsync(buf, read, count - read);
                if (n == 0) throw new EndOfStreamException();
                read += n;
            }
            return buf;
        }

        async Task<string> ReadStringAsync()
        {
            byte[] lenBytes = await ReadExactAsync(2);
            int len = (lenBytes[0] << 8) | lenBytes[1];
            if (len <= 0) return string.Empty;
            byte[] bytes = await ReadExactAsync(len);
            int contentLen = len > 0 && bytes[len - 1] == 0 ? len - 1 : len; // drop the trailing NUL
            return Encoding.ASCII.GetString(bytes, 0, contentLen);
        }

        public void Dispose()
        {
            _transport.DatagramReceived -= OnDatagram;
            try { _ssl.Dispose(); } catch { }
            _bridge.CompleteInbound();
        }
    }

    /// <summary>The server side's in-memory stream for its SslStream (mirror of the client's bridge, test-local).</summary>
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
