using System.Buffers.Binary;
using System.Net.Security;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using TqkLibrary.VpnClient.OpenVpn.DataChannel;
using TqkLibrary.VpnClient.OpenVpn.Enums;
using TqkLibrary.VpnClient.OpenVpn.Models;

namespace TqkLibrary.VpnClient.OpenVpn
{
    /// <summary>
    /// The OpenVPN control channel (client role): assembles the reliability windows, the packet codec, the 64-bit
    /// session ids and the transport into a single object, then runs a real <see cref="SslStream"/> handshake
    /// <em>inside</em> that reliable channel (TLS over the in-memory <see cref="OpenVpnTlsBridgeStream"/>).
    /// <see cref="ConnectAsync"/> performs the P_CONTROL_HARD_RESET_CLIENT_V2 ⇄ P_CONTROL_HARD_RESET_SERVER_V2 exchange
    /// (reliability packet-id 0), then the TLS client handshake (its records ride packet-id 1+). After it returns,
    /// <see cref="TlsStream"/> is the authenticated pipe the key-method-2 negotiation + data-channel keying run over
    /// (V2.d). Inbound packets are pushed in via the transport's <see cref="IOpenVpnTransport.DatagramReceived"/>; a
    /// timer pumps retransmits. An optional <see cref="IOpenVpnControlWrap"/> authenticates (<c>--tls-auth</c>) or
    /// encrypts (<c>--tls-crypt</c>) every control packet on the wire. Not a server: the responder role lives only in tests.
    /// </summary>
    public sealed class OpenVpnControlChannel : IDisposable
    {
        // One control packet carries at most one TLS record fragment; keep it well under a typical path MTU so a
        // datagram (header + acks + packet-id + payload) does not fragment at the IP layer.
        const int TlsFragmentSize = 1200;
        // Acks piggybacked onto an outgoing P_CONTROL; the rest (or all, when idle) go in a standalone P_ACK_V1 (≤8).
        const int MaxPiggybackAcks = 4;

        readonly IOpenVpnTransport _transport;
        readonly OpenVpnReliabilityOptions _options;
        readonly IOpenVpnControlWrap? _wrap;
        readonly Func<long> _clock;
        readonly byte _keyId;
        readonly ulong _localSessionId;
        readonly OpenVpnReliableSendWindow _sendWindow;
        readonly OpenVpnReliableReceiveWindow _recvWindow;
        readonly OpenVpnTlsBridgeStream _bridge;
        readonly SemaphoreSlim _windowSlots;
        readonly object _sync = new();
        readonly TaskCompletionSource<bool> _resetReceived = new(TaskCreationOptions.RunContinuationsAsynchronously);

        System.Threading.Timer? _timer;
        ulong _remoteSessionId;
        SslStream? _ssl;
        bool _disposed;

        /// <summary>
        /// Creates the channel over <paramref name="transport"/>. <paramref name="keyId"/> selects the key generation
        /// (0 for the initial handshake). <paramref name="options"/> sets the retransmit/window policy (default 1s,
        /// window 8). <paramref name="controlWrap"/> authenticates/encrypts every control packet on the wire
        /// (<see cref="OpenVpnTlsAuthWrap"/> for <c>--tls-auth</c>, <see cref="OpenVpnTlsCryptWrap"/> for
        /// <c>--tls-crypt</c>); null ⇒ the packets ride the wire verbatim (neither directive). <paramref name="clock"/>
        /// supplies the millisecond clock the retransmit pump uses (default: the system tick clock) — tests inject a
        /// deterministic one.
        /// </summary>
        public OpenVpnControlChannel(IOpenVpnTransport transport, byte keyId = 0,
            OpenVpnReliabilityOptions? options = null, IOpenVpnControlWrap? controlWrap = null, Func<long>? clock = null)
        {
            _transport = transport ?? throw new ArgumentNullException(nameof(transport));
            _options = options ?? new OpenVpnReliabilityOptions();
            _wrap = controlWrap;
            _clock = clock ?? DefaultClock;
            _keyId = keyId;
            _sendWindow = new OpenVpnReliableSendWindow(_options);
            _recvWindow = new OpenVpnReliableReceiveWindow(_options);
            _windowSlots = new SemaphoreSlim(_options.WindowSize, _options.WindowSize);
            _bridge = new OpenVpnTlsBridgeStream(SendTlsAsync);
            _localSessionId = GenerateSessionId();
            _transport.DatagramReceived += OnDatagram;
        }

        /// <summary>This client's 64-bit session id (carried in every outgoing control packet).</summary>
        public ulong LocalSessionId => _localSessionId;

        /// <summary>The peer's 64-bit session id, learned from its first control packet (0 until then).</summary>
        public ulong RemoteSessionId { get { lock (_sync) return _remoteSessionId; } }

        /// <summary>The key generation id this channel tags its control packets with.</summary>
        public byte KeyId => _keyId;

        /// <summary>The authenticated TLS pipe, valid after <see cref="ConnectAsync"/> completes.</summary>
        public SslStream TlsStream => _ssl ?? throw new InvalidOperationException("The control channel TLS is not established yet.");

        /// <summary>The server certificate captured during the TLS handshake (null until/unless one was presented).</summary>
        public X509Certificate2? RemoteCertificate { get; private set; }

        /// <summary>
        /// The OCC options string the server returned in its key-method-2 reply (empty until
        /// <see cref="NegotiateKeyMaterialAsync"/> completes). Some servers echo their NCP cipher list here
        /// (<c>IV_CIPHERS=…</c>) — see <see cref="OpenVpnDataCipher.ExtractIvCiphers"/>.
        /// </summary>
        public string ServerKeyMethodOptions { get; private set; } = string.Empty;

        /// <summary>
        /// Runs the reset exchange then the TLS client handshake. <paramref name="targetHost"/> is the TLS SNI/target;
        /// <paramref name="clientCertificates"/> authenticate the client (OpenVPN's cert auth) when supplied;
        /// <paramref name="serverCertificateValidation"/> validates the server certificate (null ⇒ accept any — the
        /// driver supplies real validation later). Throws if cancelled.
        /// </summary>
        public async Task ConnectAsync(string targetHost,
            X509CertificateCollection? clientCertificates = null,
            RemoteCertificateValidationCallback? serverCertificateValidation = null,
            CancellationToken cancellationToken = default)
        {
            // Start the retransmit/ack pump: idle ticks are cheap (nothing due, no pending acks).
            _timer = new System.Threading.Timer(_ => { try { Pump(); } catch { } }, null, _options.Interval, _options.Interval);

            // P_CONTROL_HARD_RESET_CLIENT_V2 — reliability packet-id 0 (the EncodeControl opcode rule maps id 0 → reset).
            await _windowSlots.WaitAsync(cancellationToken).ConfigureAwait(false);
            lock (_sync) _sendWindow.Queue(Array.Empty<byte>());
            Pump();

            using (cancellationToken.Register(() => _resetReceived.TrySetCanceled()))
                await _resetReceived.Task.ConfigureAwait(false);

            var ssl = new SslStream(_bridge, leaveInnerStreamOpen: false, (sender, cert, chain, errors) =>
            {
                if (cert != null) RemoteCertificate = new X509Certificate2(cert);
                return serverCertificateValidation?.Invoke(sender, cert, chain, errors) ?? true;
            });
            _ssl = ssl;
#if NET5_0_OR_GREATER
            var tlsOptions = new SslClientAuthenticationOptions { TargetHost = targetHost };
            if (clientCertificates != null) tlsOptions.ClientCertificates = clientCertificates;
            await ssl.AuthenticateAsClientAsync(tlsOptions, cancellationToken).ConfigureAwait(false);
#else
            using (cancellationToken.Register(() => { try { ssl.Dispose(); } catch { } }))
            {
                try
                {
                    await ssl.AuthenticateAsClientAsync(targetHost, clientCertificates,
                        System.Security.Authentication.SslProtocols.None, checkCertificateRevocation: false).ConfigureAwait(false);
                }
                catch (Exception) when (cancellationToken.IsCancellationRequested) { }
            }
            cancellationToken.ThrowIfCancellationRequested();
#endif
        }

        /// <summary>
        /// Runs key-method-2 over the established TLS channel and returns the derived <see cref="OpenVpnKeyMaterial"/>
        /// (V2.d). Call after <see cref="ConnectAsync"/>; slice it for the negotiated cipher once known (NCP, V2.f).
        /// <paramref name="optionsString"/> is the OCC options string the server compares;
        /// <paramref name="username"/>/<paramref name="password"/> carry auth-user-pass; <paramref name="peerInfo"/> is
        /// the optional IV_* peer-info block (carrying <c>IV_CIPHERS</c> for NCP — see
        /// <see cref="OpenVpnPeerInfo"/>).
        /// </summary>
        public async Task<OpenVpnKeyMaterial> NegotiateKeyMaterialAsync(string optionsString,
            string? username = null, string? password = null, string? peerInfo = null, CancellationToken cancellationToken = default)
        {
            var negotiation = new OpenVpnKeyNegotiation(TlsStream, LocalSessionId, RemoteSessionId);
            OpenVpnKeyMaterial material = await negotiation
                .NegotiateAsync(optionsString, username, password, peerInfo, cancellationToken).ConfigureAwait(false);
            ServerKeyMethodOptions = negotiation.ServerOptions;
            return material;
        }

        /// <summary>
        /// Pulls the server configuration (V2.e): sends <c>PUSH_REQUEST</c> over the TLS channel and returns the parsed
        /// <c>PUSH_REPLY</c> (tunnel address, routes, DNS, peer-id, keepalive timers, cipher). Non-PUSH_REPLY
        /// informational lines are skipped; <c>AUTH_FAILED</c> throws.
        /// </summary>
        public async Task<OpenVpnPushReply> RequestConfigAsync(CancellationToken cancellationToken = default)
        {
            byte[] request = OpenVpnControlMessage.Build("PUSH_REQUEST");
            await TlsStream.WriteAsync(request, 0, request.Length, cancellationToken).ConfigureAwait(false);
            await TlsStream.FlushAsync(cancellationToken).ConfigureAwait(false);

            while (true)
            {
                string message = await OpenVpnControlMessage.ReadAsync(TlsStream, cancellationToken).ConfigureAwait(false);
                if (OpenVpnPushReply.TryParse(message, out OpenVpnPushReply reply)) return reply;
                if (message.StartsWith("AUTH_FAILED", StringComparison.Ordinal))
                    throw new InvalidOperationException("OpenVPN server rejected the session: " + message);
                // otherwise an informational line (e.g. a deferred reply) — keep reading.
            }
        }

        /// <summary>
        /// Sends OpenVPN's <c>explicit-exit-notify</c> (the <c>EXIT_NOTIFY</c> OCC control message) over the TLS channel so
        /// the server tears the session down immediately instead of waiting for its keepalive timeout. Best-effort: a
        /// throw (the channel is already closing) is swallowed, and this never blocks teardown. Call before disposing the
        /// channel; no-op if TLS was never established.
        /// </summary>
        public async Task SendExitNotifyAsync(CancellationToken cancellationToken = default)
        {
            SslStream? ssl = _ssl;
            if (ssl is null) return;
            try
            {
                byte[] message = OpenVpnControlMessage.Build("EXIT_NOTIFY");
                await ssl.WriteAsync(message, 0, message.Length, cancellationToken).ConfigureAwait(false);
                await ssl.FlushAsync(cancellationToken).ConfigureAwait(false);
            }
            catch { /* best-effort: the link may already be gone — teardown proceeds regardless */ }
        }

        // Bridge write callback: fragment the TLS bytes, queue each fragment reliably (blocking on window space), pump.
        async Task SendTlsAsync(ReadOnlyMemory<byte> buffer, CancellationToken cancellationToken)
        {
            int offset = 0;
            while (offset < buffer.Length)
            {
                await _windowSlots.WaitAsync(cancellationToken).ConfigureAwait(false);
                int len = Math.Min(TlsFragmentSize, buffer.Length - offset);
                byte[] chunk = buffer.Slice(offset, len).ToArray();
                lock (_sync) _sendWindow.Queue(chunk);
                offset += len;
                Pump();
            }
        }

        void OnDatagram(ReadOnlyMemory<byte> datagram)
        {
            ReadOnlySpan<byte> controlBytes;
            byte[]? unwrapped = null;
            if (_wrap != null)
            {
                // tls-auth/tls-crypt: drop the datagram if it fails authentication (or isn't ours).
                if (!_wrap.TryUnwrap(datagram.Span, out unwrapped)) return;
                controlBytes = unwrapped;
            }
            else controlBytes = datagram.Span;

            if (!OpenVpnPacketCodec.TryDecodeControl(controlBytes, out OpenVpnControlPacket packet))
                return; // data packets are handled by the data channel (V2.d), not here

            bool resetSeen = false;
            var deliver = new List<byte[]>();
            lock (_sync)
            {
                if (_remoteSessionId == 0 && packet.SessionId != 0) _remoteSessionId = packet.SessionId;

                foreach (uint ackedId in packet.AckPacketIds)
                    if (_sendWindow.Acknowledge(ackedId)) _windowSlots.Release();

                if (!packet.IsAckOnly)
                {
                    _recvWindow.Offer(packet.PacketId, packet.Payload);
                    while (_recvWindow.TryDeliver(out byte[] payload))
                        if (payload.Length > 0) deliver.Add(payload);
                }

                if (packet.Opcode == OpenVpnOpcode.ControlHardResetServerV2
                    || packet.Opcode == OpenVpnOpcode.ControlHardResetServerV1)
                    resetSeen = true;
            }

            foreach (byte[] p in deliver) _bridge.EnqueueInbound(p);
            if (resetSeen) _resetReceived.TrySetResult(true);
            Pump();
        }

        // Emits everything currently due: (re)transmissions with piggybacked acks, then a standalone P_ACK for leftovers.
        void Pump()
        {
            var outgoing = new List<byte[]>();
            lock (_sync)
            {
                if (_disposed) return;
                IReadOnlyList<(uint Id, byte[] Payload)> due = _sendWindow.CollectDue(_clock());
                foreach ((uint id, byte[] payload) in due)
                    outgoing.Add(EncodeControl(id, payload, _recvWindow.TakeAcks(MaxPiggybackAcks)));

                IReadOnlyList<uint> rest = _recvWindow.TakeAcks(OpenVpnPacketCodec.MaxAcks);
                if (rest.Count > 0) outgoing.Add(EncodeAck(rest));
            }
            foreach (byte[] wire in outgoing)
                _ = _transport.SendAsync(_wrap != null ? _wrap.Wrap(wire) : wire);
        }

        byte[] EncodeControl(uint id, byte[] payload, IReadOnlyList<uint> acks) => OpenVpnPacketCodec.EncodeControl(new OpenVpnControlPacket
        {
            Opcode = id == 0 ? OpenVpnOpcode.ControlHardResetClientV2 : OpenVpnOpcode.ControlV1,
            KeyId = _keyId,
            SessionId = _localSessionId,
            AckPacketIds = acks,
            RemoteSessionId = acks.Count > 0 ? _remoteSessionId : 0,
            PacketId = id,
            Payload = payload,
        });

        byte[] EncodeAck(IReadOnlyList<uint> acks) => OpenVpnPacketCodec.EncodeControl(new OpenVpnControlPacket
        {
            Opcode = OpenVpnOpcode.AckV1,
            KeyId = _keyId,
            SessionId = _localSessionId,
            AckPacketIds = acks,
            RemoteSessionId = _remoteSessionId,
        });

        static ulong GenerateSessionId()
        {
            byte[] sid = new byte[8];
            using (var rng = RandomNumberGenerator.Create()) rng.GetBytes(sid);
            return BinaryPrimitives.ReadUInt64BigEndian(sid);
        }

#if NET5_0_OR_GREATER
        static long DefaultClock() => Environment.TickCount64;
#else
        static readonly System.Diagnostics.Stopwatch _stopwatch = System.Diagnostics.Stopwatch.StartNew();
        static long DefaultClock() => _stopwatch.ElapsedMilliseconds;
#endif

        /// <inheritdoc/>
        public void Dispose()
        {
            lock (_sync) { if (_disposed) return; _disposed = true; }
            _transport.DatagramReceived -= OnDatagram;
            _timer?.Dispose();
            _ssl?.Dispose();
            _bridge.CompleteInbound();
            RemoteCertificate?.Dispose();
            _windowSlots.Dispose();
            _resetReceived.TrySetCanceled();
        }
    }
}
