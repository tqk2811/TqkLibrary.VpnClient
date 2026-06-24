using System.Net;
using System.Security.Cryptography;
using Microsoft.Extensions.Logging;
using TqkLibrary.VpnClient.Abstractions.Channels;
using TqkLibrary.VpnClient.Abstractions.Channels.Interfaces;
using TqkLibrary.VpnClient.Abstractions.Diagnostics.Enums;
using TqkLibrary.VpnClient.Abstractions.Diagnostics.Extensions;
using TqkLibrary.VpnClient.Abstractions.Drivers;
using TqkLibrary.VpnClient.Abstractions.Drivers.Models;
using TqkLibrary.VpnClient.Abstractions.Net;
using TqkLibrary.VpnClient.Abstractions.Transport.Interfaces;
using TqkLibrary.VpnClient.Drivers.Core;
using TqkLibrary.VpnClient.Drivers.Nebula.Config;
using TqkLibrary.VpnClient.Drivers.Nebula.DataChannel;
using TqkLibrary.VpnClient.Drivers.Nebula.Enums;
using TqkLibrary.VpnClient.Drivers.Nebula.Transport;
using TqkLibrary.VpnClient.Nebula.Certificate;
using TqkLibrary.VpnClient.Nebula.Certificate.Models;
using TqkLibrary.VpnClient.Nebula.Handshake;
using TqkLibrary.VpnClient.Nebula.Handshake.Models;
using TqkLibrary.VpnClient.Nebula.Packet;
using TqkLibrary.VpnClient.Nebula.Packet.Enums;
using TqkLibrary.VpnClient.Nebula.Packet.Models;

namespace TqkLibrary.VpnClient.Drivers.Nebula
{
    /// <summary>
    /// A complete Nebula client. It runs the <c>Noise_IX_25519_AESGCM_SHA256</c> handshake as the <b>initiator</b>
    /// against the configured peer (a type-0 handshake-stage-1 packet → a type-0 stage-2 response → AES-256-GCM
    /// transport keys), verifies the peer's certificate against the network CA, then binds a
    /// <see cref="NebulaTransport"/> to a <see cref="NebulaChannel"/> behind a stable <see cref="SwappablePacketChannel"/>.
    /// The data plane seals each outbound IP packet into a <c>Message</c> (type-1) datagram (the 16-byte header is the
    /// AEAD associated data, its <c>RemoteIndex</c> = the peer's session index, its <c>MessageCounter</c> = the nonce).
    /// A timer loop keeps the tunnel alive (a periodic make-before-break re-handshake) and the supervisor /
    /// auto-reconnect (roadmap F.6) re-establishes a dead tunnel, mirroring the WireGuard / IKEv2 drivers. Not a server —
    /// the responder role lives only in tests. Lighthouse discovery is bypassed: the peer's UDP endpoint is configured
    /// directly (a <c>static_host_map</c> entry / the connect host:port), which is enough for the point-to-point case.
    /// </summary>
    public sealed class NebulaConnection : ReconnectingVpnConnection<NebulaConnectionState>, IDisposable, IAsyncDisposable
    {
        static readonly TimeSpan TimerTick = TimeSpan.FromMilliseconds(250);
        const string DriverNameConst = "nebula";

        readonly string _host;
        readonly int _port;
        readonly NebulaConfig _config;
        readonly INebulaTransportFactory _transportFactory;
        readonly AddressFamilyPreference _addressFamilyPreference;
        readonly IHostResolver _hostResolver;
        readonly TunnelConfig _tunnelConfig;
        readonly long _rehandshakeIntervalMs;
        readonly long _handshakeTimeoutMs;

        readonly NebulaCertificateCodec _certCodec = new();
        readonly NebulaCertificateValidator _certValidator = new();
        readonly NebulaHandshakePayloadCodec _payloadCodec = new();
        readonly NebulaHeaderCodec _headerCodec = new();

        readonly byte[] _caPublicKey;          // the CA's Ed25519 verification key
        readonly byte[] _strippedClientCert;   // our marshaled cert with the public-key field (7) stripped

        IDatagramTransport? _transport;
        CancellationTokenSource? _loopCts;
        Task? _receiveTask;
        System.Threading.Timer? _timer;
        volatile bool _timerRunning;

        readonly object _sessionLock = new();
        Session? _active;       // the live session carrying data
        Session? _pending;      // an in-flight re-handshake (make-before-break)
        SwappablePacketChannel? _innerFacadeOwner; // never null after a successful connect; the driver-level facade

        /// <summary>
        /// Creates a connection. <paramref name="config"/> is the static profile; <paramref name="transportFactory"/>
        /// opens the UDP socket (an in-process factory drives it offline). <paramref name="rehandshakeIntervalMs"/>
        /// drives the periodic make-before-break re-handshake (default 5 minutes, like nebula's handshake renewal);
        /// <paramref name="handshakeTimeoutMs"/> bounds one handshake attempt. <paramref name="clock"/> supplies the
        /// millisecond clock (tests inject a deterministic one).
        /// </summary>
        public NebulaConnection(string host, int port, NebulaConfig config, INebulaTransportFactory transportFactory,
            NebulaReconnectOptions? reconnectOptions = null,
            AddressFamilyPreference addressFamilyPreference = AddressFamilyPreference.Auto,
            IHostResolver? hostResolver = null,
            long rehandshakeIntervalMs = 5 * 60 * 1000,
            long handshakeTimeoutMs = 10 * 1000,
            Func<long>? clock = null,
            ILoggerFactory? loggerFactory = null)
            : base(DriverNameConst, reconnectOptions ?? new NebulaReconnectOptions(), clock, loggerFactory)
        {
            _host = host ?? throw new ArgumentNullException(nameof(host));
            _port = port;
            _config = config ?? throw new ArgumentNullException(nameof(config));
            _transportFactory = transportFactory ?? throw new ArgumentNullException(nameof(transportFactory));
            _addressFamilyPreference = addressFamilyPreference;
            _hostResolver = hostResolver ?? DnsHostResolver.Default;
            _tunnelConfig = config.ToTunnelConfig();
            _rehandshakeIntervalMs = rehandshakeIntervalMs;
            _handshakeTimeoutMs = handshakeTimeoutMs;

            _caPublicKey = config.CaCertificate.Details.PublicKey
                ?? throw new VpnConnectionException("Nebula CA certificate has no public key.");
            _strippedClientCert = BuildStrippedCert(config.ClientCertificate, _certCodec);
        }

        /// <summary>The static tunnel configuration (overlay address, DNS, routes, MTU).</summary>
        public TunnelConfig Config => _tunnelConfig;

        /// <summary>The local overlay (tunnel) IPv4 address, if configured / derivable.</summary>
        public IPAddress? AssignedAddress => _config.ResolveOverlayAddress();

        /// <inheritdoc/>
        protected override NebulaConnectionState DisconnectedState => NebulaConnectionState.Disconnected;
        /// <inheritdoc/>
        protected override NebulaConnectionState ConnectingState => NebulaConnectionState.Connecting;
        /// <inheritdoc/>
        protected override NebulaConnectionState ConnectedState => NebulaConnectionState.Connected;
        /// <inheritdoc/>
        protected override NebulaConnectionState ReconnectingState => NebulaConnectionState.Reconnecting;

        /// <summary>Runs the initial handshake and returns once the tunnel is carrying traffic.</summary>
        public Task ConnectAsync(CancellationToken cancellationToken = default) => ConnectCoreAsync(cancellationToken);

        // ---- one full tunnel attempt (reused by the first connect and every reconnect) ----

        /// <inheritdoc/>
        protected override async Task EstablishAsync(CancellationToken cancellationToken)
        {
            await CleanupAttemptResourcesAsync().ConfigureAwait(false);

            IPEndPoint endpoint = await ResolvePeerEndpointAsync(cancellationToken).ConfigureAwait(false);
            _loopCts = CancellationTokenSource.CreateLinkedTokenSource(LifetimeToken, cancellationToken);
            CancellationToken loopToken = _loopCts.Token;

            NebulaTransportHandle handle = await _transportFactory.ConnectAsync(endpoint, cancellationToken).ConfigureAwait(false);
            handle.SetReceiver(OnInboundDatagram);
            _transport = handle.Datagram;
            MarkRunning(); // honour a drop detected while the handshake is still in flight
            if (handle.ReceivePump != null)
                _receiveTask = Task.Run(() => handle.ReceivePump(loopToken));

            // Run the initiator handshake and wait for the peer's stage-2 response (transport keys derived).
            Session session = StartHandshake();
            lock (_sessionLock) _active = session;
            StartTimerLoop();

            bool completed = await session.WaitForHandshakeAsync(_handshakeTimeoutMs, cancellationToken).ConfigureAwait(false);
            if (!completed)
            {
                StopAttemptLoop();
                Logger.LogHandshakeFailed(DriverName, "no stage-2 response from nebula peer within the handshake timeout");
                throw new VpnConnectionException("Nebula handshake timed out: no stage-2 response from the peer.");
            }

            BindSession(session);
            Facade.SetInner(session.Channel!);
            _innerFacadeOwner = Facade;
            Logger.LogHandshakeCompleted(DriverName);
            MarkConnected();
        }

        async Task<IPEndPoint> ResolvePeerEndpointAsync(CancellationToken cancellationToken)
        {
            if (_config.PeerEndpoint is not null) return _config.PeerEndpoint;
            IPAddress ip = await _hostResolver.ResolveAsync(_host, _addressFamilyPreference, cancellationToken).ConfigureAwait(false);
            return new IPEndPoint(ip, _port);
        }

        // ---- handshake: build the Noise IX message-1 payload, send it, wait for the stage-2 response ----

        Session StartHandshake()
        {
            uint initiatorIndex = NextIndex();
            var details = new NebulaHandshakeDetails
            {
                Cert = _strippedClientCert,
                InitiatorIndex = initiatorIndex,
                Time = (ulong)DateTimeOffset.UtcNow.ToUnixTimeMilliseconds() * 1_000_000UL,
            };
            byte[] noisePayload = _payloadCodec.Marshal(details);

            var handshake = new NebulaNoiseIxHandshake(_config.ClientX25519PrivateKey);
            byte[] noiseMsg1 = handshake.CreateInitiation(noisePayload);

            var header = new NebulaHeader
            {
                Version = 1,
                Type = NebulaMessageType.Handshake,
                SubType = (byte)NebulaMessageSubType.HandshakeIxPsk0,
                Reserved = 0,
                RemoteIndex = 0, // unknown until the peer answers
                MessageCounter = 1,
            };
            byte[] packet = _headerCodec.EncodePacket(header, noiseMsg1);
            var session = new Session(handshake, initiatorIndex)
            {
                LastInitiationPacket = packet,
                HandshakeStarted = Now(),
            };

            Logger.LogHandshake(DriverName, $"Noise IX stage-1 sent (initiatorIndex=0x{initiatorIndex:x8})");
            _ = SendAsync(packet); // fire-and-forget; an unanswered stage-1 is resent by the timer loop
            return session;
        }

        // Bind a completed handshake's transport keys to a fresh channel that seals through the UDP socket.
        void BindSession(Session session)
        {
            (byte[] sendKey, byte[] receiveKey) = session.Handshake.Split();
            var transport = new NebulaTransport(sendKey, receiveKey, session.ResponderIndex, session.InitiatorIndex);
            var channel = new NebulaChannel(transport,
                (wire, ct) => SendAsync(wire, ct), _config.Mtu,
                onPacketSealed: () => session.LastActivity = Now(),
                onPacketReceived: () => session.LastActivity = Now());
            session.Channel = channel;
            session.LastActivity = Now();
        }

        ValueTask SendAsync(ReadOnlyMemory<byte> wire, CancellationToken cancellationToken = default)
        {
            IDatagramTransport? transport = _transport;
            if (transport is null) return default;
            return SendCoreAsync(transport, wire, cancellationToken);
        }

        async ValueTask SendCoreAsync(IDatagramTransport transport, ReadOnlyMemory<byte> wire, CancellationToken cancellationToken)
        {
            try { await transport.SendAsync(wire, cancellationToken).ConfigureAwait(false); }
            catch (Exception ex)
            {
                Logger.LogPacketDropped(DriverName, VpnDropReason.Unexpected, $"failed to send datagram: {ex.GetType().Name}: {ex.Message}");
            }
        }

        // ---- inbound demux: route by Nebula message type ----

        void OnInboundDatagram(ReadOnlyMemory<byte> datagram)
        {
            ReadOnlySpan<byte> span = datagram.Span;
            if (!_headerCodec.TryDecode(span, out NebulaHeader header)) return;

            switch (header.Type)
            {
                case NebulaMessageType.Handshake: OnHandshakeResponse(span, header); break;
                case NebulaMessageType.Message: OnMessage(span); break;
                case NebulaMessageType.RecvError:
                    Logger.LogPacketDropped(DriverName, VpnDropReason.Unexpected, "peer sent RecvError (no matching tunnel); re-handshake will recover");
                    break;
                // Test / LightHouse / Control are not consumed here (point-to-point with a static endpoint).
            }
        }

        void OnHandshakeResponse(ReadOnlySpan<byte> span, NebulaHeader header)
        {
            // The stage-2 response addresses the session whose initiator index it echoes in RemoteIndex.
            Session? session = MatchPendingHandshake(header.RemoteIndex);
            if (session is null)
            {
                Logger.LogPacketDropped(DriverName, VpnDropReason.Unexpected, "handshake stage-2 with no matching pending session");
                return;
            }

            byte[] noiseMsg2 = span.Slice(NebulaHeader.Size).ToArray();
            if (!session.Handshake.ConsumeResponse(noiseMsg2, out byte[] respPayload))
            {
                Logger.LogPacketDropped(DriverName, VpnDropReason.DecryptFailed, "handshake stage-2 AEAD/transcript mismatch");
                return;
            }

            NebulaHandshakeDetails respDetails = _payloadCodec.Unmarshal(respPayload);
            if (!VerifyResponderCert(session, respDetails))
            {
                Logger.LogHandshakeFailed(DriverName, "responder certificate failed to verify against the CA");
                return;
            }

            session.ResponderIndex = respDetails.ResponderIndex;
            session.HandshakeCompletedAt = Now();
            session.CompleteHandshake();
            Logger.LogHandshake(DriverName, $"handshake stage-2 consumed (responderIndex=0x{respDetails.ResponderIndex:x8}); transport keys derived");

            // A re-handshake (pending while the old session keeps running): swap the channel make-before-break.
            lock (_sessionLock)
            {
                if (_pending == session)
                {
                    BindSession(session);
                    _active = session;
                    _pending = null;
                    _innerFacadeOwner?.SetInner(session.Channel!);
                    Logger.LogRekey(DriverName, "channel swapped to the new session (make-before-break)");
                }
            }
        }

        bool VerifyResponderCert(Session session, NebulaHandshakeDetails respDetails)
        {
            byte[]? respStaticPub = session.Handshake.RemoteStaticPublic;
            if (respStaticPub is null || respDetails.Cert.Length == 0) return false;
            NebulaCertificate respCert = _certCodec.UnmarshalCertificate(respDetails.Cert, out _);
            respCert.Details.PublicKey = respStaticPub; // recombine the static pubkey carried by the Noise s token
            byte[] recombinedDetails = _certCodec.MarshalDetails(respCert.Details);
            return _certValidator.VerifySignature(respCert, recombinedDetails, _caPublicKey);
        }

        Session? MatchPendingHandshake(uint initiatorIndex)
        {
            lock (_sessionLock)
            {
                if (_pending is { } p && p.InitiatorIndex == initiatorIndex && !p.HandshakeDone) return p;
                if (_active is { } a && a.InitiatorIndex == initiatorIndex && !a.HandshakeDone) return a;
                return null;
            }
        }

        void OnMessage(ReadOnlySpan<byte> span)
        {
            // Deliver to whichever live session owns the local index in the header.
            Session? active, pending;
            lock (_sessionLock) { active = _active; pending = _pending; }
            if (active?.Channel != null && active.Channel.Deliver(span)) return;
            if (pending?.Channel != null && pending.Channel.Deliver(span)) return;
            Logger.LogPacketDropped(DriverName, VpnDropReason.DecryptFailed, "type-1 message not delivered (decrypt/replay/no session)");
        }

        // ---- timer loop: resend an unanswered stage-1, drive a periodic make-before-break re-handshake ----

        void StartTimerLoop()
        {
            _timerRunning = true;
            _timer = new System.Threading.Timer(_ => _ = TimerTickAsync(), null, TimerTick, TimerTick);
        }

        async Task TimerTickAsync()
        {
            if (!_timerRunning) return;
            long now = Now();

            Session? active, pending;
            lock (_sessionLock) { active = _active; pending = _pending; }

            // Resend an unanswered stage-1 while the initial handshake is still pending.
            if (active is { HandshakeDone: false } && pending is null)
            {
                if (now - active.HandshakeStarted > 1000) // ~1s between resends
                {
                    active.HandshakeStarted = now;
                    ResendHandshake(active);
                }
                return;
            }

            if (active is not { HandshakeDone: true }) return;

            // Periodic make-before-break re-handshake keeps the tunnel keys fresh and the peer's session alive.
            if (pending is null && now - active.HandshakeCompletedAt >= _rehandshakeIntervalMs)
            {
                Logger.LogRekey(DriverName, "initiating make-before-break re-handshake");
                Session rekey = StartHandshake();
                lock (_sessionLock) _pending = rekey;
                return;
            }

            // Abandon a stalled re-handshake (keep the old session running; try again next interval).
            if (pending is { HandshakeDone: false } && now - pending.HandshakeStarted > _handshakeTimeoutMs)
            {
                Logger.LogPacketDropped(DriverName, VpnDropReason.Unexpected, "re-handshake stalled; abandoning and keeping the current session");
                lock (_sessionLock) { if (_pending == pending) _pending = null; }
            }
            await Task.CompletedTask.ConfigureAwait(false);
        }

        void ResendHandshake(Session session)
        {
            // The Noise transcript is one-shot, so a resend reuses the already-built stage-1 packet.
            if (session.LastInitiationPacket is { } packet) _ = SendAsync(packet);
        }

        // ---- teardown ----

        /// <inheritdoc/>
        protected override async Task CleanupAttemptResourcesAsync()
        {
            StopAttemptLoop();

            CancellationTokenSource? loop = _loopCts;
            _loopCts = null;
            try { loop?.Cancel(); } catch { }

            Task? receive = _receiveTask;
            _receiveTask = null;
            if (receive != null) { try { await receive.ConfigureAwait(false); } catch { } }
            loop?.Dispose();

            IDatagramTransport? transport = _transport;
            _transport = null;
            if (transport != null) { try { await transport.DisposeAsync().ConfigureAwait(false); } catch { } }

            lock (_sessionLock) { _active = null; _pending = null; }
        }

        /// <inheritdoc/>
        protected override void StopAttemptLoop()
        {
            _timerRunning = false;
            _timer?.Dispose();
            _timer = null;
        }

        /// <inheritdoc/>
        public override async Task DisconnectAsync(CancellationToken cancellationToken = default)
            => await DisconnectCoreAsync().ConfigureAwait(false);

        /// <inheritdoc/>
        public async ValueTask DisposeAsync()
        {
            await DisconnectCoreAsync().ConfigureAwait(false);
            await CleanupAttemptResourcesAsync().ConfigureAwait(false);
            await DisposeCoreAsync().ConfigureAwait(false);
        }

        /// <inheritdoc/>
        public void Dispose() => DisposeAsync().AsTask().GetAwaiter().GetResult();

        // ---- helpers ----

        // Build the cert to embed in the handshake payload: the same details but with the public-key field (7)
        // stripped — the Noise s token already carries the static pubkey, so nebula removes field 7 from the payload.
        static byte[] BuildStrippedCert(NebulaCertificate clientCert, NebulaCertificateCodec codec)
        {
            var stripped = new NebulaCertificate
            {
                Details = new NebulaCertificateDetails
                {
                    Name = clientCert.Details.Name,
                    Ips = clientCert.Details.Ips,
                    Subnets = clientCert.Details.Subnets,
                    Groups = clientCert.Details.Groups,
                    NotBefore = clientCert.Details.NotBefore,
                    NotAfter = clientCert.Details.NotAfter,
                    PublicKey = Array.Empty<byte>(), // stripped
                    IsCa = clientCert.Details.IsCa,
                    Issuer = clientCert.Details.Issuer,
                    Curve = clientCert.Details.Curve,
                },
                Signature = clientCert.Signature,
            };
            return codec.MarshalCertificate(stripped);
        }

        static uint NextIndex()
        {
            byte[] b = new byte[4];
#if NET6_0_OR_GREATER
            RandomNumberGenerator.Fill(b);
#else
            using var rng = RandomNumberGenerator.Create();
            rng.GetBytes(b);
#endif
            uint v = ((uint)b[0] << 24) | ((uint)b[1] << 16) | ((uint)b[2] << 8) | b[3];
            return v == 0 ? 1u : v; // 0 is reserved (means "unknown")
        }

        /// <summary>One handshake/session: its initiator/responder indices, the Noise state, and the bound channel.</summary>
        sealed class Session
        {
            readonly TaskCompletionSource<bool> _handshakeDone = new(TaskCreationOptions.RunContinuationsAsynchronously);
            volatile bool _done;

            public Session(NebulaNoiseIxHandshake handshake, uint initiatorIndex)
            {
                Handshake = handshake;
                InitiatorIndex = initiatorIndex;
            }

            public NebulaNoiseIxHandshake Handshake { get; }
            public uint InitiatorIndex { get; }
            public uint ResponderIndex { get; set; }
            public NebulaChannel? Channel { get; set; }
            public bool HandshakeDone => _done;
            public long HandshakeStarted { get; set; }
            public long HandshakeCompletedAt { get; set; }
            public long LastActivity { get; set; }
            public byte[]? LastInitiationPacket { get; set; }

            public void CompleteHandshake() { _done = true; _handshakeDone.TrySetResult(true); }

            public async Task<bool> WaitForHandshakeAsync(long timeoutMs, CancellationToken cancellationToken)
            {
                using var timeoutCts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
                timeoutCts.CancelAfter(TimeSpan.FromMilliseconds(timeoutMs));
                var tcs = new TaskCompletionSource<bool>(TaskCreationOptions.RunContinuationsAsynchronously);
                using (timeoutCts.Token.Register(() => tcs.TrySetResult(false)))
                {
                    Task completed = await Task.WhenAny(_handshakeDone.Task, tcs.Task).ConfigureAwait(false);
                    return completed == _handshakeDone.Task && _handshakeDone.Task.Result;
                }
            }
        }
    }
}
