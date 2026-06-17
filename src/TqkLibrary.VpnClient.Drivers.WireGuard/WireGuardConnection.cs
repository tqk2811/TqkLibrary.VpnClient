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
using TqkLibrary.VpnClient.Drivers.WireGuard.Enums;
using TqkLibrary.VpnClient.Drivers.WireGuard.Models;
using TqkLibrary.VpnClient.Drivers.WireGuard.Transport;
using TqkLibrary.VpnClient.WireGuard;
using TqkLibrary.VpnClient.WireGuard.Config;
using TqkLibrary.VpnClient.WireGuard.DataChannel;
using TqkLibrary.VpnClient.WireGuard.Enums;
using TqkLibrary.VpnClient.WireGuard.Handshake;
using TqkLibrary.VpnClient.WireGuard.Handshake.Models;
using TqkLibrary.VpnClient.WireGuard.Routing;
using TqkLibrary.VpnClient.WireGuard.Transport;

namespace TqkLibrary.VpnClient.Drivers.WireGuard
{
    /// <summary>
    /// A complete WireGuard client over a single UDP transport. It runs the <c>Noise_IKpsk2</c> handshake as the
    /// <b>initiator</b> against <b>each configured peer</b> (type-1 initiation + mac1 → type-2 response → transport
    /// keys), binding every peer's <see cref="WireGuardTransport"/> to a per-peer <see cref="WireGuardChannel"/> behind
    /// one stable <see cref="WireGuardMultiPeerChannel"/> (exposed through a <see cref="SwappablePacketChannel"/>). The
    /// data plane then crypto-routes each outbound packet to the peer whose allowed-ips cover the destination by
    /// longest-prefix match, and runs a per-peer <see cref="WireGuardPeerState"/> timer loop for keepalives and a
    /// make-before-break rekey (a fresh handshake on a new session index, that peer's channel swapped once it
    /// completes — the other peers untouched). Inbound datagrams are demuxed by message type: type-2 completes a
    /// pending handshake of any peer, type-3 feeds the cookie machinery, type-4 transport data is delivered to whichever
    /// peer's session owns its receiver index. A dead session (a handshake that could not complete within
    /// <c>REKEY_ATTEMPT_TIME</c>, or a transport fault) triggers the supervisor / auto-reconnect, mirroring the OpenVPN
    /// / IKEv2 drivers. Not a server — the responder role lives only in tests. The single-peer point-to-point case is
    /// just one peer with allowed-ips <c>0.0.0.0/0, ::/0</c>.
    /// </summary>
    public sealed class WireGuardConnection : ReconnectingVpnConnection<WireGuardConnectionState>, IDisposable, IAsyncDisposable
    {
        static readonly TimeSpan TimerTick = TimeSpan.FromMilliseconds(250);
        const string DriverNameConst = "wireguard";

        readonly string _host;
        readonly int _port;
        readonly WireGuardConfig _config;
        readonly IReadOnlyList<WireGuardPeer> _peerConfigs;
        readonly IWireGuardTransportFactory _transportFactory;
        readonly AddressFamilyPreference _addressFamilyPreference;
        readonly IHostResolver _hostResolver;
        readonly WireGuardTimers _timers;
        readonly TunnelConfig _tunnelConfig;
        readonly WireGuardCryptoRouter _router;

        IDatagramTransport? _transport;
        CancellationTokenSource? _loopCts;
        Task? _receiveTask;
        System.Threading.Timer? _timer;

        Peer[]? _peers;                          // one per configured peer; each owns its handshake/timer/transport state
        WireGuardMultiPeerChannel? _channel;     // stable inner of the facade across rekeys

        /// <summary>
        /// Creates a connection. <paramref name="config"/> is the static profile (one or more peers);
        /// <paramref name="transportFactory"/> opens the UDP socket (an in-process factory drives it offline).
        /// <paramref name="timers"/> overrides the whitepaper timer thresholds (mainly for tests); <paramref name="clock"/>
        /// supplies the millisecond clock (default: the system tick clock) — tests inject a deterministic one.
        /// <paramref name="loggerFactory"/> receives diagnostic traces (handshake/rekey/reconnect/drop); null logs to a
        /// no-op logger.
        /// </summary>
        public WireGuardConnection(string host, int port, WireGuardConfig config, IWireGuardTransportFactory transportFactory,
            WireGuardReconnectOptions? reconnectOptions = null,
            AddressFamilyPreference addressFamilyPreference = AddressFamilyPreference.Auto,
            IHostResolver? hostResolver = null,
            WireGuardTimers? timers = null,
            Func<long>? clock = null,
            ILoggerFactory? loggerFactory = null)
            : base(DriverNameConst, reconnectOptions ?? new WireGuardReconnectOptions(), clock, loggerFactory)
        {
            _host = host ?? throw new ArgumentNullException(nameof(host));
            _port = port;
            _config = config ?? throw new ArgumentNullException(nameof(config));
            _peerConfigs = config.EnumeratePeers();
            _transportFactory = transportFactory ?? throw new ArgumentNullException(nameof(transportFactory));
            _addressFamilyPreference = addressFamilyPreference;
            _hostResolver = hostResolver ?? DnsHostResolver.Default;
            _timers = timers ?? new WireGuardTimers(); // per-peer keepalive comes from each peer's config below
            _tunnelConfig = config.ToTunnelConfig();
            var allowed = new List<IReadOnlyList<string>>(_peerConfigs.Count);
            foreach (WireGuardPeer p in _peerConfigs) allowed.Add(p.AllowedIps);
            _router = WireGuardCryptoRouter.Build(allowed);
        }

        /// <summary>The static tunnel configuration from the config (address, DNS, allowed-ips as routes, MTU).</summary>
        public TunnelConfig Config => _tunnelConfig;

        /// <summary>The local tunnel IPv4 address, if configured.</summary>
        public IPAddress? AssignedAddress => _config.Address;

        /// <summary>Raised after a successful auto-reconnect.</summary>
        public event Action<WireGuardReconnectInfo>? Reconnected;

        /// <inheritdoc/>
        protected override WireGuardConnectionState DisconnectedState => WireGuardConnectionState.Disconnected;
        /// <inheritdoc/>
        protected override WireGuardConnectionState ConnectingState => WireGuardConnectionState.Connecting;
        /// <inheritdoc/>
        protected override WireGuardConnectionState ConnectedState => WireGuardConnectionState.Connected;
        /// <inheritdoc/>
        protected override WireGuardConnectionState ReconnectingState => WireGuardConnectionState.Reconnecting;

        /// <inheritdoc/>
        protected override void OnReconnected() => Reconnected?.Invoke(new WireGuardReconnectInfo());

        /// <summary>Runs the initial handshake (to every peer) and returns once the tunnel is carrying traffic.</summary>
        public Task ConnectAsync(CancellationToken cancellationToken = default) => ConnectCoreAsync(cancellationToken);

        // ---- one full tunnel attempt (reused by the first connect and every reconnect) ----

        /// <inheritdoc/>
        protected override async Task EstablishAsync(CancellationToken cancellationToken)
        {
            await CleanupAttemptResourcesAsync().ConfigureAwait(false);

            IPAddress serverIp = await _hostResolver.ResolveAsync(_host, _addressFamilyPreference, cancellationToken).ConfigureAwait(false);
            _loopCts = CancellationTokenSource.CreateLinkedTokenSource(LifetimeToken, cancellationToken);
            CancellationToken loopToken = _loopCts.Token;

            WireGuardTransportHandle handle = await _transportFactory
                .ConnectAsync(new IPEndPoint(serverIp, _port), cancellationToken).ConfigureAwait(false);
            _transport = handle.Datagram;
            handle.SetReceiver(OnInboundDatagram);

            // Start the receive pump (real UDP socket) once the handler is wired; loopback transports self-pump.
            if (handle.ReceivePump != null)
                _receiveTask = Task.Run(() => handle.ReceivePump(loopToken));

            // Build the per-peer state + the routing channel that fronts every peer's data channel.
            var channel = new WireGuardMultiPeerChannel(_router, _peerConfigs.Count, _config.Mtu,
                onNoRoute: () => Logger.LogPacketDropped(DriverName, VpnDropReason.NoRoute, "outbound packet matched no peer's allowed-ips"));
            _channel = channel;
            var peers = new Peer[_peerConfigs.Count];
            for (int i = 0; i < peers.Length; i++)
                peers[i] = new Peer(i, _peerConfigs[i], new WireGuardPeerState(TimersForPeer(_peerConfigs[i])));
            _peers = peers;

            // --- run an initiator handshake against every peer and start the timer loop before awaiting them ---
            long now = Now();
            foreach (Peer peer in peers)
            {
                Logger.LogHandshake(DriverName, $"Noise_IKpsk2 initiation sent to peer {peer.Index} (type-1 + mac1)");
                Session session = StartHandshake(peer);
                peer.Active = session;
                peer.State.OnHandshakeInitiated(now);
            }

            // Start the timer loop *before* awaiting completion so an unanswered initiation (e.g. one a responder met
            // with a cookie-reply) is resent with a valid mac2 by the ResendHandshake path while we wait.
            StartTimerLoop();

            // Every peer's handshake must complete within REKEY_ATTEMPT_TIME for the tunnel to be considered up.
            foreach (Peer peer in peers)
            {
                Session session = peer.Active!;
                bool completed = await session.WaitForHandshakeAsync(_timers.RekeyAttemptTimeMs, cancellationToken).ConfigureAwait(false);
                if (!completed)
                {
                    StopAttemptLoop();
                    Logger.LogHandshakeFailed(DriverName, $"no type-2 response from peer {peer.Index} within REKEY_ATTEMPT_TIME");
                    throw new VpnConnectionException($"WireGuard handshake timed out: no type-2 response from peer {peer.Index}.");
                }
                BindSession(peer, session);
            }

            Facade.SetInner(channel);
            Logger.LogHandshakeCompleted(DriverName);
            MarkConnected();
        }

        // The per-peer timers reuse the shared thresholds but carry that peer's own persistent-keepalive interval.
        WireGuardTimers TimersForPeer(WireGuardPeer peer) => new WireGuardTimers(
            persistentKeepaliveSeconds: peer.PersistentKeepaliveSeconds,
            rekeyAfterTimeSeconds: (int)(_timers.RekeyAfterTimeMs / 1000),
            rejectAfterTimeSeconds: (int)(_timers.RejectAfterTimeMs / 1000),
            rekeyAttemptTimeSeconds: (int)(_timers.RekeyAttemptTimeMs / 1000),
            rekeyTimeoutSeconds: (int)(_timers.RekeyTimeoutMs / 1000),
            keepaliveTimeoutSeconds: (int)(_timers.KeepaliveTimeoutMs / 1000),
            rekeyAfterMessages: _timers.RekeyAfterMessages,
            rejectAfterMessages: _timers.RejectAfterMessages);

        // ---- handshake start: allocate a local index, send the initiation with mac1 (to one peer) ----

        Session StartHandshake(Peer peer)
        {
            var handshake = new WireGuardHandshake(
                BuildLocalStatic(), peer.Config.PublicKey, peer.Config.PresharedKey);
            uint localIndex = NextIndex();
            var session = new Session(handshake, localIndex);

            WireGuardInitiationMessage init = handshake.CreateInitiation(localIndex);
            byte[] wire = new WireGuardMessageCodec().EncodeInitiation(init);
            handshake.StampOutgoingMacs(wire);
            _ = SendAsync(wire); // fire-and-forget; a missed initiation is resent by the timer loop
            return session;
        }

        WireGuardKeyPair BuildLocalStatic()
        {
            byte[] priv = _config.PrivateKey ?? throw new VpnConnectionException("WireGuard config has no PrivateKey.");
            var dh = new TqkLibrary.VpnClient.Crypto.Noise.Curve25519DhGroup();
            return new WireGuardKeyPair { PrivateKey = (byte[])priv.Clone(), PublicKey = dh.DerivePublicValue(priv) };
        }

        // Bind a completed handshake's transport to a fresh per-peer channel and install it behind the routing channel.
        void BindSession(Peer peer, Session session)
        {
            WireGuardTransportKeys keys = session.Handshake.DeriveTransportKeys();
            var transport = new WireGuardTransport(keys, session.PeerIndex, session.LocalIndex);
            long now = Now();
            var channel = new WireGuardChannel(transport, SendChannelAsync, _config.Mtu,
                onPacketSealed: () => peer.State.OnDataSent(Now()),
                onPacketReceived: () => peer.State.OnDataReceived(Now()));
            session.Channel = channel;
            peer.State.OnHandshakeCompleted(now);
            _channel?.SetPeerChannel(peer.Index, channel);
        }

        ValueTask SendChannelAsync(ReadOnlyMemory<byte> wire, CancellationToken cancellationToken)
        {
            IDatagramTransport? transport = _transport;
            return transport?.SendAsync(wire, cancellationToken) ?? default;
        }

        Task SendAsync(ReadOnlyMemory<byte> wire)
        {
            IDatagramTransport? transport = _transport;
            return transport is null ? Task.CompletedTask : transport.SendAsync(wire).AsTask();
        }

        // ---- inbound demux: route by message type (response / cookie-reply / transport-data) ----

        void OnInboundDatagram(ReadOnlyMemory<byte> datagram)
        {
            ReadOnlySpan<byte> span = datagram.Span;
            if (span.Length < 1) return;
            byte type = span[0];

            if (type == WireGuardConstants.MessageTypeResponse) { OnResponse(span); return; }
            if (type == WireGuardConstants.MessageTypeCookieReply) { OnCookieReply(span); return; }
            if (type == WireGuardConstants.MessageTypeTransportData) { OnTransportData(span); return; }
            // type-1 initiation is the server's job (we are the initiator); drop anything else.
        }

        void OnResponse(ReadOnlySpan<byte> span)
        {
            var codec = new WireGuardMessageCodec();
            if (!codec.TryDecodeResponse(span, out WireGuardResponseMessage response))
            {
                Logger.LogPacketDropped(DriverName, VpnDropReason.Malformed, "type-2 response failed to decode");
                return;
            }

            // The response addresses the session whose local (sender) index it echoes in ReceiverIndex.
            (Peer peer, Session session)? match = MatchPendingHandshake(response.ReceiverIndex);
            if (match is null)
            {
                Logger.LogPacketDropped(DriverName, VpnDropReason.Unexpected, "type-2 response with no matching pending handshake");
                return;
            }
            Peer target = match.Value.peer;
            Session targetSession = match.Value.session;

            if (!targetSession.Handshake.VerifyIncomingMac1(span)) // forged/foreign — drop before the DH work
            {
                Logger.LogPacketDropped(DriverName, VpnDropReason.AuthFailed, "type-2 response mac1 mismatch");
                return;
            }
            if (!targetSession.Handshake.ConsumeResponse(response)) // bad tag / PSK mismatch
            {
                Logger.LogPacketDropped(DriverName, VpnDropReason.DecryptFailed, "type-2 response AEAD/PSK mismatch");
                return;
            }

            targetSession.PeerIndex = response.SenderIndex;
            targetSession.CompleteHandshake();
            Logger.LogHandshake(DriverName, $"type-2 response from peer {target.Index} consumed; transport keys derived");

            // A rekey handshake (pending while the old session keeps running): swap that peer's channel make-before-break.
            if (target.Pending == targetSession)
            {
                target.Active = targetSession;
                target.Pending = null;
                BindSession(target, targetSession);
                Logger.LogRekey(DriverName, $"peer {target.Index} channel swapped to new session (make-before-break)");
            }
        }

        (Peer peer, Session session)? MatchPendingHandshake(uint localIndex)
        {
            Peer[]? peers = _peers;
            if (peers is null) return null;
            foreach (Peer peer in peers)
            {
                if (peer.Pending is { } p && p.LocalIndex == localIndex && !p.HandshakeDone) return (peer, p);
                if (peer.Active is { } a && a.LocalIndex == localIndex && !a.HandshakeDone) return (peer, a);
            }
            return null;
        }

        void OnCookieReply(ReadOnlySpan<byte> span)
        {
            var codec = new WireGuardMessageCodec();
            if (!codec.TryDecodeCookieReply(span, out WireGuardCookieReplyMessage reply)) return;
            (Peer peer, Session session)? match = MatchPendingHandshake(reply.ReceiverIndex);
            match?.session.Handshake.ConsumeCookieReply(reply); // caches the cookie → mac2 on the next (resent) initiation
        }

        void OnTransportData(ReadOnlySpan<byte> span)
        {
            // Deliver to whichever live peer session owns the receiver index in the header.
            WireGuardMultiPeerChannel? channel = _channel;
            if (channel != null && channel.Deliver(span) >= 0) return;
            // A late packet for a just-replaced previous session (or a counter outside the replay window / a bad tag)
            // could not be delivered — record it as a drop.
            Logger.LogPacketDropped(DriverName, VpnDropReason.DecryptFailed, "type-4 transport packet not delivered (decrypt/replay/no session)");
        }

        // ---- timer loop: keepalive + make-before-break rekey, driven per peer by WireGuardPeerState ----

        // Distinct from the base's IsRunning ("tunnel is up"): the timer loop runs from the moment the initiations are
        // sent (before the handshakes complete) so an unanswered initiation is resent — so it has its own guard.
        volatile bool _timerRunning;

        void StartTimerLoop()
        {
            _timerRunning = true;
            _timer = new System.Threading.Timer(_ => _ = TimerTickAsync(), null, TimerTick, TimerTick);
        }

        async Task TimerTickAsync()
        {
            if (!_timerRunning) return;
            Peer[]? peers = _peers;
            if (peers is null) return;

            long now = Now();
            foreach (Peer peer in peers)
            {
                if (!_timerRunning) return;
                WireGuardSessionAction action = peer.State.Evaluate(now);
                switch (action)
                {
                    case WireGuardSessionAction.SendKeepalive:
                        try
                        {
                            WireGuardChannel? channel = peer.Active?.Channel;
                            if (channel != null)
                            {
                                await channel.SendKeepaliveAsync().ConfigureAwait(false);
                                Logger.LogKeepalive(DriverName, $"sent empty type-4 keepalive to peer {peer.Index}");
                            }
                        }
                        catch { /* a missed keepalive is harmless; the peer's own timer covers liveness */ }
                        break;

                    case WireGuardSessionAction.InitiateHandshake:
                        StartRekey(peer, now);
                        break;

                    case WireGuardSessionAction.ResendHandshake:
                        ResendHandshake(peer, now);
                        break;

                    case WireGuardSessionAction.AbandonHandshake:
                    case WireGuardSessionAction.SessionDead:
                        OnLinkLost($"WireGuard peer {peer.Index} session dead: handshake could not be (re)established within REKEY_ATTEMPT_TIME.");
                        return; // one dead peer tears the whole attempt down; stop evaluating the rest
                }
            }
        }

        // Begin a make-before-break rekey for one peer: a new handshake on a new index runs while the old session keeps carrying data.
        void StartRekey(Peer peer, long now)
        {
            if (peer.Pending != null) return; // already rekeying this peer
            Logger.LogRekey(DriverName, $"initiating make-before-break rekey handshake for peer {peer.Index}");
            Session rekey = StartHandshake(peer);
            peer.Pending = rekey;
            peer.State.OnHandshakeInitiated(now);
        }

        void ResendHandshake(Peer peer, long now)
        {
            Session? handshaking = peer.Pending ?? (peer.Active is { HandshakeDone: false } a ? a : null);
            if (handshaking is null) return;
            WireGuardInitiationMessage init = handshaking.Handshake.CreateInitiation(handshaking.LocalIndex);
            byte[] wire = new WireGuardMessageCodec().EncodeInitiation(init);
            handshaking.Handshake.StampOutgoingMacs(wire); // includes mac2 if a cookie-reply was consumed
            _ = SendAsync(wire);
            peer.State.OnHandshakeInitiated(now);
        }

        // ---- link-loss handling + auto-reconnect supervisor live in ReconnectingVpnConnection (roadmap F.6). ----
        // The session-dead path above calls the inherited OnLinkLost, which arms the shared ReconnectLoopAsync.

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

            _peers = null;
            _channel = null;
        }

        /// <inheritdoc/>
        protected override void StopAttemptLoop()
        {
            _timerRunning = false;
            _timer?.Dispose();
            _timer = null;
        }

        // ---- helpers ----

        static uint NextIndex()
        {
            byte[] b = new byte[4];
#if NET6_0_OR_GREATER
            RandomNumberGenerator.Fill(b);
#else
            using (var rng = RandomNumberGenerator.Create()) rng.GetBytes(b);
#endif
            return BitConverter.ToUInt32(b, 0);
        }

        /// <inheritdoc/>
        public async ValueTask DisposeAsync()
        {
            try { await DisconnectAsync().ConfigureAwait(false); } catch { }
            await DisposeCoreAsync().ConfigureAwait(false);
        }

        /// <inheritdoc/>
        public void Dispose() => DisposeAsync().AsTask().GetAwaiter().GetResult();

        /// <summary>One configured peer: its static config, its timer state machine, and its current (and any pending
        /// rekey) session. A rekey produces a second <see cref="Session"/> in <see cref="Pending"/> that replaces
        /// <see cref="Active"/> once its handshake completes.</summary>
        sealed class Peer
        {
            public Peer(int index, WireGuardPeer config, WireGuardPeerState state)
            {
                Index = index;
                Config = config;
                State = state;
            }

            public int Index { get; }
            public WireGuardPeer Config { get; }
            public WireGuardPeerState State { get; }
            public Session? Active { get; set; }    // the live session feeding this peer's channel
            public Session? Pending { get; set; }   // a make-before-break rekey handshake in flight (no transport yet)
        }

        /// <summary>One handshake/transport generation for one peer: the Noise state machine, the two session indices,
        /// and (once the handshake completes) the live data channel. A rekey produces a second instance that replaces
        /// the first.</summary>
        sealed class Session
        {
            readonly TaskCompletionSource<bool> _handshakeDone = new(TaskCreationOptions.RunContinuationsAsynchronously);

            public Session(WireGuardHandshake handshake, uint localIndex)
            {
                Handshake = handshake;
                LocalIndex = localIndex;
            }

            public WireGuardHandshake Handshake { get; }
            public uint LocalIndex { get; }
            public uint PeerIndex { get; set; }
            public WireGuardChannel? Channel { get; set; }
            public bool HandshakeDone { get; private set; }

            public void CompleteHandshake()
            {
                HandshakeDone = true;
                _handshakeDone.TrySetResult(true);
            }

            public async Task<bool> WaitForHandshakeAsync(long timeoutMs, CancellationToken cancellationToken)
            {
                using var timeout = new CancellationTokenSource(timeoutMs > 0 ? (int)Math.Min(timeoutMs, int.MaxValue) : -1);
                using var linked = CancellationTokenSource.CreateLinkedTokenSource(timeout.Token, cancellationToken);
                using (linked.Token.Register(() => _handshakeDone.TrySetResult(false)))
                    return await _handshakeDone.Task.ConfigureAwait(false);
            }
        }
    }
}
