using System.Net;
using Microsoft.Extensions.Logging;
using TqkLibrary.VpnClient.Abstractions.Channels;
using TqkLibrary.VpnClient.Abstractions.Diagnostics.Enums;
using TqkLibrary.VpnClient.Abstractions.Diagnostics.Extensions;
using TqkLibrary.VpnClient.Abstractions.Drivers;
using TqkLibrary.VpnClient.Abstractions.Drivers.Models;
using TqkLibrary.VpnClient.Abstractions.Net;
using TqkLibrary.VpnClient.Abstractions.Transport.Interfaces;
using TqkLibrary.VpnClient.Drivers.Core;
using TqkLibrary.VpnClient.Drivers.Tinc.Config;
using TqkLibrary.VpnClient.Drivers.Tinc.DataChannel;
using TqkLibrary.VpnClient.Drivers.Tinc.Meta;
using TqkLibrary.VpnClient.Drivers.Tinc.Transport;
using TqkLibrary.VpnClient.Tinc.Hosts;
using TqkLibrary.VpnClient.Tinc.Meta;
using TqkLibrary.VpnClient.Tinc.Meta.Enums;
using TqkLibrary.VpnClient.Tinc.Sptps;
using TqkLibrary.VpnClient.Tinc.Sptps.Enums;

namespace TqkLibrary.VpnClient.Drivers.Tinc
{
    /// <summary>
    /// A complete tinc 1.1 (SPTPS) client to a single peer node (point-to-point). It opens the TCP meta-connection,
    /// runs the ID + SPTPS handshake (<see cref="TincMetaConnection"/>), sends its ACK and overlay <c>ADD_SUBNET</c>,
    /// then establishes a <b>data-plane</b> SPTPS session by exchanging KEX/SIG over the meta-connection
    /// (<c>REQ_KEY</c>/<c>ANS_KEY</c>, tinc's <c>send_req_key</c>) and finally carries bare IP packets over UDP data
    /// datagrams behind a stable <see cref="SwappablePacketChannel"/>. A background loop reads meta requests
    /// (ADD_SUBNET/ADD_EDGE for routing, REQ_KEY/ANS_KEY for the data handshake); the supervisor / auto-reconnect
    /// (roadmap F.6) re-establishes a dead tunnel, mirroring the Nebula / WireGuard drivers. Lighthouse / mesh discovery
    /// is bypassed: the peer's endpoint is configured directly (its host file), which is enough for the point-to-point
    /// case. The data-plane handshake is carried over the meta-connection (TCP); only the keyed data packets use UDP.
    /// </summary>
    public sealed class TincConnection : ReconnectingVpnConnection, IDisposable, IAsyncDisposable
    {
        const string DriverNameConst = "tinc";

        readonly string _host;
        readonly int _port;
        readonly TincConfig _config;
        readonly ITincTransportFactory _transportFactory;
        readonly AddressFamilyPreference _addressFamilyPreference;
        readonly IHostResolver _hostResolver;
        readonly TunnelConfig _tunnelConfig;
        readonly long _dataHandshakeTimeoutMs;

        readonly byte[] _localNodeId;
        readonly byte[] _peerNodeId;

        IByteStreamTransport? _meta;
        IDatagramTransport? _udp;
        TincMetaConnection? _metaConn;
        CancellationTokenSource? _loopCts;
        Task? _metaReadTask;
        Task? _udpReceiveTask;

        readonly object _dataLock = new();
        SptpsHandshake? _dataHandshake;          // the in-flight data-plane SPTPS handshake
        SptpsDatagramRecordLayer? _dataRecord;   // the data-plane record layer (handshake then keyed)
        TaskCompletionSource<bool>? _dataKeyReady;
        TincChannel? _channel;

        /// <summary>
        /// Creates a connection. <paramref name="config"/> is the static profile; <paramref name="transportFactory"/>
        /// opens the TCP meta + UDP data sockets (an in-process factory drives it offline).
        /// <paramref name="dataHandshakeTimeoutMs"/> bounds the data-plane key exchange.
        /// </summary>
        public TincConnection(string host, int port, TincConfig config, ITincTransportFactory transportFactory,
            TincReconnectOptions? reconnectOptions = null,
            AddressFamilyPreference addressFamilyPreference = AddressFamilyPreference.Auto,
            IHostResolver? hostResolver = null,
            long dataHandshakeTimeoutMs = 10 * 1000,
            Func<long>? clock = null,
            ILoggerFactory? loggerFactory = null)
            : base(DriverNameConst, reconnectOptions ?? new TincReconnectOptions(), clock, loggerFactory)
        {
            _host = host ?? throw new ArgumentNullException(nameof(host));
            _port = port;
            _config = config ?? throw new ArgumentNullException(nameof(config));
            _transportFactory = transportFactory ?? throw new ArgumentNullException(nameof(transportFactory));
            _addressFamilyPreference = addressFamilyPreference;
            _hostResolver = hostResolver ?? DnsHostResolver.Default;
            _tunnelConfig = config.ToTunnelConfig();
            _dataHandshakeTimeoutMs = dataHandshakeTimeoutMs;

            _localNodeId = TincNodeId.Compute(config.NodeName);
            _peerNodeId = TincNodeId.Compute(config.PeerName);
        }

        /// <summary>The static tunnel configuration (overlay address, DNS, routes, MTU).</summary>
        public TunnelConfig Config => _tunnelConfig;

        /// <summary>The local overlay (tunnel) address, if configured.</summary>
        public IPAddress? AssignedAddress => _config.OverlayAddress;

        /// <summary>Runs the meta + data handshakes and returns once the tunnel is carrying traffic.</summary>
        public Task ConnectAsync(CancellationToken cancellationToken = default) => ConnectCoreAsync(cancellationToken);

        // ---- one full tunnel attempt (reused by the first connect and every reconnect) ----

        /// <inheritdoc/>
        protected override async Task EstablishAsync(CancellationToken cancellationToken)
        {
            await CleanupAttemptResourcesAsync().ConfigureAwait(false);

            IPEndPoint endpoint = await ResolvePeerEndpointAsync(cancellationToken).ConfigureAwait(false);
            _loopCts = CancellationTokenSource.CreateLinkedTokenSource(LifetimeToken, cancellationToken);
            CancellationToken loopToken = _loopCts.Token;

            TincTransportHandle handle = await _transportFactory.ConnectAsync(endpoint, cancellationToken).ConfigureAwait(false);
            _meta = handle.Meta;
            _udp = handle.Datagram;
            handle.SetDatagramReceiver(OnInboundDatagram);
            MarkRunning(); // honour a drop detected during the handshake

            // 1) Meta-connection: ID + SPTPS handshake.
            byte[] peerPub = _config.PeerHost.Ed25519PublicKey
                ?? throw new VpnConnectionException("Peer host config has no Ed25519PublicKey.");
            var metaConn = new TincMetaConnection(_meta, _config.NodeName, _config.PrivateKey, peerPub, Logger);
            metaConn.RawDataPacket = raw => OnInboundDatagram(raw); // TCP data-fallback packets share the UDP datagram wire form
            await metaConn.HandshakeAsync(cancellationToken).ConfigureAwait(false);
            _metaConn = metaConn;
            Logger.LogHandshake(DriverName, $"meta SPTPS handshake with {metaConn.PeerName} complete");

            // 2) Send our ACK line + our overlay subnet (ADD_SUBNET) so the peer routes our address back through the
            //    tunnel. tinc's send_ack carries "<myport> <weight> <options>"; ADD_SUBNET carries "<owner> <cidr>".
            await metaConn.SendRequestAsync(
                new TincMetaRequest(TincRequestType.Ack, _port.ToString(System.Globalization.CultureInfo.InvariantCulture), "0",
                    ((TincDriverConstants.ProtocolMinor << 24) | 0).ToString("x", System.Globalization.CultureInfo.InvariantCulture)),
                cancellationToken).ConfigureAwait(false);
            if (_config.OverlayAddress is not null)
            {
                string subnet = $"{_config.OverlayAddress}/{_config.PrefixLength}";
                await metaConn.SendRequestAsync(new TincMetaRequest(TincRequestType.AddSubnet, _config.NodeName, subnet), cancellationToken).ConfigureAwait(false);
            }

            // 2b) Announce our edge to the peer (ADD_EDGE client→server). tinc's graph (MST/SSSP) needs an edge in BOTH
            //     directions to set each node's via/nexthop; without our edge the peer cannot route the data SPTPS reply
            //     (it logs "selecting relay" and drops). Format: "12 <rand> <from> <to> <to-addr> <to-port> <opts> <weight>".
            string edgeOptions = ((TincDriverConstants.ProtocolMinor << 24) | 0x08).ToString("x", System.Globalization.CultureInfo.InvariantCulture); // PMTU_DISCOVERY
            string rnd = NextRandomHex();
            await metaConn.SendRequestAsync(new TincMetaRequest(TincRequestType.AddEdge,
                rnd, _config.NodeName, _config.PeerName,
                endpoint.Address.ToString(), endpoint.Port.ToString(System.Globalization.CultureInfo.InvariantCulture),
                edgeOptions, "256"), cancellationToken).ConfigureAwait(false);

            // 3) Start the background meta read loop (consumes ACK / ADD_SUBNET / ADD_EDGE / REQ_KEY / ANS_KEY).
            _metaReadTask = Task.Run(() => MetaReadLoopAsync(loopToken), loopToken);
            if (handle.DatagramReceivePump != null)
                _udpReceiveTask = Task.Run(() => handle.DatagramReceivePump(loopToken));

            // 4) Establish the data-plane SPTPS session (KEX/SIG over the meta-connection) and wait for the keys.
            await StartDataHandshakeAsync(cancellationToken).ConfigureAwait(false);
            bool keyed = await WaitForDataKeyAsync(cancellationToken).ConfigureAwait(false);
            if (!keyed)
            {
                Logger.LogHandshakeFailed(DriverName, "data-plane SPTPS key exchange did not complete in time");
                throw new VpnConnectionException("tinc data-plane key exchange timed out (no ANS_KEY / SIG from the peer).");
            }

            Logger.LogHandshakeCompleted(DriverName);
            MarkConnected();
        }

        async Task<IPEndPoint> ResolvePeerEndpointAsync(CancellationToken cancellationToken)
        {
            if (_config.PeerEndpoint is not null) return _config.PeerEndpoint;
            string host = _config.PeerHost.Addresses.Count > 0 ? _config.PeerHost.Addresses[0] : _host;
            int port = _config.PeerHost.Port != 0 ? _config.PeerHost.Port : _port;
            IPAddress ip = await _hostResolver.ResolveAsync(host, _addressFamilyPreference, cancellationToken).ConfigureAwait(false);
            return new IPEndPoint(ip, port);
        }

        // ---- data-plane SPTPS handshake (carried over the meta-connection via REQ_KEY/ANS_KEY) ----

        async Task StartDataHandshakeAsync(CancellationToken cancellationToken)
        {
            // tinc's send_req_key: label = "tinc UDP key expansion <me> <peer>" + NUL; we are the SPTPS initiator
            // (datagram mode). The first SPTPS record (KEX) is sent over the meta-connection as
            // "REQ_KEY <me> <peer> REQ_KEY <b64(seqno||128||kex)>".
            byte[] label = SptpsHandshake.BuildUdpLabel(_config.NodeName, _config.PeerName);
            byte[] peerPub = _config.PeerHost.Ed25519PublicKey!;
            var handshake = new SptpsHandshake(initiator: true, _config.PrivateKey, peerPub, label);
            var record = new SptpsDatagramRecordLayer();

            byte[] kex = handshake.CreateKex();
            byte[] kexRecord = record.EncodeHandshake((byte)SptpsRecordType.Handshake, kex); // seqno 0 || 128 || kex

            var ready = new TaskCompletionSource<bool>(TaskCreationOptions.RunContinuationsAsynchronously);
            lock (_dataLock)
            {
                _dataHandshake = handshake;
                _dataRecord = record;
                _dataKeyReady = ready;
            }

            await SendSptpsHandshakeOverMetaAsync(kexRecord, isInitialReqKey: true, cancellationToken).ConfigureAwait(false);
            Logger.LogHandshake(DriverName, "data-plane SPTPS KEX sent (REQ_KEY)");
        }

        // Send a data-plane SPTPS handshake record over the meta-connection. The very first record uses
        // "REQ_KEY <me> <peer> REQ_KEY <b64>" (tinc's send_initial_sptps_data); subsequent records would use
        // "REQ_KEY <me> <peer> SPTPS_PACKET <b64>" (send_sptps_data), but for a point-to-point initiator the only record
        // we send is the KEX (the SIG goes back to the peer the same way only if it initiates — here the peer answers).
        async Task SendSptpsHandshakeOverMetaAsync(byte[] sptpsRecord, bool isInitialReqKey, CancellationToken cancellationToken)
        {
            TincMetaConnection meta = _metaConn!;
            string b64 = TincBase64.Encode(sptpsRecord);
            int innerReqno = isInitialReqKey ? (int)TincRequestType.ReqKey : (int)TincRequestType.SptpsPacket;
            var req = new TincMetaRequest(TincRequestType.ReqKey, _config.NodeName, _config.PeerName,
                innerReqno.ToString(System.Globalization.CultureInfo.InvariantCulture), b64);
            await meta.SendRequestAsync(req, cancellationToken).ConfigureAwait(false);
        }

        // Send a data-plane SPTPS HANDSHAKE record (e.g. our SIG) over the meta-connection via ANS_KEY — tinc's
        // send_sptps_data routes SPTPS_HANDSHAKE records through "ANS_KEY <from> <to> <b64> -1 -1 -1 <comp>".
        async Task SendSptpsHandshakeViaAnsKeyAsync(byte[] sptpsRecord, CancellationToken cancellationToken)
        {
            TincMetaConnection meta = _metaConn!;
            string b64 = TincBase64.Encode(sptpsRecord);
            var req = new TincMetaRequest(TincRequestType.AnsKey, _config.NodeName, _config.PeerName, b64, "-1", "-1", "-1", "0");
            await meta.SendRequestAsync(req, cancellationToken).ConfigureAwait(false);
        }

        async Task<bool> WaitForDataKeyAsync(CancellationToken cancellationToken)
        {
            Task<bool>? ready;
            lock (_dataLock) ready = _dataKeyReady?.Task;
            if (ready is null) return false;
            using var timeoutCts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
            timeoutCts.CancelAfter(TimeSpan.FromMilliseconds(_dataHandshakeTimeoutMs));
            var cancelTcs = new TaskCompletionSource<bool>(TaskCreationOptions.RunContinuationsAsynchronously);
            using (timeoutCts.Token.Register(() => cancelTcs.TrySetResult(false)))
            {
                Task completed = await Task.WhenAny(ready, cancelTcs.Task).ConfigureAwait(false);
                return completed == ready && ready.Result;
            }
        }

        // ---- meta read loop: routes inbound meta requests ----

        async Task MetaReadLoopAsync(CancellationToken cancellationToken)
        {
            TincMetaConnection meta = _metaConn!;
            try
            {
                while (!cancellationToken.IsCancellationRequested)
                {
                    TincMetaRequest? request = await meta.ReadRequestAsync(cancellationToken).ConfigureAwait(false);
                    if (request is null) { OnLinkLost("tinc meta-connection closed by peer"); return; }
                    await HandleMetaRequestAsync(meta, request, cancellationToken).ConfigureAwait(false);
                }
            }
            catch (OperationCanceledException) { }
            catch (Exception ex)
            {
                Logger.LogPacketDropped(DriverName, VpnDropReason.Unexpected, $"meta read loop error: {ex.GetType().Name}: {ex.Message}");
                OnLinkLost("tinc meta read loop ended");
            }
        }

        async Task HandleMetaRequestAsync(TincMetaConnection meta, TincMetaRequest request, CancellationToken cancellationToken)
        {
            switch (request.Type)
            {
                case TincRequestType.Ack:
                case TincRequestType.AddSubnet:
                case TincRequestType.AddEdge:
                case TincRequestType.DelSubnet:
                case TincRequestType.DelEdge:
                case TincRequestType.Status:
                case TincRequestType.KeyChanged:
                case TincRequestType.UdpInfo:
                case TincRequestType.MtuInfo:
                    Logger.LogProtocolStep("tinc-meta", $"{request.Type} {string.Join(" ", request.Arguments)}");
                    break;

                case TincRequestType.Ping:
                    // Reply PONG to keep the meta-connection alive.
                    await meta.SendRequestAsync(new TincMetaRequest(TincRequestType.Pong), cancellationToken).ConfigureAwait(false);
                    break;

                case TincRequestType.ReqKey:
                    await HandleReqKeyAsync(meta, request, cancellationToken).ConfigureAwait(false);
                    break;

                case TincRequestType.AnsKey:
                    HandleAnsKey(request);
                    break;

                default:
                    Logger.LogProtocolStep("tinc-meta", $"ignored request {request.RawType}");
                    break;
            }
        }

        // REQ_KEY "<from> <to> [<reqno> <b64>]". An extended REQ_KEY (reqno == REQ_KEY) carries the peer's data-plane
        // SPTPS handshake record destined for us; feed it to our handshake. A plain REQ_KEY (no extra args) means the
        // peer wants our key — we already initiated, so we ignore it.
        async Task HandleReqKeyAsync(TincMetaConnection meta, TincMetaRequest request, CancellationToken cancellationToken)
        {
            // args: <from> <to> <reqno> <b64data>
            if (request.Arguments.Count < 4) return;
            if (!int.TryParse(request.Arguments[2], out int reqno)) return;
            if (reqno != (int)TincRequestType.ReqKey && reqno != (int)TincRequestType.SptpsPacket) return;

            byte[] sptpsRecord = TincBase64.Decode(request.Arguments[3]);
            await FeedDataHandshakeRecordAsync(sptpsRecord, cancellationToken).ConfigureAwait(false);
        }

        // ANS_KEY "<from> <to> <b64data> -1 -1 -1 <comp>" carries a data-plane SPTPS handshake record back to us
        // (tinc sends SPTPS_HANDSHAKE records via ANS_KEY). Feed it to our handshake.
        void HandleAnsKey(TincMetaRequest request)
        {
            if (request.Arguments.Count < 3) return;
            byte[] sptpsRecord = TincBase64.Decode(request.Arguments[2]);
            _ = FeedDataHandshakeRecordAsync(sptpsRecord, CancellationToken.None);
        }

        // Process one inbound data-plane SPTPS handshake record (seqno||128||payload). The peer answers our KEX with
        // its own KEX, then its SIG; once we have consumed the SIG the directional keys are derived and the data channel
        // is bound.
        async Task FeedDataHandshakeRecordAsync(byte[] sptpsRecord, CancellationToken cancellationToken)
        {
            SptpsHandshake? handshake;
            SptpsDatagramRecordLayer? record;
            lock (_dataLock) { handshake = _dataHandshake; record = _dataRecord; }
            if (handshake is null || record is null) return;
            if (handshake.IsVerified) return; // already keyed

            SptpsDecodeResult result = record.DecodeHandshake(sptpsRecord, out byte type, out byte[] data);
            if (result != SptpsDecodeResult.Ok || type != (byte)SptpsRecordType.Handshake)
            {
                // An empty ACK record (data.Length == 0) is also a handshake record; ignore decode noise.
                return;
            }

            // The peer's first handshake record is its KEX (65 bytes); the second is its SIG (64 bytes). On consuming the
            // server KEX the initiator must send its OWN SIG (tinc's receive_kex → send_sig); that SIG goes back over the
            // meta-connection via ANS_KEY (send_sptps_data for a SPTPS_HANDSHAKE record). After consuming the server SIG
            // both sides are keyed (the in cipher is enabled internally) — no empty ACK record on the wire.
            try
            {
                if (data.Length == SptpsConstants.NonceSize + SptpsConstants.EcdhSize + 1) // 1 (version) + 32 (nonce) + 32 (pubkey)
                {
                    handshake.ConsumeKex(data);
                    Logger.LogHandshake(DriverName, "data-plane SPTPS server KEX consumed; sending our SIG (ANS_KEY)");
                    byte[] sigRecord = record.EncodeHandshake((byte)SptpsRecordType.Handshake, handshake.CreateSig()); // seqno 1
                    await SendSptpsHandshakeViaAnsKeyAsync(sigRecord, cancellationToken).ConfigureAwait(false);
                }
                else if (data.Length == SptpsConstants.SignatureSize)
                {
                    if (!handshake.ConsumeSig(data))
                    {
                        Logger.LogHandshakeFailed(DriverName, "data-plane SPTPS server SIG verification failed");
                        return;
                    }
                    BindDataChannel(handshake, record);
                }
            }
            catch (Exception ex)
            {
                Logger.LogPacketDropped(DriverName, VpnDropReason.Unexpected, $"data handshake record error: {ex.Message}");
            }
        }

        void BindDataChannel(SptpsHandshake handshake, SptpsDatagramRecordLayer record)
        {
            // Switch the datagram record layer to the derived directional keys (its seqno already continued past the
            // handshake records — KEX seqno 0, SIG seqno 1 — so the first data record is seqno 2).
            record.EnableEncryption(handshake.OutCipherKey, handshake.InCipherKey);
            var transport = new TincDataTransport(record, _localNodeId, _peerNodeId);
            var channel = new TincChannel(transport, (wire, ct) => SendDatagramAsync(wire, ct), _config.Mtu);
            lock (_dataLock) _channel = channel;

            Facade.SetInner(channel);
            TaskCompletionSource<bool>? ready;
            lock (_dataLock) ready = _dataKeyReady;
            ready?.TrySetResult(true);
            Logger.LogHandshake(DriverName, "data-plane SPTPS keyed; data channel bound (UDP)");
        }

        // ---- UDP data plane ----

        void OnInboundDatagram(ReadOnlyMemory<byte> datagram)
        {
            TincChannel? channel;
            lock (_dataLock) channel = _channel;
            if (channel is null) return;
            if (!channel.Deliver(datagram.Span))
                Logger.LogPacketDropped(DriverName, VpnDropReason.DecryptFailed, "UDP data datagram not delivered (decrypt/replay/no session)");
        }

        ValueTask SendDatagramAsync(ReadOnlyMemory<byte> wire, CancellationToken cancellationToken = default)
        {
            IDatagramTransport? udp = _udp;
            if (udp is null) return default;
            return SendDatagramCoreAsync(udp, wire, cancellationToken);
        }

        async ValueTask SendDatagramCoreAsync(IDatagramTransport udp, ReadOnlyMemory<byte> wire, CancellationToken cancellationToken)
        {
            try { await udp.SendAsync(wire, cancellationToken).ConfigureAwait(false); }
            catch (Exception ex)
            {
                Logger.LogPacketDropped(DriverName, VpnDropReason.Unexpected, $"failed to send UDP datagram: {ex.GetType().Name}: {ex.Message}");
            }
        }

        // ---- teardown ----

        /// <inheritdoc/>
        protected override async Task CleanupAttemptResourcesAsync()
        {
            StopAttemptLoop();

            CancellationTokenSource? loop = _loopCts;
            _loopCts = null;
            try { loop?.Cancel(); } catch { }

            Task? metaRead = _metaReadTask; _metaReadTask = null;
            Task? udpReceive = _udpReceiveTask; _udpReceiveTask = null;
            if (metaRead != null) { try { await metaRead.ConfigureAwait(false); } catch { } }
            if (udpReceive != null) { try { await udpReceive.ConfigureAwait(false); } catch { } }
            loop?.Dispose();

            IByteStreamTransport? meta = _meta; _meta = null;
            IDatagramTransport? udp = _udp; _udp = null;
            if (meta != null) { try { await meta.DisposeAsync().ConfigureAwait(false); } catch { } }
            if (udp != null) { try { await udp.DisposeAsync().ConfigureAwait(false); } catch { } }

            lock (_dataLock)
            {
                _dataHandshake = null;
                _dataRecord = null;
                _dataKeyReady = null;
                _channel = null;
            }
            _metaConn = null;
        }

        /// <inheritdoc/>
        protected override void StopAttemptLoop()
        {
            // Nothing extra: the timers are the meta/udp loops cancelled via _loopCts in CleanupAttemptResourcesAsync.
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

        // tinc stamps each ADD_EDGE with a random hex nonce (its rand()); any value works — it only deduplicates.
        static string NextRandomHex()
        {
            byte[] b = new byte[4];
            using (var rng = System.Security.Cryptography.RandomNumberGenerator.Create()) rng.GetBytes(b);
            uint v = ((uint)b[0] << 24) | ((uint)b[1] << 16) | ((uint)b[2] << 8) | b[3];
            return v.ToString("x", System.Globalization.CultureInfo.InvariantCulture);
        }
    }
}
