using System.Net;
using Microsoft.Extensions.Logging;
using TqkLibrary.VpnClient.Abstractions.Channels;
using TqkLibrary.VpnClient.Abstractions.Channels.Interfaces;
using TqkLibrary.VpnClient.Abstractions.Diagnostics.Extensions;
using TqkLibrary.VpnClient.Abstractions.Drivers;
using TqkLibrary.VpnClient.Abstractions.Net;
using TqkLibrary.VpnClient.Drivers.CiscoIpsec.Enums;
using TqkLibrary.VpnClient.Drivers.CiscoIpsec.Models;
using TqkLibrary.VpnClient.Drivers.Core;
using TqkLibrary.VpnClient.Ipsec.Esp;
using TqkLibrary.VpnClient.Ipsec.Ike.V1;
using TqkLibrary.VpnClient.Ipsec.Ike.V1.Enums;
using TqkLibrary.VpnClient.Ipsec.Ike.V1.Models;
using TqkLibrary.VpnClient.Ipsec.Nat;
using TqkLibrary.VpnClient.Ipsec.Nat.Enums;

namespace TqkLibrary.VpnClient.Drivers.CiscoIpsec
{
    /// <summary>
    /// A complete Cisco IPsec / EzVPN remote-access client: IKEv1 <b>Aggressive Mode</b> with a group PSK, then
    /// <b>XAUTH</b> (extended user-name/password authentication) and <b>Mode-Config</b> (which pulls the virtual IP/DNS),
    /// over UDP/500→4500 forced NAT-T, finishing with a Quick Mode that installs an ESP <b>tunnel-mode</b> CHILD SA.
    /// The decapsulated inner IP packets ride the stable <see cref="ReconnectingVpnConnection{TState}.PacketChannel"/>
    /// straight to the userspace stack — no PPP, no L2TP. After <see cref="ConnectAsync"/> the tunnel is up.
    /// <para>The link-loss → supervisor → reconnect-loop machinery (backoff/jitter, the stable
    /// <see cref="SwappablePacketChannel"/> facade, the lifetime cancellation, state changes + structured logging, the
    /// monotonic clock) lives in <see cref="ReconnectingVpnConnection{TState}"/> (roadmap F.6), mirroring the IKEv2 /
    /// L2TP-IPsec drivers. This driver keeps only its protocol logic and runs <b>in-place</b> DPD keepalive + Phase 2 ESP
    /// CHILD SA rekey (make-before-break) on its own timers, deliberately <i>outside</i> the supervisor so a rekey
    /// refreshes the SA without re-establishing the tunnel; only a real drop (DPD timeout / a server Delete) calls
    /// the inherited <c>OnLinkLost</c>.</para>
    /// <para><b>Security note:</b> Aggressive Mode + group PSK is a known-weak Phase 1 (the responder's HASH_R lets an
    /// eavesdropper mount an offline dictionary attack on the group PSK). This driver exists only to interop with legacy
    /// Cisco-compatible gateways (strongSwan/vpnc EzVPN); prefer IKEv2 or L2TP/IPsec Main Mode where available.</para>
    /// </summary>
    public sealed class CiscoIpsecConnection : ReconnectingVpnConnection<CiscoIpsecConnectionState>, IDisposable, IAsyncDisposable
    {
        static readonly TimeSpan DpdInterval = TimeSpan.FromSeconds(20);
        const int DpdMaxMissed = 3;
        static readonly TimeSpan RekeyInterval = TimeSpan.FromSeconds(IkeV1Lifetimes.Phase2Seconds * 9 / 10);
        static readonly TimeSpan RekeyGrace = TimeSpan.FromSeconds(10);
        static readonly TimeSpan ExchangeTimeout = TimeSpan.FromSeconds(2.5);
        const int ExchangeMaxAttempts = 5;
        const int Mtu = 1400;
        const string DriverNameConst = "cisco-ipsec";

        // KEY_ID identity type for the Aggressive Mode group name (RFC 2407 §4.6.2.1, what Cisco/strongSwan expect).
        const byte IdTypeKeyId = 11;

        readonly string _host;
        readonly byte[] _groupPreSharedKey;
        readonly string _groupName;
        readonly string _userName;
        readonly string _password;
        readonly AddressFamilyPreference _addressFamilyPreference;
        readonly IHostResolver _hostResolver;

        IPAddress? _assignedAddress;
        IPAddress? _assignedDns;
        IPAddress? _lastAssignedAddress;

        NatTraversalChannel? _natt;
        IkeV1Client? _ike;
        EspTunnelChannel? _dataPlane;
        CancellationTokenSource? _loopCts;
        TaskCompletionSource<byte[]>? _ikeWaiter;
        TaskCompletionSource<byte[]>? _rekeyWaiter;
        volatile bool _espActive;

        System.Threading.Timer? _dpdTimer;
        System.Threading.Timer? _rekeyTimer;
        System.Threading.Timer? _dropTimer;
        int _dpdSequence;
        int _dpdMissed;
        int _rekeyInProgress;

        /// <summary>
        /// Creates a connection to the given Cisco IPsec / EzVPN gateway. <paramref name="groupName"/> +
        /// <paramref name="groupPreSharedKey"/> are the Aggressive Mode group credentials (the gateway selects the group
        /// PSK by the group name, sent in the clear in message 1). <paramref name="userName"/> +
        /// <paramref name="password"/> authenticate the user through XAUTH. <paramref name="loggerFactory"/> receives
        /// diagnostic traces (handshake/DPD/rekey/reconnect); null logs to a no-op logger.
        /// </summary>
        public CiscoIpsecConnection(string host, string groupName, byte[] groupPreSharedKey, string userName, string password,
            CiscoIpsecReconnectOptions? reconnectOptions = null,
            AddressFamilyPreference addressFamilyPreference = AddressFamilyPreference.Auto, IHostResolver? hostResolver = null,
            ILoggerFactory? loggerFactory = null)
            : base(DriverNameConst, reconnectOptions ?? new CiscoIpsecReconnectOptions(), clock: null, loggerFactory: loggerFactory)
        {
            _host = host ?? throw new ArgumentNullException(nameof(host));
            _groupName = groupName ?? throw new ArgumentNullException(nameof(groupName));
            _groupPreSharedKey = groupPreSharedKey ?? throw new ArgumentNullException(nameof(groupPreSharedKey));
            _userName = userName ?? throw new ArgumentNullException(nameof(userName));
            _password = password ?? throw new ArgumentNullException(nameof(password));
            _addressFamilyPreference = addressFamilyPreference;
            _hostResolver = hostResolver ?? DnsHostResolver.Default;
        }

        /// <summary>The virtual IP address the gateway assigned via Mode-Config.</summary>
        public IPAddress AssignedAddress => _assignedAddress ?? IPAddress.Any;

        /// <summary>The DNS server pushed in the Mode-Config reply, if any.</summary>
        public IPAddress? AssignedDns => _assignedDns;

        /// <summary>Raised after a successful auto-reconnect, carrying the new address and whether it changed.</summary>
        public event Action<CiscoIpsecReconnectInfo>? Reconnected;

        /// <inheritdoc/>
        protected override CiscoIpsecConnectionState DisconnectedState => CiscoIpsecConnectionState.Disconnected;
        /// <inheritdoc/>
        protected override CiscoIpsecConnectionState ConnectingState => CiscoIpsecConnectionState.Connecting;
        /// <inheritdoc/>
        protected override CiscoIpsecConnectionState ConnectedState => CiscoIpsecConnectionState.Connected;
        /// <inheritdoc/>
        protected override CiscoIpsecConnectionState ReconnectingState => CiscoIpsecConnectionState.Reconnecting;

        /// <summary>Runs the full handshake and returns once the gateway has assigned a virtual address.</summary>
        public async Task ConnectAsync(CancellationToken cancellationToken = default)
        {
            await ConnectCoreAsync(cancellationToken).ConfigureAwait(false);
            _lastAssignedAddress = _assignedAddress;
        }

        // ---- one full tunnel attempt (reused by the first connect and every reconnect) ----

        /// <inheritdoc/>
        protected override async Task EstablishAsync(CancellationToken cancellationToken)
        {
            await CleanupAttemptResourcesAsync().ConfigureAwait(false);
            _espActive = false;
            Interlocked.Exchange(ref _dpdSequence, 0);
            Interlocked.Exchange(ref _dpdMissed, 0);
            Interlocked.Exchange(ref _rekeyInProgress, 0);
            _ikeWaiter = null;
            _rekeyWaiter = null;

            IPAddress serverIp = await ResolveAsync(_host, cancellationToken).ConfigureAwait(false);

            NatTraversalChannel natt = StartAttemptChannel(serverIp, cancellationToken);
            var ike = new IkeV1Client(_groupPreSharedKey, IPAddress.Any, serverIp, logger: Logger) { PreferTunnelMode = true };
            ike.SetAggressiveIdentity(IdTypeKeyId, System.Text.Encoding.UTF8.GetBytes(_groupName));
            _ike = ike;

            // --- Phase 1: Aggressive Mode (AG1 cleartext on UDP/500, AG2 reply, then float to 4500 for the encrypted AG3) ---
            Logger.LogHandshake(DriverName, "IKEv1 Aggressive Mode AG1/AG2 (group PSK) + NAT-T float");
            byte[] ag2 = await ExchangeIkeAsync(natt, ike.BuildAggressive1(), cancellationToken).ConfigureAwait(false);
            if (!ike.ProcessAggressive2(ag2))
            {
                Logger.LogHandshakeFailed(DriverName, "Aggressive Mode failed (wrong group PSK / HASH_R mismatch)");
                throw new VpnAuthenticationException("IKEv1 Aggressive Mode failed (wrong group PSK or tampered HASH_R).");
            }
            // Forced NAT-T: an ephemeral source port means the gateway always sees us NATed, so float to UDP/4500 for
            // the encrypted AG3 and every later exchange (XAUTH, Mode-Config, Quick Mode, DPD).
            natt.SwitchToNatTPort();
            await natt.SendIkeAsync(ike.BuildAggressive3()).ConfigureAwait(false); // AG3 has no reply

            // --- XAUTH: the gateway pulls user name + password, then pushes a status the client acknowledges ---
            Logger.LogHandshake(DriverName, "IKEv1 XAUTH (extended user authentication)");
            await RunXAuthAsync(natt, ike, cancellationToken).ConfigureAwait(false);

            // --- Mode-Config: pull the virtual IP/DNS the tunnel uses as its inner source ---
            Logger.LogHandshake(DriverName, "IKEv1 Mode-Config (pull virtual IP/DNS)");
            byte[] cfgReply = await ExchangeIkeAsync(natt, ike.BuildModeConfigRequest(), cancellationToken).ConfigureAwait(false);
            if (!ike.ProcessModeConfigReply(cfgReply))
                throw new VpnServerRejectedException("The gateway did not assign a virtual IP (no INTERNAL_IP4_ADDRESS in the Mode-Config reply).");
            _assignedAddress = ike.AssignedAddress;
            _assignedDns = ike.AssignedDns.FirstOrDefault();

            // --- Phase 2: Quick Mode installs the ESP tunnel-mode CHILD SA (IDci = virtual IP, IDcr = 0.0.0.0/0) ---
            Logger.LogHandshake(DriverName, "IKEv1 Quick Mode (ESP tunnel-mode CHILD SA)");
            byte[] qm2 = await ExchangeIkeAsync(natt, ike.BuildQuickMode1(), cancellationToken).ConfigureAwait(false);
            if (!ike.ProcessQuickMode2(qm2))
            {
                Logger.LogHandshakeFailed(DriverName, "Quick Mode failed (no ESP SA)");
                throw new VpnServerRejectedException("IKEv1 Quick Mode failed (no ESP SA).");
            }
            await natt.SendIkeAsync(ike.BuildQuickMode3()).ConfigureAwait(false); // QM3 has no reply

            // --- ESP tunnel-mode data plane straight to the IP channel (ESP-in-UDP/4500) ---
            EspSession esp = BuildEspSession(ike.NegotiatedEsp, ike.CreatePhase2Keys(), ike.ChildOutboundSpi, ike.ChildInboundSpi, Logger);
            var dataPlane = new EspTunnelChannel(esp, datagram => natt.SendEspAsync(datagram), Mtu);
            dataPlane.RekeyNeeded += OnRekeyNeeded; // outbound ESP sequence nearing 2^32 → rekey before it wraps
            _dataPlane = dataPlane;
            _espActive = true;

            _ikeWaiter = null;
            Facade.SetInner(dataPlane);
            StartKeepalive();
        }

        // Runs the XAUTH exchange: the gateway sends a CFG_REQUEST, the client replies with the credentials, the gateway
        // sends a CFG_SET status, the client acknowledges it. Some gateways skip the SET/ACK round (status implied by
        // proceeding straight to Mode-Config); the wait there is bounded so a missing SET does not stall the handshake.
        async Task RunXAuthAsync(NatTraversalChannel natt, IkeV1Client ike, CancellationToken cancellationToken)
        {
            byte[] request = await ExchangeIkeAsync(natt, /* first send: trigger the gateway's CFG_REQUEST */ null, cancellationToken,
                expectXAuthRequest: true).ConfigureAwait(false);
            byte[] reply = ike.BuildXAuthReply(request, _userName, _password);

            // After the REPLY the gateway sends a CFG_SET with the status; answer it with a CFG_ACK.
            byte[] set = await ExchangeIkeAsync(natt, reply, cancellationToken).ConfigureAwait(false);
            byte[] ack = ike.BuildXAuthAck(set, out bool success);
            if (!success)
            {
                Logger.LogHandshakeFailed(DriverName, "XAUTH authentication failed (bad user name / password)");
                throw new VpnAuthenticationException("IKEv1 XAUTH failed (bad user name or password).");
            }
            await natt.SendIkeAsync(ack).ConfigureAwait(false); // CFG_ACK has no reply
            Logger.LogHandshake(DriverName, "XAUTH authentication succeeded");
        }

        // Opens the attempt's NAT-T channel on an ephemeral local port, publishes it + a linked CTS, starts its loop.
        NatTraversalChannel StartAttemptChannel(IPAddress serverIp, CancellationToken cancellationToken)
        {
            var natt = new NatTraversalChannel(serverIp, NatTraversal.IkePort, localPort: 0);
            _natt = natt;
            _loopCts = CancellationTokenSource.CreateLinkedTokenSource(LifetimeToken, cancellationToken);
            CancellationToken loopToken = _loopCts.Token;
            _ = Task.Run(() => ReceiveLoopAsync(natt, loopToken));
            return natt;
        }

        // Builds the bidirectional ESP session from the negotiated suite (AES-CBC or AES-GCM). For AES-CBC the
        // per-direction key material is encryption-key ‖ integrity-key; for AES-GCM it is encryption-key ‖ 4-byte salt.
        static EspSession BuildEspSession(EspSuiteSelection selection, IkeV1Phase2Keys keys, byte[] outboundSpi, byte[] inboundSpi,
            ILogger? logger = null)
        {
            EspCipherSuite outbound = selection.BuildSuite(keys.OutboundEncryption, keys.OutboundIntegrity);
            EspCipherSuite inbound = selection.BuildSuite(keys.InboundEncryption, keys.InboundIntegrity);
            return new EspSession(ToSpi(outboundSpi), outbound, ToSpi(inboundSpi), inbound, logger);
        }

        // ---- IKE request/response with retransmit (handshake exchanges) ----

        // Sends one request (or nothing, for the XAUTH CFG_REQUEST the gateway initiates) and waits for the reply,
        // retransmitting on timeout. When expectXAuthRequest is set, only an XAUTH CFG_REQUEST satisfies the wait — a
        // stray DPD or rekey reply is ignored — and no request is sent (the gateway speaks first after AG3).
        async Task<byte[]> ExchangeIkeAsync(NatTraversalChannel natt, byte[]? request, CancellationToken cancellationToken,
            bool expectXAuthRequest = false)
        {
            for (int attempt = 0; attempt < ExchangeMaxAttempts; attempt++)
            {
                var waiter = new TaskCompletionSource<byte[]>(TaskCreationOptions.RunContinuationsAsynchronously);
                _ikeWaiter = waiter;
                if (request != null) await natt.SendIkeAsync(request).ConfigureAwait(false);

                Task completed = await Task.WhenAny(waiter.Task, Task.Delay(ExchangeTimeout, cancellationToken)).ConfigureAwait(false);
                if (completed == waiter.Task)
                {
                    byte[] reply = await waiter.Task.ConfigureAwait(false);
                    if (IkeV1Client.TryReadRejectNotify(reply, out ushort notifyType))
                        throw new VpnServerRejectedException($"The Cisco IPsec gateway refused the exchange (NOTIFY {notifyType}).");
                    return reply;
                }
                cancellationToken.ThrowIfCancellationRequested();
                // When waiting for the gateway-initiated XAUTH request there is nothing to retransmit; just keep waiting.
                if (expectXAuthRequest && request is null) { attempt--; }
            }
            throw new VpnNetworkTimeoutException(
                natt.RemotePort == NatTraversal.NatTPort
                    ? "No IKEv1 response on UDP/4500 after the NAT-T float (gateway unreachable or refusing the exchange)."
                    : "No IKEv1 response from the gateway on UDP/500 (host unreachable, UDP blocked, or wrong address).");
        }

        // ---- receive loop: demux IKE (responses vs peer-initiated) and ESP ----

        async Task ReceiveLoopAsync(NatTraversalChannel natt, CancellationToken cancellationToken)
        {
            try
            {
                while (!cancellationToken.IsCancellationRequested)
                {
                    (NatTPacketKind kind, byte[] payload) = await natt.ReceiveAsync(cancellationToken).ConfigureAwait(false);
                    if (cancellationToken.IsCancellationRequested || !ReferenceEquals(_natt, natt)) break;

                    if (kind == NatTPacketKind.Ike)
                    {
                        TaskCompletionSource<byte[]>? waiter = _ikeWaiter;
                        TaskCompletionSource<byte[]>? rekey = _rekeyWaiter;
                        if (waiter != null)
                            waiter.TrySetResult(payload);                 // a handshake / XAUTH / Mode-Config reply
                        else if (rekey != null && _ike != null && _ike.IsRekeyReply(payload))
                            rekey.TrySetResult(payload);                  // a Phase 2 rekey Quick Mode reply
                        else
                            HandleInboundIke(payload);                    // steady-state DPD / Delete
                    }
                    else if (kind == NatTPacketKind.Esp && _espActive)
                    {
                        _dataPlane?.OnEspPacket(payload);
                    }
                }
            }
            catch (OperationCanceledException) { }
            catch { /* this attempt's transport died; the pending exchange times out and the attempt fails cleanly */ }
        }

        // ---- keepalive + in-place Phase 2 rekey (deliberately outside the supervisor — a rekey refreshes the SA in place) ----

        void StartKeepalive()
        {
            Logger.LogHandshakeCompleted(DriverName);
            MarkConnected();
            _dpdTimer = new System.Threading.Timer(_ => _ = SendDpdTickAsync(), null, DpdInterval, DpdInterval);
            _rekeyTimer = new System.Threading.Timer(_ => _ = RekeyPhase2Async(), null, RekeyInterval, RekeyInterval);
        }

        /// <summary>Stops the per-attempt DPD/rekey timers and parks the ESP demux (the shared supervisor drives the
        /// run/teardown flags around this; it is called under the state lock on link-loss and on teardown/cleanup).</summary>
        protected override void StopAttemptLoop()
        {
            _espActive = false;
            _dpdTimer?.Dispose();
            _rekeyTimer?.Dispose();
            _dropTimer?.Dispose();
            _dpdTimer = null;
            _rekeyTimer = null;
            _dropTimer = null;
        }

        async Task SendDpdTickAsync()
        {
            if (!IsRunning) return;
            if (Interlocked.CompareExchange(ref _dpdMissed, 0, 0) >= DpdMaxMissed)
            {
                OnLinkLost("DPD: gateway stopped answering R-U-THERE.");
                return;
            }
            Interlocked.Increment(ref _dpdMissed);
            uint sequence = (uint)Interlocked.Increment(ref _dpdSequence);
            NatTraversalChannel? natt = _natt;
            IkeV1Client? ike = _ike;
            if (natt is null || ike is null) return;
            try
            {
                Logger.LogKeepalive(DriverName, "sent IKE DPD R-U-THERE");
                await natt.SendIkeAsync(ike.BuildDpdRUThere(sequence)).ConfigureAwait(false);
            }
            catch { /* no reply this round; _dpdMissed stays incremented and trips after DpdMaxMissed */ }
        }

        // A post-handshake IKE datagram: a DPD probe/ack from the gateway, or a Delete tearing the SA down.
        void HandleInboundIke(byte[] payload)
        {
            IkeV1Client? ike = _ike;
            if (ike is null || !IsRunning) return;
            try
            {
                IkeV1InformationalResult info = ike.ProcessInformational(payload);
                switch (info.Kind)
                {
                    case IkeV1InformationalKind.DpdRequest:
                        Interlocked.Exchange(ref _dpdMissed, 0);
                        _ = SendDpdAckAsync(ike, info.Sequence);
                        break;
                    case IkeV1InformationalKind.DpdAck:
                        Interlocked.Exchange(ref _dpdMissed, 0);
                        break;
                    case IkeV1InformationalKind.DeleteEsp:
                    case IkeV1InformationalKind.DeleteIsakmp:
                        OnLinkLost("Gateway sent an IKE Delete.");
                        break;
                }
            }
            catch { /* malformed / undecryptable Informational — ignore */ }
        }

        async Task SendDpdAckAsync(IkeV1Client ike, uint sequence)
        {
            NatTraversalChannel? natt = _natt;
            if (natt is null) return;
            try { await natt.SendIkeAsync(ike.BuildDpdAck(sequence)).ConfigureAwait(false); }
            catch { }
        }

        // ---- rekey: refresh the ESP CHILD SA on the live IKE SA (make-before-break) ----

        void OnRekeyNeeded() => _ = RekeyPhase2Async();

        async Task RekeyPhase2Async()
        {
            if (!IsRunning) return;
            if (Interlocked.CompareExchange(ref _rekeyInProgress, 1, 0) != 0) return;
            try
            {
                IkeV1Client? ike = _ike;
                NatTraversalChannel? natt = _natt;
                EspTunnelChannel? dataPlane = _dataPlane;
                if (ike is null || natt is null || dataPlane is null) return;

                byte[] reply = await ExchangeRekeyAsync(natt, ike.BuildRekeyQuickMode1()).ConfigureAwait(false);
                if (!ike.ProcessRekeyQuickMode2(reply)) return; // keep the current SA; retry at the next interval / signal
                await natt.SendIkeAsync(ike.BuildRekeyQuickMode3()).ConfigureAwait(false);

                EspSession next = BuildEspSession(ike.RekeyNegotiatedEsp, ike.CreateRekeyPhase2Keys(),
                    ike.RekeyChildOutboundSpi, ike.RekeyChildInboundSpi, Logger);
                dataPlane.SwapSession(next);
                Logger.LogRekey(DriverName, "Phase 2 ESP CHILD SA rekeyed (make-before-break)");
                ScheduleDropPreviousInbound(dataPlane);
            }
            catch { /* a failed rekey keeps the current SA; the lifetime timer / watermark retries */ }
            finally { Interlocked.Exchange(ref _rekeyInProgress, 0); }
        }

        async Task<byte[]> ExchangeRekeyAsync(NatTraversalChannel natt, byte[] request)
        {
            for (int attempt = 0; attempt < ExchangeMaxAttempts && IsRunning; attempt++)
            {
                var waiter = new TaskCompletionSource<byte[]>(TaskCreationOptions.RunContinuationsAsynchronously);
                _rekeyWaiter = waiter;
                await natt.SendIkeAsync(request).ConfigureAwait(false);

                Task completed = await Task.WhenAny(waiter.Task, Task.Delay(ExchangeTimeout, LifetimeToken)).ConfigureAwait(false);
                _rekeyWaiter = null;
                if (completed == waiter.Task) return await waiter.Task.ConfigureAwait(false);
            }
            throw new VpnNetworkTimeoutException("No Quick Mode rekey response from the gateway.");
        }

        void ScheduleDropPreviousInbound(EspTunnelChannel dataPlane)
        {
            _dropTimer?.Dispose();
            _dropTimer = new System.Threading.Timer(_ => { try { dataPlane.DropPreviousInbound(); } catch { } },
                null, RekeyGrace, System.Threading.Timeout.InfiniteTimeSpan);
        }

        // ---- link-loss handling + auto-reconnect supervisor live in ReconnectingVpnConnection (roadmap F.6). ----

        /// <inheritdoc/>
        protected override void OnReconnected()
        {
            IPAddress newAddress = _assignedAddress ?? IPAddress.Any;
            bool changed = _lastAssignedAddress != null && !newAddress.Equals(_lastAssignedAddress);
            _lastAssignedAddress = newAddress;
            Reconnected?.Invoke(new CiscoIpsecReconnectInfo(newAddress, changed));
        }

        // ---- teardown ----

        /// <summary>
        /// Tears the tunnel down gracefully and permanently (no reconnect): sends a best-effort IKE Delete for the ESP
        /// CHILD SA and the ISAKMP SA, then runs the shared teardown (cancel any reconnect in flight, cancel the receive
        /// loop, dispose the transport). Best-effort and time-boxed; safe to call more than once.
        /// </summary>
        public override async Task DisconnectAsync(CancellationToken cancellationToken = default)
        {
            IkeV1Client? ike = _ike;
            NatTraversalChannel? natt = _natt;
            if (ike != null && natt != null)
            {
                try { await natt.SendIkeAsync(ike.BuildDeleteEsp()).ConfigureAwait(false); } catch { }
                try { await natt.SendIkeAsync(ike.BuildDeleteIsakmp()).ConfigureAwait(false); } catch { }
            }

            await DisconnectCoreAsync().ConfigureAwait(false);
        }

        /// <inheritdoc/>
        protected override async Task CleanupAttemptResourcesAsync()
        {
            StopAttemptLoop();

            CancellationTokenSource? loop = _loopCts;
            _loopCts = null;
            try { loop?.Cancel(); } catch { }
            loop?.Dispose();

            NatTraversalChannel? natt = _natt;
            _natt = null;
            if (natt != null)
            {
                try { await natt.DisposeAsync().ConfigureAwait(false); } catch { }
            }

            _ike = null;
            _dataPlane = null;
            _espActive = false;
        }

        // ---- helpers ----

        Task<IPAddress> ResolveAsync(string host, CancellationToken cancellationToken)
            => _hostResolver.ResolveAsync(host, _addressFamilyPreference, cancellationToken);

        static uint ToSpi(byte[] spi) => (uint)((spi[0] << 24) | (spi[1] << 16) | (spi[2] << 8) | spi[3]);

        /// <inheritdoc/>
        public async ValueTask DisposeAsync()
        {
            try { await DisconnectAsync().ConfigureAwait(false); } catch { }
            await DisposeCoreAsync().ConfigureAwait(false);
        }

        /// <inheritdoc/>
        public void Dispose()
        {
            // Prefer DisposeAsync; this offloads to the thread pool to avoid a sync-context deadlock on the block.
            try { Task.Run(() => DisposeAsync().AsTask()).GetAwaiter().GetResult(); } catch { }
        }
    }
}
