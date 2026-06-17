using System.Net;
using Microsoft.Extensions.Logging;
using TqkLibrary.VpnClient.Abstractions.Channels;
using TqkLibrary.VpnClient.Abstractions.Channels.Interfaces;
using TqkLibrary.VpnClient.Abstractions.Diagnostics.Extensions;
using TqkLibrary.VpnClient.Abstractions.Drivers;
using TqkLibrary.VpnClient.Abstractions.Net;
using TqkLibrary.VpnClient.Drivers.Core;
using TqkLibrary.VpnClient.Drivers.Ikev2.Enums;
using TqkLibrary.VpnClient.Drivers.Ikev2.Models;
using TqkLibrary.VpnClient.Ipsec.Esp;
using TqkLibrary.VpnClient.Ipsec.Ike.V2;
using TqkLibrary.VpnClient.Ipsec.Ike.V2.Enums;
using TqkLibrary.VpnClient.Ipsec.Ike.V2.Models;
using TqkLibrary.VpnClient.Ipsec.Ike.V2.Payloads;
using TqkLibrary.VpnClient.Ipsec.Nat;
using TqkLibrary.VpnClient.Ipsec.Nat.Enums;

namespace TqkLibrary.VpnClient.Drivers.Ikev2
{
    /// <summary>
    /// A complete IKEv2-native client (RFC 7296): IKE_SA_INIT + IKE_AUTH (PSK) over UDP/500→4500 NAT-T, a Configuration
    /// Payload that pulls the virtual IP/DNS, and an ESP tunnel-mode data plane that carries bare IP packets straight to
    /// the userspace stack — no PPP, no L2TP. After <see cref="ConnectAsync"/> the tunnel rides the stable
    /// <see cref="ReconnectingVpnConnection{TState}.PacketChannel"/>.
    /// <para>The link-loss → supervisor → reconnect-loop machinery (backoff/jitter, the stable
    /// <see cref="SwappablePacketChannel"/> facade, the lifetime cancellation, state changes + structured logging, the
    /// monotonic clock) lives in <see cref="ReconnectingVpnConnection{TState}"/> (roadmap F.6), mirroring the
    /// OpenConnect / OpenVPN / WireGuard / SoftEther / SSTP drivers. This driver keeps only its protocol logic
    /// (<see cref="EstablishAsync"/> / <see cref="CleanupAttemptResourcesAsync"/> / the per-attempt timers) and — IKEv2's
    /// distinctive part — runs <b>in-place</b> DPD keepalive, CREATE_CHILD_SA + IKE-SA rekey (make-before-break with DELETE)
    /// on its own timers, deliberately <i>outside</i> the supervisor so a rekey refreshes the SA without re-establishing
    /// the tunnel; only a real drop (DPD timeout / a server DELETE) calls the inherited <c>OnLinkLost</c>.</para>
    /// </summary>
    public sealed class Ikev2Connection : ReconnectingVpnConnection<Ikev2ConnectionState>, IDisposable, IAsyncDisposable
    {
        static readonly TimeSpan DpdInterval = TimeSpan.FromSeconds(20);
        const int DpdMaxMissed = 3;
        // Rekey the ESP CHILD_SA at ~90% of a conventional 1-hour lifetime; the sequence-exhaustion watermark rekeys
        // sooner on a very busy tunnel (EspTunnelChannel raises RekeyNeeded near 2^32).
        static readonly TimeSpan RekeyInterval = TimeSpan.FromSeconds(3600 * 9 / 10);
        // Rekey the IKE SA (control channel) at ~90% of a conventional 8-hour lifetime — mirrors the L2TP/IPsec
        // Phase-1 rekey cadence. This refreshes only the SK_* keys; the ESP CHILD_SA / data plane is untouched.
        static readonly TimeSpan RekeyIkeSaInterval = TimeSpan.FromSeconds(3600 * 8 * 9 / 10);
        static readonly TimeSpan RekeyGrace = TimeSpan.FromSeconds(10);
        static readonly TimeSpan ExchangeTimeout = TimeSpan.FromSeconds(2.5);
        const int ExchangeMaxAttempts = 5;
        const int Mtu = 1400;
        const string DriverNameConst = "ikev2";

        readonly string _host;
        readonly byte[] _preSharedKey;
        readonly string? _eapUserName;
        readonly string? _eapPassword;
        readonly IkeCertificateTrust? _responderTrust;
        readonly IReadOnlyList<TrafficSelector>? _initiatorSelectors;
        readonly IReadOnlyList<TrafficSelector>? _responderSelectors;
        readonly AddressFamilyPreference _addressFamilyPreference;
        readonly IHostResolver _hostResolver;
        readonly SemaphoreSlim _exchangeGate = new(1, 1); // one post-handshake request/response in flight at a time

        IPAddress? _assignedAddress;
        IPAddress? _assignedDns;
        IPAddress? _lastAssignedAddress;

        NatTraversalChannel? _natt;
        IkeClient? _ike;
        EspTunnelChannel? _dataPlane;
        CancellationTokenSource? _loopCts;
        TaskCompletionSource<byte[]>? _ikeWaiter;
        volatile bool _espActive;

        System.Threading.Timer? _dpdTimer;
        System.Threading.Timer? _rekeyTimer;
        System.Threading.Timer? _rekeyIkeTimer;
        System.Threading.Timer? _dropTimer;
        int _dpdMissed;
        int _rekeyInProgress;

        /// <summary>
        /// Creates a connection to the given IKEv2 gateway. <paramref name="preSharedKey"/> authenticates the
        /// responder by default (RFC 7296 §2.15 PSK). When <paramref name="eapUserName"/>/<paramref name="eapPassword"/>
        /// are both supplied, the initiator authenticates with EAP-MSCHAPv2 instead of a PSK AUTH (RFC 7296 §2.16);
        /// otherwise it authenticates with the PSK as well. When <paramref name="responderTrust"/> is supplied, a gateway
        /// that authenticates with a digital signature is verified against that trust (its CERT must be trusted and its
        /// AUTH signature must verify — otherwise <see cref="VpnServerRejectedException"/>); a PSK AUTH from the gateway
        /// is refused in that mode. <paramref name="initiatorSelectors"/>/<paramref name="responderSelectors"/> offer
        /// several traffic selectors (RFC 7296 §3.13); null offers the usual single match-all IPv4 selector.
        /// <paramref name="loggerFactory"/> receives diagnostic traces (handshake/DPD/rekey/reconnect); null logs to a
        /// no-op logger.
        /// </summary>
        public Ikev2Connection(string host, byte[] preSharedKey, Ikev2ReconnectOptions? reconnectOptions = null,
            AddressFamilyPreference addressFamilyPreference = AddressFamilyPreference.Auto, IHostResolver? hostResolver = null,
            string? eapUserName = null, string? eapPassword = null,
            IkeCertificateTrust? responderTrust = null,
            IReadOnlyList<TrafficSelector>? initiatorSelectors = null,
            IReadOnlyList<TrafficSelector>? responderSelectors = null,
            ILoggerFactory? loggerFactory = null)
            : base(DriverNameConst, reconnectOptions ?? new Ikev2ReconnectOptions(), clock: null, loggerFactory: loggerFactory)
        {
            _host = host;
            _preSharedKey = preSharedKey;
            _eapUserName = eapUserName;
            _eapPassword = eapPassword;
            _responderTrust = responderTrust;
            _initiatorSelectors = initiatorSelectors;
            _responderSelectors = responderSelectors;
            _addressFamilyPreference = addressFamilyPreference;
            _hostResolver = hostResolver ?? DnsHostResolver.Default;
        }

        /// <summary>The virtual IP address the gateway assigned via the Configuration Payload.</summary>
        public IPAddress AssignedAddress => _assignedAddress ?? IPAddress.Any;

        /// <summary>The DNS server pushed in the CFG_REPLY, if any.</summary>
        public IPAddress? AssignedDns => _assignedDns;

        /// <summary>Raised after a successful auto-reconnect, carrying the new address and whether it changed.</summary>
        public event Action<Ikev2ReconnectInfo>? Reconnected;

        /// <inheritdoc/>
        protected override Ikev2ConnectionState DisconnectedState => Ikev2ConnectionState.Disconnected;
        /// <inheritdoc/>
        protected override Ikev2ConnectionState ConnectingState => Ikev2ConnectionState.Connecting;
        /// <inheritdoc/>
        protected override Ikev2ConnectionState ConnectedState => Ikev2ConnectionState.Connected;
        /// <inheritdoc/>
        protected override Ikev2ConnectionState ReconnectingState => Ikev2ConnectionState.Reconnecting;

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
            Interlocked.Exchange(ref _dpdMissed, 0);
            Interlocked.Exchange(ref _rekeyInProgress, 0);
            _ikeWaiter = null;

            IPAddress serverIp = await ResolveAsync(_host, cancellationToken).ConfigureAwait(false);

            bool useEap = _eapUserName is not null && _eapPassword is not null;
            NatTraversalChannel natt = StartAttemptChannel(serverIp, cancellationToken);
            var ike = new IkeClient(_preSharedKey, BuildIdentity(useEap), requestTransportMode: false, requestConfiguration: true,
                eapUserName: _eapUserName, eapPassword: _eapPassword,
                responderTrust: _responderTrust,
                initiatorSelectors: _initiatorSelectors, responderSelectors: _responderSelectors);
            _ike = ike;

            // --- IKE_SA_INIT on UDP/500 ---
            Logger.LogHandshake(DriverName, "IKE_SA_INIT on UDP/500");
            IkeMessage initRequest = ike.BuildInitRequest(natt.GetLocalAddress(), (ushort)natt.LocalPort, serverIp, (ushort)NatTraversal.IkePort);
            byte[] initReply = await ExchangeIkeAsync(natt, initRequest.Encode(), cancellationToken).ConfigureAwait(false);
            ike.ProcessInitResponse(IkeMessage.Decode(initReply));

            // Forced NAT-T: an ephemeral source port means the gateway always sees us NATed, so float to UDP/4500.
            natt.SwitchToNatTPort();

            // --- IKE_AUTH on UDP/4500 (encrypted; carries IDi, AUTH, CP request, SAi2, TS) ---
            Logger.LogHandshake(DriverName, useEap ? "IKE_AUTH (EAP-MSCHAPv2) on UDP/4500" : "IKE_AUTH (PSK) on UDP/4500");
            if (useEap)
                await RunEapAuthAsync(natt, ike, cancellationToken).ConfigureAwait(false);
            else
            {
                byte[] authReply = await ExchangeIkeAsync(natt, ike.BuildAuthRequest(), cancellationToken).ConfigureAwait(false);
                if (!ike.ProcessAuthResponse(authReply))
                {
                    Logger.LogHandshakeFailed(DriverName, "IKE_AUTH failed (PSK / AUTH mismatch or no CHILD_SA)");
                    throw new VpnAuthenticationException("IKEv2 IKE_AUTH failed (PSK / AUTH mismatch or no CHILD_SA).");
                }
            }

            IPAddress? assigned = ike.Configuration?.AssignedIp4Address;
            if (assigned is null)
                throw new VpnServerRejectedException("The IKEv2 gateway did not assign a virtual IP (no INTERNAL_IP4_ADDRESS in the CFG_REPLY).");
            _assignedAddress = assigned;
            _assignedDns = ike.Configuration!.DnsServers.FirstOrDefault();

            // --- ESP tunnel-mode data plane straight to the IP channel ---
            EspSession esp = BuildEspSession(ike);
            var dataPlane = new EspTunnelChannel(esp, datagram => natt.SendEspAsync(datagram), Mtu);
            dataPlane.RekeyNeeded += OnRekeyNeeded; // outbound ESP sequence nearing 2^32 → rekey before it wraps
            _dataPlane = dataPlane;
            _espActive = true;

            _ikeWaiter = null;
            Facade.SetInner(dataPlane);
            StartKeepalive();
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

        // PSK auth identifies by virtual IPv4 (gateway looks the PSK up by IDi); EAP carries the user name as IDi so the
        // gateway can pick the EAP identity before the inner MSCHAPv2 exchange names it again.
        IdentificationPayload BuildIdentity(bool useEap)
        {
            if (useEap && _eapUserName is not null)
            {
                IkeIdType idType = _eapUserName.Contains("@") ? IkeIdType.Rfc822Address : IkeIdType.Fqdn;
                return new IdentificationPayload { IsInitiator = true, IdType = idType, Data = System.Text.Encoding.ASCII.GetBytes(_eapUserName) };
            }
            return new IdentificationPayload { IsInitiator = true, IdType = IkeIdType.Ipv4Address, Data = new byte[] { 0, 0, 0, 0 } };
        }

        // Runs the EAP-MSCHAPv2 exchange (RFC 7296 §2.16): the first IKE_AUTH omits AUTH, then each round trips an EAP
        // request/response on its own message ID until the IkeClient reports the CHILD_SA is established or auth failed.
        async Task RunEapAuthAsync(NatTraversalChannel natt, IkeClient ike, CancellationToken cancellationToken)
        {
            byte[] eapRequest = ike.BuildAuthRequestEap();
            while (true)
            {
                byte[] reply = await ExchangeIkeAsync(natt, eapRequest, cancellationToken).ConfigureAwait(false);
                byte[]? next = ike.ProcessAuthResponseEap(reply);
                if (next is null) break;
                eapRequest = next;
            }
            if (!ike.EapEstablished)
            {
                Logger.LogHandshakeFailed(DriverName, "EAP-MSCHAPv2 authentication failed");
                throw new VpnAuthenticationException(
                    "IKEv2 EAP-MSCHAPv2 authentication failed (bad user name/password, EAP-Failure, or responder AUTH mismatch).");
            }
        }

        // Builds the bidirectional ESP session from the negotiated CHILD_SA: initiator keys outbound, responder inbound.
        static EspSession BuildEspSession(IkeClient ike)
        {
            ChildSaKeys k = ike.ChildKeys!;
            EspSuiteSelection suite = ike.NegotiatedEsp!;
            EspCipherSuite outbound = suite.BuildSuite(k.EncryptionInitiator, k.IntegrityInitiator);
            EspCipherSuite inbound = suite.BuildSuite(k.EncryptionResponder, k.IntegrityResponder);
            return new EspSession(ToSpi(ike.ChildOutboundSpi), outbound, ToSpi(ike.ChildInboundSpi), inbound);
        }

        // ---- IKE request/response with retransmit (handshake exchanges) ----

        async Task<byte[]> ExchangeIkeAsync(NatTraversalChannel natt, byte[] request, CancellationToken cancellationToken)
        {
            for (int attempt = 0; attempt < ExchangeMaxAttempts; attempt++)
            {
                var waiter = new TaskCompletionSource<byte[]>(TaskCreationOptions.RunContinuationsAsynchronously);
                _ikeWaiter = waiter;
                await natt.SendIkeAsync(request).ConfigureAwait(false);

                Task completed = await Task.WhenAny(waiter.Task, Task.Delay(WithJitter(ExchangeTimeout), cancellationToken)).ConfigureAwait(false);
                if (completed == waiter.Task) return await waiter.Task.ConfigureAwait(false);
                cancellationToken.ThrowIfCancellationRequested();
            }
            throw new VpnNetworkTimeoutException(
                natt.RemotePort == NatTraversal.NatTPort
                    ? "No IKEv2 response on UDP/4500 after the NAT-T float (gateway unreachable or refusing the exchange)."
                    : "No IKEv2 response from the gateway on UDP/500 (host unreachable, UDP blocked, or wrong address).");
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
                        if (IsResponse(payload) && waiter != null)
                            waiter.TrySetResult(payload);    // a reply to our outstanding request (handshake/DPD/rekey)
                        else if (!IsResponse(payload))
                            HandleInboundIke(payload);       // a peer-initiated INFORMATIONAL (DPD probe / DELETE)
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

        // The IKEv2 header Response flag (bit 0x20 of the flags byte at offset 19) distinguishes a reply from a request.
        static bool IsResponse(byte[] ikeMessage) => ikeMessage.Length > 19 && (ikeMessage[19] & (byte)IkeHeaderFlags.Response) != 0;

        // ---- keepalive + in-place rekey timers (deliberately outside the supervisor — a rekey refreshes the SA in place) ----

        void StartKeepalive()
        {
            Logger.LogHandshakeCompleted(DriverName);
            MarkConnected();
            _dpdTimer = new System.Threading.Timer(_ => _ = SendDpdTickAsync(), null, DpdInterval, DpdInterval);
            _rekeyTimer = new System.Threading.Timer(_ => _ = RekeyChildSaAsync(), null, RekeyInterval, RekeyInterval);
            _rekeyIkeTimer = new System.Threading.Timer(_ => _ = RekeyIkeSaAsync(), null, RekeyIkeSaInterval, RekeyIkeSaInterval);
        }

        /// <summary>Stops the per-attempt DPD/rekey timers and parks the ESP demux (the shared supervisor drives the
        /// run/teardown flags around this; it is called under the state lock on link-loss and on teardown/cleanup).</summary>
        protected override void StopAttemptLoop()
        {
            _espActive = false;
            _dpdTimer?.Dispose();
            _rekeyTimer?.Dispose();
            _rekeyIkeTimer?.Dispose();
            _dropTimer?.Dispose();
            _dpdTimer = null;
            _rekeyTimer = null;
            _rekeyIkeTimer = null;
            _dropTimer = null;
        }

        async Task SendDpdTickAsync()
        {
            if (!IsRunning) return;
            if (Interlocked.CompareExchange(ref _dpdMissed, 0, 0) >= DpdMaxMissed)
            {
                OnLinkLost("DPD: gateway stopped answering the liveness check.");
                return;
            }
            Interlocked.Increment(ref _dpdMissed);
            IkeClient? ike = _ike;
            if (ike is null) return;
            try
            {
                Logger.LogKeepalive(DriverName, "sent IKEv2 DPD INFORMATIONAL");
                await SendRequestAwaitResponseAsync(ike.BuildDeadPeerDetection()).ConfigureAwait(false);
                Interlocked.Exchange(ref _dpdMissed, 0); // a reply proves the peer is alive
            }
            catch { /* no reply this round; _dpdMissed stays incremented and trips after DpdMaxMissed */ }
        }

        // A peer-initiated INFORMATIONAL: a DPD probe (empty → ack it) or a DELETE (tear the tunnel down).
        void HandleInboundIke(byte[] payload)
        {
            IkeClient? ike = _ike;
            if (ike is null || !IsRunning) return;
            IkeMessage? message = ike.Decrypt(payload);
            if (message is null) return;
            Interlocked.Exchange(ref _dpdMissed, 0); // an inbound request also proves the peer is alive

            if (message.Find<DeletePayload>() != null)
            {
                OnLinkLost("Gateway sent an IKEv2 DELETE.");
                return;
            }
            // Empty INFORMATIONAL = liveness probe → echo an empty INFORMATIONAL response with the same message ID.
            _ = SendInformationalAckAsync(ike, message.MessageId);
        }

        async Task SendInformationalAckAsync(IkeClient ike, uint messageId)
        {
            NatTraversalChannel? natt = _natt;
            if (natt is null) return;
            try { await natt.SendIkeAsync(ike.BuildInformationalResponse(messageId)).ConfigureAwait(false); }
            catch { }
        }

        // Transmits an already-built INFORMATIONAL+DELETE wire on the current NAT-T channel, best-effort and without
        // awaiting an ACK — used to retire a rekeyed-out SA (CHILD_SA or the old IKE SA) whose teardown does not need
        // confirmation. Keeping it off the request/response gate avoids racing the live _ikeWaiter.
        async Task SendDeleteAsync(byte[] deleteWire)
        {
            NatTraversalChannel? natt = _natt;
            if (natt is null) return;
            try { await natt.SendIkeAsync(deleteWire).ConfigureAwait(false); }
            catch { }
        }

        // Sends an SK request and awaits its response under the single-exchange gate (so DPD and rekey never race on
        // the shared _ikeWaiter). Throws on timeout.
        async Task<byte[]> SendRequestAwaitResponseAsync(byte[] request)
        {
            NatTraversalChannel? natt = _natt;
            if (natt is null) throw new InvalidOperationException("No NAT-T channel.");
            await _exchangeGate.WaitAsync().ConfigureAwait(false);
            try
            {
                for (int attempt = 0; attempt < ExchangeMaxAttempts; attempt++)
                {
                    var waiter = new TaskCompletionSource<byte[]>(TaskCreationOptions.RunContinuationsAsynchronously);
                    _ikeWaiter = waiter;
                    await natt.SendIkeAsync(request).ConfigureAwait(false);
                    Task completed = await Task.WhenAny(waiter.Task, Task.Delay(WithJitter(ExchangeTimeout), LifetimeToken)).ConfigureAwait(false);
                    if (completed == waiter.Task) return await waiter.Task.ConfigureAwait(false);
                }
                throw new VpnNetworkTimeoutException("No IKEv2 response (DPD/rekey) from the gateway.");
            }
            finally
            {
                _ikeWaiter = null;
                _exchangeGate.Release();
            }
        }

        // ---- rekey: refresh the ESP CHILD_SA on the live IKE SA (make-before-break) ----

        void OnRekeyNeeded() => _ = RekeyChildSaAsync();

        async Task RekeyChildSaAsync()
        {
            if (!IsRunning) return;
            if (Interlocked.CompareExchange(ref _rekeyInProgress, 1, 0) != 0) return;
            try
            {
                IkeClient? ike = _ike;
                EspTunnelChannel? dataPlane = _dataPlane;
                if (ike is null || dataPlane is null) return;

                byte[] oldInboundSpi = ike.ChildInboundSpi;        // the SPI of the SA being replaced (overwritten below)
                byte[] reply = await SendRequestAwaitResponseAsync(ike.BuildRekeyChildSaRequest()).ConfigureAwait(false);
                ChildSaParameters? rekeyed = ike.ProcessRekeyChildSaResponse(reply);
                if (rekeyed is null) return; // keep the current SA; retry at the next interval / signal

                EspCipherSuite outbound = rekeyed.Suite.BuildSuite(rekeyed.Keys.EncryptionInitiator, rekeyed.Keys.IntegrityInitiator);
                EspCipherSuite inbound = rekeyed.Suite.BuildSuite(rekeyed.Keys.EncryptionResponder, rekeyed.Keys.IntegrityResponder);
                var fresh = new EspSession(ToSpi(rekeyed.OutboundSpi), outbound, ToSpi(rekeyed.InboundSpi), inbound);

                dataPlane.SwapSession(fresh);                       // send on the new SA now; keep the old for inbound
                Logger.LogRekey(DriverName, "CHILD_SA rekeyed (make-before-break)");
                ScheduleDropPreviousInbound(dataPlane);             // drop the old SA after the grace window

                // Retire the old CHILD_SA on the gateway (RFC 7296 §2.8): DELETE its inbound SPI on the live IKE SA.
                // Best-effort and fire-and-forget — the grace window above still protects in-flight inbound packets.
                await SendDeleteAsync(ike.BuildDeleteChildSa(oldInboundSpi)).ConfigureAwait(false);
            }
            catch { /* a failed rekey keeps the current SA; the lifetime timer / watermark retries */ }
            finally { Interlocked.Exchange(ref _rekeyInProgress, 0); }
        }

        void ScheduleDropPreviousInbound(EspTunnelChannel dataPlane)
        {
            _dropTimer?.Dispose();
            _dropTimer = new System.Threading.Timer(_ => { try { dataPlane.DropPreviousInbound(); } catch { } },
                null, RekeyGrace, System.Threading.Timeout.InfiniteTimeSpan);
        }

        // ---- rekey: replace the IKE SA in place (RFC 7296 §1.3.2/§2.18) ----
        // Refreshes the control-channel SK_* keys (new SPIs, new D-H, message-id reset to 0). The ESP CHILD_SA / data
        // plane is unaffected, so there is no make-before-break on traffic — the request rides the old SK channel and the
        // IkeClient swings onto the new keys once the response is verified. Shares the _rekeyInProgress guard with the
        // CHILD_SA rekey so the two never run concurrently on the same IKE SA.
        async Task RekeyIkeSaAsync()
        {
            if (!IsRunning) return;
            if (Interlocked.CompareExchange(ref _rekeyInProgress, 1, 0) != 0) return;
            try
            {
                IkeClient? ike = _ike;
                if (ike is null) return;

                byte[] reply = await SendRequestAwaitResponseAsync(ike.BuildRekeyIkeSaRequest()).ConfigureAwait(false);
                if (!ike.ProcessRekeyIkeSaResponse(reply)) return; // false ⇒ keep the current IKE SA; the timer retries
                Logger.LogRekey(DriverName, "IKE SA rekeyed in place (SK_* refreshed)");

                // Retire the old IKE SA on the gateway (RFC 7296 §2.18): the DELETE was encrypted with the old SK keys
                // the instant before the swing, so it must ride the old SA. Best-effort and fire-and-forget — the new
                // SA already carries the control channel, so we do not wait for an ACK on the dying SA.
                byte[]? deleteOld = ike.TakePendingOldIkeSaDelete();
                if (deleteOld is not null) await SendDeleteAsync(deleteOld).ConfigureAwait(false);
            }
            catch { /* a failed rekey keeps the current IKE SA; the lifetime timer retries */ }
            finally { Interlocked.Exchange(ref _rekeyInProgress, 0); }
        }

        // ---- link-loss handling + auto-reconnect supervisor live in ReconnectingVpnConnection (roadmap F.6). ----
        // The DPD timeout / a server DELETE call the inherited OnLinkLost, which arms the shared ReconnectLoopAsync.

        /// <inheritdoc/>
        protected override void OnReconnected()
        {
            IPAddress newAddress = _assignedAddress ?? IPAddress.Any;
            bool changed = _lastAssignedAddress != null && !newAddress.Equals(_lastAssignedAddress);
            _lastAssignedAddress = newAddress;
            Reconnected?.Invoke(new Ikev2ReconnectInfo(newAddress, changed));
        }

        // ---- teardown ----

        /// <summary>
        /// Tears the tunnel down gracefully and permanently (no reconnect): sends a best-effort IKEv2 DELETE for the IKE
        /// SA, then runs the shared teardown (cancel any reconnect in flight, cancel the receive loop, dispose the
        /// transport). Best-effort and time-boxed; safe to call more than once.
        /// </summary>
        public override async Task DisconnectAsync(CancellationToken cancellationToken = default)
        {
            // Notify the peer first so it releases the IKE SA immediately instead of waiting for DPD to time out.
            IkeClient? ike = _ike;
            NatTraversalChannel? natt = _natt;
            if (ike != null && natt != null)
            {
                try { await natt.SendIkeAsync(ike.BuildDeleteIkeSa()).ConfigureAwait(false); } catch { }
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
            _exchangeGate.Dispose();
            await DisposeCoreAsync().ConfigureAwait(false);
        }

        /// <inheritdoc/>
        public void Dispose() => DisposeAsync().AsTask().GetAwaiter().GetResult();
    }
}
