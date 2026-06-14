using System.Net;
using TqkLibrary.VpnClient.Abstractions.Channels;
using TqkLibrary.VpnClient.Abstractions.Channels.Interfaces;
using TqkLibrary.VpnClient.Abstractions.Drivers;
using TqkLibrary.VpnClient.Abstractions.Net;
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
    /// <see cref="PacketChannel"/>; DPD keepalive, CREATE_CHILD_SA rekey and a DELETE teardown run for its lifetime,
    /// and (when enabled) a dropped tunnel is re-established behind that same channel.
    /// </summary>
    public sealed class Ikev2Connection : IDisposable, IAsyncDisposable
    {
        static readonly TimeSpan DpdInterval = TimeSpan.FromSeconds(20);
        const int DpdMaxMissed = 3;
        // Rekey the ESP CHILD_SA at ~90% of a conventional 1-hour lifetime; the sequence-exhaustion watermark rekeys
        // sooner on a very busy tunnel (EspTunnelChannel raises RekeyNeeded near 2^32).
        static readonly TimeSpan RekeyInterval = TimeSpan.FromSeconds(3600 * 9 / 10);
        static readonly TimeSpan RekeyGrace = TimeSpan.FromSeconds(10);
        static readonly TimeSpan ExchangeTimeout = TimeSpan.FromSeconds(2.5);
        const int ExchangeMaxAttempts = 5;
        const int Mtu = 1400;

        readonly string _host;
        readonly byte[] _preSharedKey;
        readonly Ikev2ReconnectOptions _opts;
        readonly AddressFamilyPreference _addressFamilyPreference;
        readonly IHostResolver _hostResolver;
        readonly SwappablePacketChannel _facade = new();
        readonly CancellationTokenSource _lifetimeCts = new();
        readonly Random _random = new();
        readonly object _stateLock = new();
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
        System.Threading.Timer? _dropTimer;
        int _dpdMissed;
        int _rekeyInProgress;
        bool _supervisorActive;        // guarded by _stateLock
        volatile bool _keepaliveRunning;
        volatile bool _userTeardown;
        Task? _supervisor;
        Ikev2ConnectionState _state = Ikev2ConnectionState.Disconnected;

        /// <summary>Creates a connection to the given IKEv2 gateway with the IPsec pre-shared key.</summary>
        public Ikev2Connection(string host, byte[] preSharedKey, Ikev2ReconnectOptions? reconnectOptions = null,
            AddressFamilyPreference addressFamilyPreference = AddressFamilyPreference.Auto, IHostResolver? hostResolver = null)
        {
            _host = host;
            _preSharedKey = preSharedKey;
            _opts = reconnectOptions ?? new Ikev2ReconnectOptions();
            _addressFamilyPreference = addressFamilyPreference;
            _hostResolver = hostResolver ?? DnsHostResolver.Default;
        }

        /// <summary>The stable L3 packet channel (valid after a successful connect; survives reconnect).</summary>
        public IPacketChannel PacketChannel => _facade;

        /// <summary>The virtual IP address the gateway assigned via the Configuration Payload.</summary>
        public IPAddress AssignedAddress => _assignedAddress ?? IPAddress.Any;

        /// <summary>The DNS server pushed in the CFG_REPLY, if any.</summary>
        public IPAddress? AssignedDns => _assignedDns;

        /// <summary>Raised whenever the connection state changes (handshake progress, drop, reconnect).</summary>
        public event Action<Ikev2ConnectionState>? StateChanged;

        /// <summary>Raised after a successful auto-reconnect, carrying the new address and whether it changed.</summary>
        public event Action<Ikev2ReconnectInfo>? Reconnected;

        /// <summary>The current lifecycle state.</summary>
        public Ikev2ConnectionState State => _state;

        /// <summary>Runs the full handshake and returns once the gateway has assigned a virtual address.</summary>
        public async Task ConnectAsync(CancellationToken cancellationToken = default)
        {
            SetState(Ikev2ConnectionState.Connecting);
            await EstablishAsync(cancellationToken).ConfigureAwait(false);
            _lastAssignedAddress = _assignedAddress;
        }

        // ---- one full tunnel attempt (reused by the first connect and every reconnect) ----

        async Task EstablishAsync(CancellationToken cancellationToken)
        {
            await CleanupAttemptResourcesAsync().ConfigureAwait(false);
            _espActive = false;
            Interlocked.Exchange(ref _dpdMissed, 0);
            Interlocked.Exchange(ref _rekeyInProgress, 0);
            _ikeWaiter = null;

            IPAddress serverIp = await ResolveAsync(_host, cancellationToken).ConfigureAwait(false);

            NatTraversalChannel natt = StartAttemptChannel(serverIp, cancellationToken);
            var ike = new IkeClient(_preSharedKey, BuildIdentity(), requestTransportMode: false, requestConfiguration: true);
            _ike = ike;

            // --- IKE_SA_INIT on UDP/500 ---
            IkeMessage initRequest = ike.BuildInitRequest(natt.GetLocalAddress(), (ushort)natt.LocalPort, serverIp, (ushort)NatTraversal.IkePort);
            byte[] initReply = await ExchangeIkeAsync(natt, initRequest.Encode(), cancellationToken).ConfigureAwait(false);
            ike.ProcessInitResponse(IkeMessage.Decode(initReply));

            // Forced NAT-T: an ephemeral source port means the gateway always sees us NATed, so float to UDP/4500.
            natt.SwitchToNatTPort();

            // --- IKE_AUTH on UDP/4500 (encrypted; carries IDi, AUTH, CP request, SAi2, TS) ---
            byte[] authReply = await ExchangeIkeAsync(natt, ike.BuildAuthRequest(), cancellationToken).ConfigureAwait(false);
            if (!ike.ProcessAuthResponse(authReply))
                throw new VpnAuthenticationException("IKEv2 IKE_AUTH failed (PSK / AUTH mismatch or no CHILD_SA).");

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
            _facade.SetInner(dataPlane);
            StartKeepalive();
        }

        // Opens the attempt's NAT-T channel on an ephemeral local port, publishes it + a linked CTS, starts its loop.
        NatTraversalChannel StartAttemptChannel(IPAddress serverIp, CancellationToken cancellationToken)
        {
            var natt = new NatTraversalChannel(serverIp, NatTraversal.IkePort, localPort: 0);
            _natt = natt;
            _loopCts = CancellationTokenSource.CreateLinkedTokenSource(_lifetimeCts.Token, cancellationToken);
            CancellationToken loopToken = _loopCts.Token;
            _ = Task.Run(() => ReceiveLoopAsync(natt, loopToken));
            return natt;
        }

        static IdentificationPayload BuildIdentity()
            => new() { IsInitiator = true, IdType = IkeIdType.Ipv4Address, Data = new byte[] { 0, 0, 0, 0 } };

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

        // ---- keepalive: IKEv2 DPD (empty INFORMATIONAL, RFC 7296 §2.4) ----

        void StartKeepalive()
        {
            _keepaliveRunning = true;
            SetState(Ikev2ConnectionState.Connected);
            _dpdTimer = new System.Threading.Timer(_ => _ = SendDpdTickAsync(), null, DpdInterval, DpdInterval);
            _rekeyTimer = new System.Threading.Timer(_ => _ = RekeyChildSaAsync(), null, RekeyInterval, RekeyInterval);
        }

        void StopKeepalive()
        {
            _keepaliveRunning = false;
            _dpdTimer?.Dispose();
            _rekeyTimer?.Dispose();
            _dropTimer?.Dispose();
            _dpdTimer = null;
            _rekeyTimer = null;
            _dropTimer = null;
        }

        async Task SendDpdTickAsync()
        {
            if (!_keepaliveRunning) return;
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
                await SendRequestAwaitResponseAsync(ike.BuildDeadPeerDetection()).ConfigureAwait(false);
                Interlocked.Exchange(ref _dpdMissed, 0); // a reply proves the peer is alive
            }
            catch { /* no reply this round; _dpdMissed stays incremented and trips after DpdMaxMissed */ }
        }

        // A peer-initiated INFORMATIONAL: a DPD probe (empty → ack it) or a DELETE (tear the tunnel down).
        void HandleInboundIke(byte[] payload)
        {
            IkeClient? ike = _ike;
            if (ike is null || !_keepaliveRunning) return;
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
                    Task completed = await Task.WhenAny(waiter.Task, Task.Delay(WithJitter(ExchangeTimeout), _lifetimeCts.Token)).ConfigureAwait(false);
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
            if (!_keepaliveRunning) return;
            if (Interlocked.CompareExchange(ref _rekeyInProgress, 1, 0) != 0) return;
            try
            {
                IkeClient? ike = _ike;
                EspTunnelChannel? dataPlane = _dataPlane;
                if (ike is null || dataPlane is null) return;

                byte[] reply = await SendRequestAwaitResponseAsync(ike.BuildRekeyChildSaRequest()).ConfigureAwait(false);
                ChildSaParameters? rekeyed = ike.ProcessRekeyChildSaResponse(reply);
                if (rekeyed is null) return; // keep the current SA; retry at the next interval / signal

                EspCipherSuite outbound = rekeyed.Suite.BuildSuite(rekeyed.Keys.EncryptionInitiator, rekeyed.Keys.IntegrityInitiator);
                EspCipherSuite inbound = rekeyed.Suite.BuildSuite(rekeyed.Keys.EncryptionResponder, rekeyed.Keys.IntegrityResponder);
                var fresh = new EspSession(ToSpi(rekeyed.OutboundSpi), outbound, ToSpi(rekeyed.InboundSpi), inbound);

                dataPlane.SwapSession(fresh);                       // send on the new SA now; keep the old for inbound
                ScheduleDropPreviousInbound(dataPlane);             // drop the old SA after the grace window
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

        // ---- link-loss handling + auto-reconnect supervisor (mirrors the L2TP/IPsec driver) ----

        void OnLinkLost(string reason)
        {
            bool goDisconnected = false;
            bool startSupervisor = false;
            lock (_stateLock)
            {
                if (!_keepaliveRunning) return;
                StopKeepalive();
                _espActive = false;

                if (_userTeardown || !_opts.Enabled)
                    goDisconnected = true;
                else if (!_supervisorActive)
                {
                    _supervisorActive = true;
                    startSupervisor = true;
                }
            }

            if (goDisconnected) { SetState(Ikev2ConnectionState.Disconnected); return; }
            if (startSupervisor)
            {
                SetState(Ikev2ConnectionState.Reconnecting);
                _supervisor = Task.Run(() => ReconnectLoopAsync(_lifetimeCts.Token));
            }
        }

        async Task ReconnectLoopAsync(CancellationToken cancellationToken)
        {
            TimeSpan delay = _opts.InitialBackoff;
            int failures = 0;
            while (!_userTeardown && !cancellationToken.IsCancellationRequested)
            {
                bool established = false;
                try { await EstablishAsync(cancellationToken).ConfigureAwait(false); established = true; }
                catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested) { break; }
                catch { /* attempt failed — back off and retry */ }

                if (established)
                {
                    bool healthy;
                    lock (_stateLock)
                    {
                        healthy = _keepaliveRunning;
                        if (healthy) _supervisorActive = false;
                    }
                    if (healthy) { RaiseReconnected(); return; }

                    SetState(Ikev2ConnectionState.Reconnecting);
                    delay = _opts.InitialBackoff;
                    failures = 0;
                    continue;
                }

                if (_opts.MaxAttempts != 0 && ++failures >= _opts.MaxAttempts) break;
                try { await Task.Delay(WithJitter(delay), cancellationToken).ConfigureAwait(false); }
                catch (OperationCanceledException) { break; }
                delay = _opts.NextBackoff(delay);
            }

            lock (_stateLock) { _supervisorActive = false; }
            if (!_userTeardown) SetState(Ikev2ConnectionState.Disconnected);
        }

        void RaiseReconnected()
        {
            IPAddress newAddress = _assignedAddress ?? IPAddress.Any;
            bool changed = _lastAssignedAddress != null && !newAddress.Equals(_lastAssignedAddress);
            _lastAssignedAddress = newAddress;
            Reconnected?.Invoke(new Ikev2ReconnectInfo(newAddress, changed));
        }

        // ---- teardown ----

        /// <summary>
        /// Tears the tunnel down gracefully and permanently (no reconnect): cancels any reconnect in flight, sends an
        /// IKEv2 DELETE for the IKE SA, then cancels the receive loop and disposes the transport. Best-effort and
        /// time-boxed; safe to call more than once.
        /// </summary>
        public async Task DisconnectAsync(CancellationToken cancellationToken = default)
        {
            _userTeardown = true;
            lock (_stateLock) StopKeepalive();

            IkeClient? ike = _ike;
            NatTraversalChannel? natt = _natt;
            if (ike != null && natt != null)
            {
                try { await natt.SendIkeAsync(ike.BuildDeleteIkeSa()).ConfigureAwait(false); } catch { }
            }

            _lifetimeCts.Cancel();
            Task? supervisor = _supervisor;
            if (supervisor != null) { try { await supervisor.ConfigureAwait(false); } catch { } }

            await CleanupAttemptResourcesAsync().ConfigureAwait(false);
            SetState(Ikev2ConnectionState.Disconnected);
        }

        async Task CleanupAttemptResourcesAsync()
        {
            StopKeepalive();

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

        TimeSpan WithJitter(TimeSpan delay)
        {
            double fraction = _opts.JitterFraction;
            if (fraction <= 0) return delay;
            double r;
            lock (_random) r = _random.NextDouble();
            double jitter = delay.TotalMilliseconds * fraction * (r * 2 - 1);
            return TimeSpan.FromMilliseconds(Math.Max(0, delay.TotalMilliseconds + jitter));
        }

        void SetState(Ikev2ConnectionState state)
        {
            if (_state == state) return;
            _state = state;
            StateChanged?.Invoke(state);
        }

        static uint ToSpi(byte[] spi) => (uint)((spi[0] << 24) | (spi[1] << 16) | (spi[2] << 8) | spi[3]);

        /// <inheritdoc/>
        public async ValueTask DisposeAsync()
        {
            try { await DisconnectAsync().ConfigureAwait(false); } catch { }
            _lifetimeCts.Dispose();
            _exchangeGate.Dispose();
            await _facade.DisposeAsync().ConfigureAwait(false);
        }

        /// <inheritdoc/>
        public void Dispose() => DisposeAsync().AsTask().GetAwaiter().GetResult();
    }
}
