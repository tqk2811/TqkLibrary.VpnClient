using System.Net;
using TqkLibrary.Vpn.Abstractions.Channels;
using TqkLibrary.Vpn.Abstractions.Channels.Interfaces;
using TqkLibrary.Vpn.Abstractions.Drivers;
using TqkLibrary.Vpn.Drivers.L2tpIpsec.Enums;
using TqkLibrary.Vpn.Drivers.L2tpIpsec.Models;
using TqkLibrary.Vpn.Ipsec.Esp;
using TqkLibrary.Vpn.Ipsec.Ike.V1;
using TqkLibrary.Vpn.Ipsec.Ike.V1.Enums;
using TqkLibrary.Vpn.Ipsec.Ike.V1.Models;
using TqkLibrary.Vpn.Ipsec.Nat;
using TqkLibrary.Vpn.Ipsec.Nat.Enums;
using TqkLibrary.Vpn.L2tp;
using TqkLibrary.Vpn.Ppp;
using TqkLibrary.Vpn.Ppp.Auth;

namespace TqkLibrary.Vpn.Drivers.L2tpIpsec
{
    /// <summary>
    /// A complete L2TP/IPsec client: IKEv1 Main Mode + Quick Mode (PSK) over UDP/500→4500 NAT-T, an ESP transport-mode
    /// data plane, an L2TP tunnel/session over UDP/1701, and a PPP session (MS-CHAPv2) that yields the assigned IP.
    /// After <see cref="ConnectAsync"/> the tunnel carries IP traffic via the stable <see cref="PacketChannel"/>.
    /// When auto-reconnect is enabled, a dropped tunnel is re-established behind that same channel.
    /// </summary>
    public sealed class L2tpIpsecConnection : IDisposable, IAsyncDisposable
    {
        static readonly TimeSpan HelloInterval = TimeSpan.FromSeconds(60);
        static readonly TimeSpan DpdInterval = TimeSpan.FromSeconds(20);
        const int DpdMaxMissed = 3;

        // Rekey the ESP CHILD SA at ~90% of its lifetime; declare the IKE SA expired likewise (Phase 1 = 8h).
        static readonly TimeSpan RekeyInterval = TimeSpan.FromSeconds(IkeV1Lifetimes.Phase2Seconds * 9 / 10);
        static readonly TimeSpan Phase1Lifetime = TimeSpan.FromSeconds(IkeV1Lifetimes.Phase1Seconds * 9 / 10);
        static readonly TimeSpan RekeyGrace = TimeSpan.FromSeconds(10);

        readonly string _host;
        readonly byte[] _preSharedKey;
        readonly uint _magic;
        readonly L2tpIpsecReconnectOptions _opts;
        readonly L2tpIpsecTimeoutOptions _timeouts;
        readonly L2tpIpsecNatTraversalMode _natMode;
        readonly SwappablePacketChannel _facade = new();
        readonly CancellationTokenSource _lifetimeCts = new();
        readonly Random _random = new();
        readonly object _stateLock = new();

        string? _userName;
        string? _password;
        IPAddress? _lastAssignedAddress;

        NatTraversalChannel? _natt;
        IpsecL2tpTransport? _dataTransport;
        L2tpClient? _l2tp;
        PppEngine? _ppp;
        IkeV1Client? _ike;
        CancellationTokenSource? _loopCts;
        TaskCompletionSource<byte[]>? _ikeWaiter;
        volatile bool _espActive;

        System.Threading.Timer? _helloTimer;
        System.Threading.Timer? _dpdTimer;
        System.Threading.Timer? _rekeyTimer;
        System.Threading.Timer? _phase1Timer;
        System.Threading.Timer? _dropTimer;
        TaskCompletionSource<byte[]>? _rekeyWaiter;
        int _dpdSequence;
        int _dpdMissed;
        int _rekeyInProgress; // 0/1 guard so the timer rekey and the sequence-exhaustion rekey never overlap
        int _teardownStarted;
        bool _supervisorActive; // guarded by _stateLock
        volatile bool _keepaliveRunning;
        volatile bool _userTeardown;
        Task? _supervisor;
        L2tpIpsecConnectionState _state = L2tpIpsecConnectionState.Disconnected;

        /// <summary>Creates a connection to the given L2TP/IPsec gateway with the IPsec pre-shared key.</summary>
        public L2tpIpsecConnection(string host, byte[] preSharedKey, uint magic = 0x4D2A3B1C,
            L2tpIpsecReconnectOptions? reconnectOptions = null, L2tpIpsecTimeoutOptions? timeoutOptions = null,
            L2tpIpsecNatTraversalMode natTraversalMode = L2tpIpsecNatTraversalMode.ForcedNatT)
        {
            _host = host;
            _preSharedKey = preSharedKey;
            _magic = magic;
            _opts = reconnectOptions ?? new L2tpIpsecReconnectOptions();
            _timeouts = timeoutOptions ?? new L2tpIpsecTimeoutOptions();
            _natMode = natTraversalMode;
        }

        /// <summary>The stable L3 packet channel (valid after a successful connect; survives reconnect).</summary>
        public IPacketChannel PacketChannel => _facade;

        /// <summary>The IP address assigned by the server via IPCP (tracks the latest attempt).</summary>
        public IPAddress AssignedAddress => _ppp!.AssignedAddress;

        /// <summary>The DNS server pushed by IPCP, if any (tracks the latest attempt).</summary>
        public IPAddress? AssignedDns => _ppp!.AssignedDns;

        /// <summary>Raised whenever the connection state changes (handshake progress, drop, reconnect).</summary>
        public event Action<L2tpIpsecConnectionState>? StateChanged;

        /// <summary>Raised after a successful auto-reconnect, carrying the new address and whether it changed.</summary>
        public event Action<L2tpIpsecReconnectInfo>? Reconnected;

        /// <summary>The current lifecycle state.</summary>
        public L2tpIpsecConnectionState State => _state;

        /// <summary>Runs the full handshake and returns once PPP/IPCP has assigned an address.</summary>
        public async Task ConnectAsync(string userName, string password, CancellationToken cancellationToken = default)
        {
            _userName = userName;
            _password = password;
            SetState(L2tpIpsecConnectionState.Connecting);

            await EstablishAsync(cancellationToken).ConfigureAwait(false);
            _lastAssignedAddress = _ppp!.AssignedAddress;
        }

        /// <summary>
        /// Brings up one full tunnel attempt from scratch: a clean-slate factory reused by the first connect and by
        /// every reconnect. On success the fresh PPP channel is installed behind the stable facade and keepalive starts.
        /// </summary>
        async Task EstablishAsync(CancellationToken cancellationToken)
        {
            await CleanupAttemptResourcesAsync().ConfigureAwait(false);
            _espActive = false;
            Interlocked.Exchange(ref _dpdSequence, 0);
            Interlocked.Exchange(ref _dpdMissed, 0);
            Interlocked.Exchange(ref _rekeyInProgress, 0);
            _ikeWaiter = null;
            _rekeyWaiter = null;

            IPAddress serverIp = await ResolveAsync(_host).ConfigureAwait(false);

            // Phase 1 Main Mode 1-4 + the NAT-T port decision (forced, or honest-first with a forced fallback).
            (NatTraversalChannel natt, IkeV1Client ike) = await BringUpPhase1Async(serverIp, cancellationToken).ConfigureAwait(false);

            // MM5/MM6 (encrypted IDi + HASH_I, then verify HASH_R) on the port Phase 1 settled on.
            if (!ike.ProcessMainMode6(await ExchangeIkeAsync(natt, ike.BuildMainMode5(), cancellationToken).ConfigureAwait(false)))
                throw new VpnAuthenticationException("IKEv1 Phase 1 authentication failed (PSK / HASH_R mismatch).");

            // Phase 2 — Quick Mode.
            if (!ike.ProcessQuickMode2(await ExchangeIkeAsync(natt, ike.BuildQuickMode1(), cancellationToken).ConfigureAwait(false)))
                throw new VpnServerRejectedException("IKEv1 Quick Mode failed (no ESP SA).");
            await natt.SendIkeAsync(ike.BuildQuickMode3()).ConfigureAwait(false); // QM3 has no reply

            // ESP data plane + L2TP + PPP. The suite (AES-CBC or AES-GCM) follows what the gateway selected in QM2.
            EspSession esp = BuildEspSession(ike.NegotiatedEsp, ike.CreatePhase2Keys(), ike.ChildOutboundSpi, ike.ChildInboundSpi);
            _dataTransport = new IpsecL2tpTransport(esp, datagram => natt.SendEspAsync(datagram));
            _dataTransport.RekeyNeeded += OnRekeyNeeded; // outbound ESP sequence nearing 2^32 → rekey before it wraps
            _espActive = true;

            var l2tp = new L2tpClient(_dataTransport,
                retransmitOptions: _timeouts.BuildL2tpRetransmitOptions());
            _l2tp = l2tp;
            l2tp.Disconnected += OnLinkLost;
            await l2tp.ConnectAsync(cancellationToken).ConfigureAwait(false);

            var pppChannel = new L2tpPppFrameChannel(l2tp);
            var authenticator = new MsChapV2Authenticator(_userName ?? string.Empty, _password ?? string.Empty);
            var ppp = new PppEngine(pppChannel, _magic, IPAddress.Any, authenticator: authenticator);
            _ppp = ppp;

            var linkUp = new TaskCompletionSource<bool>(TaskCreationOptions.RunContinuationsAsynchronously);
            ppp.LinkUp += () => linkUp.TrySetResult(true);
            ppp.AuthFailed += () => linkUp.TrySetException(new VpnAuthenticationException("PPP MS-CHAPv2 authentication failed."));
            ppp.Start();

            await WaitAsync(linkUp.Task, cancellationToken).ConfigureAwait(false);

            // Handshake done: stop steering IKE to the handshake waiter, publish the new plane, start keepalive.
            _ikeWaiter = null;
            _facade.SetInner(ppp.PacketChannel);
            StartKeepalive();
        }

        // ---- Phase 1 bring-up: pick the NAT-T strategy, run Main Mode 1-4, and settle on the data-plane port ----

        // Returns the channel/client on the port the rest of the handshake will use. Forced mode always floats to
        // UDP/4500; honest-first binds the real port 500 and lets the gateway's NAT-D verdict decide, falling back to
        // forced when it cannot bind 500 or the gateway reports no NAT (it would want native ESP, which is not built).
        async Task<(NatTraversalChannel Natt, IkeV1Client Ike)> BringUpPhase1Async(IPAddress serverIp, CancellationToken cancellationToken)
        {
            if (_natMode == L2tpIpsecNatTraversalMode.HonestFirst)
            {
                (NatTraversalChannel, IkeV1Client)? honest = await TryHonestPhase1Async(serverIp, cancellationToken).ConfigureAwait(false);
                if (honest != null) return (honest.Value.Item1, honest.Value.Item2);
            }
            return await ForcedPhase1Async(serverIp, cancellationToken).ConfigureAwait(false);
        }

        // Forced NAT-T (the default, proven live): ephemeral source port, NAT-D claims port 500, always float to 4500.
        async Task<(NatTraversalChannel, IkeV1Client)> ForcedPhase1Async(IPAddress serverIp, CancellationToken cancellationToken)
        {
            NatTraversalChannel natt = StartAttemptChannel(serverIp, localPort: 0, cancellationToken);
            var ike = new IkeV1Client(_preSharedKey, IPAddress.Any, serverIp);
            _ike = ike;

            ike.ProcessMainMode2(await ExchangeIkeAsync(natt, ike.BuildMainMode1(), cancellationToken).ConfigureAwait(false));
            ike.ProcessMainMode4(await ExchangeIkeAsync(natt, ike.BuildMainMode3(IPAddress.Any, serverIp), cancellationToken).ConfigureAwait(false));
            natt.SwitchToNatTPort();
            return (natt, ike);
        }

        // Honest-first: bind the real port 500, send truthful NAT-D, then read the gateway's MM4 verdict. A real NAT
        // floats to 4500 (userspace ESP-in-UDP); no NAT means the gateway wants native ESP (not built) — tear down and
        // return null so the caller retries forced. Returns null too if port 500 is unavailable (e.g. Windows IKEEXT).
        async Task<(NatTraversalChannel, IkeV1Client)?> TryHonestPhase1Async(IPAddress serverIp, CancellationToken cancellationToken)
        {
            NatTraversalChannel natt;
            try { natt = StartAttemptChannel(serverIp, localPort: NatTraversal.IkePort, cancellationToken); }
            catch (System.Net.Sockets.SocketException) { return null; }

            var ike = new IkeV1Client(_preSharedKey, IPAddress.Any, serverIp);
            _ike = ike;
            IPAddress localIp = natt.GetLocalAddress();
            ushort localPort = (ushort)natt.LocalPort;

            ike.ProcessMainMode2(await ExchangeIkeAsync(natt, ike.BuildMainMode1(), cancellationToken).ConfigureAwait(false));
            ike.ProcessMainMode4(await ExchangeIkeAsync(natt,
                ike.BuildMainMode3(localIp, localPort, serverIp, (ushort)NatTraversal.IkePort), cancellationToken).ConfigureAwait(false));

            if (ike.DetectNat(localIp, localPort, serverIp, (ushort)NatTraversal.IkePort).ShouldFloatToNatT)
            {
                natt.SwitchToNatTPort();
                return (natt, ike);
            }

            await TeardownPhase1AttemptAsync(natt).ConfigureAwait(false);
            return null;
        }

        // Opens the attempt's NAT-T channel on the given local port, publishes it + a linked CTS, and starts its
        // receive loop. May throw SocketException if the port is busy (the caller decides whether to fall back).
        NatTraversalChannel StartAttemptChannel(IPAddress serverIp, int localPort, CancellationToken cancellationToken)
        {
            var natt = new NatTraversalChannel(serverIp, NatTraversal.IkePort, localPort);
            _natt = natt;
            _loopCts = CancellationTokenSource.CreateLinkedTokenSource(_lifetimeCts.Token, cancellationToken);
            CancellationToken loopToken = _loopCts.Token;
            _ = Task.Run(() => ReceiveLoopAsync(natt, loopToken));
            return natt;
        }

        // Tears down a Phase 1 attempt mid-handshake (honest path declined) so a fresh forced attempt can rebind: cancel
        // + drop the receive loop, null the shared fields (tripping the stale loop's identity guard), close the socket.
        async Task TeardownPhase1AttemptAsync(NatTraversalChannel natt)
        {
            CancellationTokenSource? loop = _loopCts;
            _loopCts = null;
            try { loop?.Cancel(); } catch { }
            loop?.Dispose();
            _natt = null;
            _ike = null;
            try { await natt.DisposeAsync().ConfigureAwait(false); } catch { }
        }

        // Tears down the resources of the previous attempt before a fresh one (no-op on the very first attempt).
        async Task CleanupAttemptResourcesAsync()
        {
            StopKeepalive();

            if (_l2tp != null) _l2tp.Disconnected -= OnLinkLost;

            CancellationTokenSource? loop = _loopCts;
            _loopCts = null;
            try { loop?.Cancel(); } catch { }
            loop?.Dispose();

            _l2tp?.Dispose();

            // Null the channel before disposing it so the stale receive loop's identity guard trips immediately,
            // and await the dispose so the old socket is fully closed before the next attempt opens a new one.
            NatTraversalChannel? natt = _natt;
            _natt = null;
            if (natt != null)
            {
                try { await natt.DisposeAsync().ConfigureAwait(false); } catch { }
            }

            _l2tp = null;
            _ike = null;
            _dataTransport = null;
            _espActive = false;
        }

        // Builds the bidirectional ESP session from the negotiated suite. For AES-CBC the per-direction key material
        // is encryption-key ‖ integrity-key; for AES-GCM it is encryption-key ‖ 4-byte salt (EspSuiteSelection maps it).
        static EspSession BuildEspSession(EspSuiteSelection selection, IkeV1Phase2Keys keys, byte[] outboundSpi, byte[] inboundSpi)
        {
            EspCipherSuite outbound = selection.BuildSuite(keys.OutboundEncryption, keys.OutboundIntegrity);
            EspCipherSuite inbound = selection.BuildSuite(keys.InboundEncryption, keys.InboundIntegrity);
            return new EspSession(ToSpi(outboundSpi), outbound, ToSpi(inboundSpi), inbound);
        }

        async Task<byte[]> ExchangeIkeAsync(NatTraversalChannel natt, byte[] request, CancellationToken cancellationToken)
        {
            for (int attempt = 0; attempt < _timeouts.IkeMaxAttempts; attempt++)
            {
                var waiter = new TaskCompletionSource<byte[]>(TaskCreationOptions.RunContinuationsAsynchronously);
                _ikeWaiter = waiter;
                await natt.SendIkeAsync(request).ConfigureAwait(false);

                Task completed = await Task.WhenAny(waiter.Task, Task.Delay(WithJitter(_timeouts.IkeIntervalFor(attempt), _timeouts.RetransmitJitterFraction), cancellationToken)).ConfigureAwait(false);
                if (completed == waiter.Task)
                {
                    byte[] reply = await waiter.Task.ConfigureAwait(false);
                    // A gateway that refuses the exchange in the clear (e.g. NO-PROPOSAL-CHOSEN) sends an Informational
                    // NOTIFY where a Main/Quick Mode reply is expected; surface it rather than mis-decoding it downstream.
                    if (IkeV1Client.TryReadRejectNotify(reply, out ushort notifyType))
                        throw IkeRejected(notifyType, natt.RemotePort);
                    return reply;
                }
                cancellationToken.ThrowIfCancellationRequested();
            }
            throw IkeTimedOut(natt.RemotePort);
        }

        // Diagnose a failed handshake exchange by the port it stalled on. Past the NAT-T float (UDP/4500) silence is the
        // signature of a gateway that refuses forced NAT-T: not behind a NAT, it expects native ESP — which this userspace
        // client cannot send (native-ESP fallback P0.8c not built). An honest real-port handshake is available via
        // L2tpIpsecNatTraversalMode.HonestFirst, but it only rescues a gateway that actually sees a NAT in front of us.
        static VpnNetworkTimeoutException IkeTimedOut(int targetPort)
            => new(targetPort == NatTraversal.NatTPort
                ? "No IKE response on UDP/4500 after the NAT-T float. The gateway may refuse forced NAT-T (it is not "
                  + "behind a NAT and rejects UDP-encapsulated IPsec); native-ESP fallback is not yet implemented "
                  + "(try L2tpIpsecNatTraversalMode.HonestFirst if UDP/500 can be bound)."
                : "No IKE response from the gateway on UDP/500 (host unreachable, UDP blocked, or wrong address).");

        static VpnServerRejectedException IkeRejected(ushort notifyType, int targetPort)
            => new(targetPort == NatTraversal.NatTPort
                ? $"The IKEv1 gateway refused the exchange after the NAT-T float (NOTIFY {NotifyName(notifyType)}); it may refuse forced NAT-T."
                : $"The IKEv1 gateway refused the exchange (NOTIFY {NotifyName(notifyType)}).");

        // Common ISAKMP/IKEv1 error notify names (RFC 2408 §3.14) for diagnostics; unknown types fall back to the number.
        static string NotifyName(ushort notifyType) => notifyType switch
        {
            1 => "INVALID-PAYLOAD-TYPE",
            7 => "INVALID-PROTOCOL-ID",
            8 => "INVALID-SPI",
            14 => "NO-PROPOSAL-CHOSEN",
            17 => "PAYLOAD-MALFORMED",
            18 => "INVALID-ID-INFORMATION",
            20 => "INVALID-CERTIFICATE",
            24 => "AUTHENTICATION-FAILED",
            29 => "ATTRIBUTES-NOT-SUPPORTED",
            _ => notifyType.ToString(System.Globalization.CultureInfo.InvariantCulture),
        };

        // The receive loop binds to ITS attempt's NAT-T channel so a stale loop never reads the next attempt's socket.
        async Task ReceiveLoopAsync(NatTraversalChannel natt, CancellationToken cancellationToken)
        {
            try
            {
                while (!cancellationToken.IsCancellationRequested)
                {
                    (NatTPacketKind kind, byte[] payload) = await natt.ReceiveAsync(cancellationToken).ConfigureAwait(false);
                    // A datagram already in flight when this attempt was torn down must not be processed: by now a new
                    // attempt may own the shared waiters, and a stale IKE reply (old cookies/SPI) would fail it spuriously.
                    if (cancellationToken.IsCancellationRequested || !ReferenceEquals(_natt, natt)) break;
                    if (kind == NatTPacketKind.Ike)
                    {
                        TaskCompletionSource<byte[]>? waiter = _ikeWaiter;
                        TaskCompletionSource<byte[]>? rekey = _rekeyWaiter;
                        if (waiter != null)
                            waiter.TrySetResult(payload);                  // a handshake reply
                        else if (rekey != null && _ike != null && _ike.IsRekeyReply(payload))
                            rekey.TrySetResult(payload);                   // a rekey Quick Mode reply
                        else
                            HandleInboundIke(payload);                     // steady-state DPD / Delete
                    }
                    else if (kind == NatTPacketKind.Esp && _espActive)
                        _dataTransport?.OnEspPacket(payload);
                }
            }
            catch (OperationCanceledException) { }
            catch
            {
                // This attempt's transport died (socket error/dispose). Do NOT touch the shared _ikeWaiter here:
                // a concurrent new attempt may own it. The pending exchange times out and the attempt fails cleanly.
            }
        }

        // ---- keepalive: L2TP HELLO + IKE DPD (RFC 3706) ----

        void StartKeepalive()
        {
            _keepaliveRunning = true;
            SetState(L2tpIpsecConnectionState.Connected);
            _helloTimer = new System.Threading.Timer(_ => _ = SendHelloTickAsync(), null, HelloInterval, HelloInterval);
            _dpdTimer = new System.Threading.Timer(_ => _ = SendDpdTickAsync(), null, DpdInterval, DpdInterval);
            _rekeyTimer = new System.Threading.Timer(_ => _ = RekeyPhase2Async(), null, RekeyInterval, RekeyInterval);
            _phase1Timer = new System.Threading.Timer(
                _ => OnLinkLost("IKE Phase 1 SA lifetime expired."), null, Phase1Lifetime, System.Threading.Timeout.InfiniteTimeSpan);
        }

        void StopKeepalive()
        {
            _keepaliveRunning = false;
            _helloTimer?.Dispose();
            _dpdTimer?.Dispose();
            _rekeyTimer?.Dispose();
            _phase1Timer?.Dispose();
            _dropTimer?.Dispose();
            _helloTimer = null;
            _dpdTimer = null;
            _rekeyTimer = null;
            _phase1Timer = null;
            _dropTimer = null;
        }

        async Task SendHelloTickAsync()
        {
            if (!_keepaliveRunning) return;
            L2tpClient? l2tp = _l2tp; // snapshot: a concurrent teardown nulls the field
            if (l2tp == null) return;
            try { await l2tp.SendHelloAsync().ConfigureAwait(false); }
            catch { /* a dead tunnel surfaces via DPD or the L2TP Disconnected event */ }
        }

        async Task SendDpdTickAsync()
        {
            if (!_keepaliveRunning) return;
            if (Interlocked.CompareExchange(ref _dpdMissed, 0, 0) >= DpdMaxMissed)
            {
                OnLinkLost("DPD: gateway stopped answering R-U-THERE.");
                return;
            }
            Interlocked.Increment(ref _dpdMissed);
            uint sequence = (uint)Interlocked.Increment(ref _dpdSequence);
            NatTraversalChannel? natt = _natt; // snapshot: a concurrent teardown nulls the fields
            IkeV1Client? ike = _ike;
            if (natt == null || ike == null) return;
            try { await natt.SendIkeAsync(ike.BuildDpdRUThere(sequence)).ConfigureAwait(false); }
            catch { }
        }

        // A post-handshake IKE datagram: a DPD probe/ack from the gateway, or a Delete tearing the SA down.
        void HandleInboundIke(byte[] payload)
        {
            IkeV1Client? ike = _ike;
            if (ike is null || !_keepaliveRunning) return;
            try
            {
                IkeV1InformationalResult info = ike.ProcessInformational(payload);
                switch (info.Kind)
                {
                    case IkeV1InformationalKind.DpdRequest:
                        Interlocked.Exchange(ref _dpdMissed, 0); // an inbound probe also proves the peer is alive
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
            catch { /* malformed/undecryptable Informational — ignore */ }
        }

        async Task SendDpdAckAsync(IkeV1Client ike, uint sequence)
        {
            NatTraversalChannel? natt = _natt; // snapshot: a concurrent teardown nulls the field
            if (natt == null) return;
            try { await natt.SendIkeAsync(ike.BuildDpdAck(sequence)).ConfigureAwait(false); }
            catch { }
        }

        // ---- rekey: refresh the ESP CHILD SA on the live IKE SA (make-before-break) ----

        // The data plane reports the outbound ESP sequence is nearing 2^32 — rekey now, before it wraps.
        void OnRekeyNeeded() => _ = RekeyPhase2Async();

        async Task RekeyPhase2Async()
        {
            if (!_keepaliveRunning) return;
            // Either the lifetime timer or the sequence-exhaustion signal can land here; one rekey at a time so they
            // don't clobber the shared _rekeyWaiter or run two Quick Mode exchanges at once.
            if (Interlocked.CompareExchange(ref _rekeyInProgress, 1, 0) != 0) return;
            try
            {
                IkeV1Client? ike = _ike; // snapshot: a concurrent teardown nulls the fields
                NatTraversalChannel? natt = _natt;
                if (ike == null || natt == null) return;
                byte[] reply = await ExchangeRekeyAsync(ike.BuildRekeyQuickMode1()).ConfigureAwait(false);
                if (!ike.ProcessRekeyQuickMode2(reply)) return; // keep the current SA; retry at the next interval / signal
                await natt.SendIkeAsync(ike.BuildRekeyQuickMode3()).ConfigureAwait(false);

                IpsecL2tpTransport? transport = _dataTransport;
                if (transport == null) return;
                EspSession next = BuildEspSession(ike.RekeyNegotiatedEsp, ike.CreateRekeyPhase2Keys(), ike.RekeyChildOutboundSpi, ike.RekeyChildInboundSpi);
                transport.SwapSession(next);
                ScheduleDropPreviousInbound();
            }
            catch { /* rekey failed; the current SA stays active — DPD declares the peer dead if it is truly gone */ }
            finally { Interlocked.Exchange(ref _rekeyInProgress, 0); }
        }

        async Task<byte[]> ExchangeRekeyAsync(byte[] request)
        {
            for (int attempt = 0; attempt < _timeouts.IkeMaxAttempts && _keepaliveRunning; attempt++)
            {
                NatTraversalChannel? natt = _natt; // snapshot: a concurrent teardown nulls the field
                if (natt == null) break;
                var waiter = new TaskCompletionSource<byte[]>(TaskCreationOptions.RunContinuationsAsynchronously);
                _rekeyWaiter = waiter;
                await natt.SendIkeAsync(request).ConfigureAwait(false);

                Task completed = await Task.WhenAny(waiter.Task, Task.Delay(WithJitter(_timeouts.IkeIntervalFor(attempt), _timeouts.RetransmitJitterFraction))).ConfigureAwait(false);
                _rekeyWaiter = null;
                if (completed == waiter.Task) return await waiter.Task.ConfigureAwait(false);
            }
            throw new VpnNetworkTimeoutException("No Quick Mode rekey response from the gateway.");
        }

        void ScheduleDropPreviousInbound()
        {
            _dropTimer?.Dispose();
            _dropTimer = new System.Threading.Timer(
                _ => { try { _dataTransport?.DropPreviousInbound(); } catch { } },
                null, RekeyGrace, System.Threading.Timeout.InfiniteTimeSpan);
        }

        // ---- link-loss handling + auto-reconnect supervisor ----

        // Any of {DPD death, server Delete, L2TP teardown, Phase 1 expiry} may call this from different threads.
        void OnLinkLost(string reason)
        {
            bool goDisconnected = false;
            bool startSupervisor = false;
            lock (_stateLock)
            {
                if (!_keepaliveRunning) return; // first signal stops keepalive; the rest no-op
                StopKeepalive();
                _espActive = false;

                if (_userTeardown || !_opts.Enabled)
                    goDisconnected = true;
                else if (!_supervisorActive)
                {
                    _supervisorActive = true;
                    startSupervisor = true;
                }
                // else: a supervisor already owns the reconnect; it re-checks health after its next establish.
            }

            if (goDisconnected) { SetState(L2tpIpsecConnectionState.Disconnected); return; }
            if (startSupervisor)
            {
                SetState(L2tpIpsecConnectionState.Reconnecting);
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
                catch { /* attempt failed — back off and retry below */ }

                if (established)
                {
                    bool healthy;
                    lock (_stateLock)
                    {
                        // If keepalive is still up the new tunnel is healthy and we hand ownership back.
                        // If a drop landed during the connect window, OnLinkLost already stopped keepalive but
                        // could not start a new supervisor (we still own it) — so loop and reconnect again.
                        healthy = _keepaliveRunning;
                        if (healthy) _supervisorActive = false;
                    }
                    if (healthy) { RaiseReconnected(); return; }

                    SetState(L2tpIpsecConnectionState.Reconnecting);
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
            if (!_userTeardown) SetState(L2tpIpsecConnectionState.Disconnected);
        }

        void RaiseReconnected()
        {
            IPAddress newAddress = _ppp!.AssignedAddress;
            bool changed = _lastAssignedAddress != null && !newAddress.Equals(_lastAssignedAddress);
            _lastAssignedAddress = newAddress;
            Reconnected?.Invoke(new L2tpIpsecReconnectInfo(newAddress, changed));
        }

        TimeSpan WithJitter(TimeSpan delay) => WithJitter(delay, _opts.JitterFraction);

        // Shared by reconnect backoff and IKE retransmit backoff. _random is not thread-safe and is now reached from the
        // reconnect supervisor, the handshake path and the rekey timer, so the draw is serialised.
        TimeSpan WithJitter(TimeSpan delay, double fraction)
        {
            if (fraction <= 0) return delay;
            double r;
            lock (_random) r = _random.NextDouble();
            double jitter = delay.TotalMilliseconds * fraction * (r * 2 - 1);
            return TimeSpan.FromMilliseconds(Math.Max(0, delay.TotalMilliseconds + jitter));
        }

        void SetState(L2tpIpsecConnectionState state)
        {
            if (_state == state) return;
            _state = state;
            StateChanged?.Invoke(state);
        }

        static async Task WaitAsync(Task task, CancellationToken cancellationToken)
        {
            var cancelled = new TaskCompletionSource<bool>(TaskCreationOptions.RunContinuationsAsynchronously);
            using (cancellationToken.Register(() => cancelled.TrySetResult(true)))
            {
                if (await Task.WhenAny(task, cancelled.Task).ConfigureAwait(false) != task)
                    cancellationToken.ThrowIfCancellationRequested();
            }
            await task.ConfigureAwait(false);
        }

        static async Task<IPAddress> ResolveAsync(string host)
        {
            if (IPAddress.TryParse(host, out IPAddress? literal)) return literal;
            IPAddress[] addresses = await Dns.GetHostAddressesAsync(host).ConfigureAwait(false);
            return addresses.First(a => a.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork);
        }

        static uint ToSpi(byte[] spi) => (uint)((spi[0] << 24) | (spi[1] << 16) | (spi[2] << 8) | spi[3]);

        /// <summary>
        /// Tears the tunnel down gracefully and permanently (no reconnect): cancels any reconnect in flight, sends
        /// L2TP CDN + StopCCN and IKE Delete (ESP + ISAKMP), then cancels the receive loop and disposes the transports.
        /// Best-effort and time-boxed; safe to call more than once.
        /// </summary>
        public async Task DisconnectAsync(CancellationToken cancellationToken = default)
        {
            _userTeardown = true;
            _lifetimeCts.Cancel(); // abort any in-flight backoff / supervisor / handshake

            Task? supervisor = _supervisor;
            if (supervisor != null) { try { await supervisor.ConfigureAwait(false); } catch { } }

            if (Interlocked.Exchange(ref _teardownStarted, 1) != 0) return;

            StopKeepalive();
            SetState(L2tpIpsecConnectionState.Disconnected);

            await SendTeardownAsync().ConfigureAwait(false);

            _espActive = false;
            _loopCts?.Cancel();
            _l2tp?.Dispose();
            if (_natt != null) await _natt.DisposeAsync().ConfigureAwait(false);
            await _facade.DisposeAsync().ConfigureAwait(false);

            _userName = null;
            _password = null;
        }

        async Task SendTeardownAsync()
        {
            L2tpClient? l2tp = _l2tp;
            IkeV1Client? ike = _ike;
            NatTraversalChannel? natt = _natt;

            // Notify the peer so it releases the SAs immediately instead of waiting for them to time out.
            Task teardown = Task.Run(async () =>
            {
                if (l2tp != null)
                {
                    await Swallow(() => l2tp.SendCallDisconnectAsync()).ConfigureAwait(false);
                    await Swallow(() => l2tp.SendStopControlConnectionAsync()).ConfigureAwait(false);
                }
                if (ike != null && natt != null)
                {
                    await Swallow(() => natt.SendIkeAsync(ike.BuildDeleteEsp())).ConfigureAwait(false);
                    await Swallow(() => natt.SendIkeAsync(ike.BuildDeleteIsakmp())).ConfigureAwait(false);
                }
                await Task.Delay(200).ConfigureAwait(false); // let the datagrams leave before the socket closes
            });

            await Task.WhenAny(teardown, Task.Delay(TimeSpan.FromSeconds(2))).ConfigureAwait(false);
        }

        static async Task Swallow(Func<Task> action)
        {
            try { await action().ConfigureAwait(false); } catch { }
        }

        /// <inheritdoc/>
        public async ValueTask DisposeAsync()
        {
            try { await DisconnectAsync().ConfigureAwait(false); } catch { }
        }

        /// <inheritdoc/>
        public void Dispose()
        {
            // Prefer DisposeAsync; this offloads to the thread pool to avoid a sync-context deadlock on the block.
            try { Task.Run(() => DisconnectAsync()).GetAwaiter().GetResult(); } catch { }
        }
    }
}
