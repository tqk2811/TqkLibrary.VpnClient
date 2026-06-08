using System.Net;
using System.Net.Sockets;
using TqkLibrary.Vpn.Abstractions.Channels.Interfaces;
using TqkLibrary.Vpn.Drivers.L2tpIpsec.Enums;
using TqkLibrary.Vpn.Ipsec.Esp;
using TqkLibrary.Vpn.Ipsec.Ike.V1;
using TqkLibrary.Vpn.Ipsec.Ike.V1.Enums;
using TqkLibrary.Vpn.Ipsec.Ike.V1.Models;
using TqkLibrary.Vpn.L2tp;
using TqkLibrary.Vpn.Ppp;
using TqkLibrary.Vpn.Ppp.Auth;
using TqkLibrary.Vpn.Transport.Udp;

namespace TqkLibrary.Vpn.Drivers.L2tpIpsec
{
    /// <summary>
    /// A complete L2TP/IPsec client: IKEv1 Main Mode + Quick Mode (PSK) over UDP/500→4500 NAT-T, an ESP transport-mode
    /// data plane, an L2TP tunnel/session over UDP/1701, and a PPP session (MS-CHAPv2) that yields the assigned IP.
    /// After <see cref="ConnectAsync"/> the tunnel carries IP traffic via <see cref="PacketChannel"/>.
    /// </summary>
    public sealed class L2tpIpsecConnection : IDisposable
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
        volatile bool _keepaliveRunning;
        L2tpIpsecConnectionState _state = L2tpIpsecConnectionState.Disconnected;

        /// <summary>Creates a connection to the given L2TP/IPsec gateway with the IPsec pre-shared key.</summary>
        public L2tpIpsecConnection(string host, byte[] preSharedKey, uint magic = 0x4D2A3B1C)
        {
            _host = host;
            _preSharedKey = preSharedKey;
            _magic = magic;
        }

        /// <summary>The L3 packet channel (valid after a successful connect).</summary>
        public IPacketChannel PacketChannel => _ppp!.PacketChannel;

        /// <summary>The IP address assigned by the server via IPCP.</summary>
        public IPAddress AssignedAddress => _ppp!.AssignedAddress;

        /// <summary>The DNS server pushed by IPCP, if any.</summary>
        public IPAddress? AssignedDns => _ppp!.AssignedDns;

        /// <summary>Raised whenever the connection state changes (handshake progress, keepalive-detected drop).</summary>
        public event Action<L2tpIpsecConnectionState>? StateChanged;

        /// <summary>The current lifecycle state.</summary>
        public L2tpIpsecConnectionState State => _state;

        /// <summary>Runs the full handshake and returns once PPP/IPCP has assigned an address.</summary>
        public async Task ConnectAsync(string userName, string password, CancellationToken cancellationToken = default)
        {
            SetState(L2tpIpsecConnectionState.Connecting);
            IPAddress serverIp = await ResolveAsync(_host).ConfigureAwait(false);
            _natt = new NatTraversalChannel(serverIp, NatTraversal.IkePort);
            _loopCts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
            _ = Task.Run(() => ReceiveLoopAsync(_loopCts.Token));

            var ike = new IkeV1Client(_preSharedKey, IPAddress.Any, serverIp);
            _ike = ike;

            // Phase 1 — Main Mode (messages 1-4 on UDP/500).
            ike.ProcessMainMode2(await ExchangeIkeAsync(ike.BuildMainMode1(), cancellationToken).ConfigureAwait(false));
            ike.ProcessMainMode4(await ExchangeIkeAsync(ike.BuildMainMode3(IPAddress.Any, serverIp), cancellationToken).ConfigureAwait(false));

            // NAT-T detected → move to UDP/4500 for the encrypted MM5/MM6 and all of Quick Mode + ESP.
            _natt.SwitchToNatTPort();
            if (!ike.ProcessMainMode6(await ExchangeIkeAsync(ike.BuildMainMode5(), cancellationToken).ConfigureAwait(false)))
                throw new IOException("IKEv1 Phase 1 authentication failed (PSK / HASH_R mismatch).");

            // Phase 2 — Quick Mode.
            if (!ike.ProcessQuickMode2(await ExchangeIkeAsync(ike.BuildQuickMode1(), cancellationToken).ConfigureAwait(false)))
                throw new IOException("IKEv1 Quick Mode failed (no ESP SA).");
            await _natt.SendIkeAsync(ike.BuildQuickMode3()).ConfigureAwait(false); // QM3 has no reply

            // ESP data plane + L2TP + PPP.
            EspSession esp = BuildEspSession(ike.CreatePhase2Keys(), ike.ChildOutboundSpi, ike.ChildInboundSpi);
            _dataTransport = new IpsecL2tpTransport(esp, datagram => _natt.SendEspAsync(datagram));
            _espActive = true;

            _l2tp = new L2tpClient(_dataTransport);
            _l2tp.Disconnected += OnLinkLost;
            await _l2tp.ConnectAsync(cancellationToken).ConfigureAwait(false);

            var pppChannel = new L2tpPppFrameChannel(_l2tp);
            var authenticator = new MsChapV2Authenticator(userName, password);
            _ppp = new PppEngine(pppChannel, _magic, IPAddress.Any, authenticator: authenticator);

            var linkUp = new TaskCompletionSource<bool>(TaskCreationOptions.RunContinuationsAsynchronously);
            _ppp.LinkUp += () => linkUp.TrySetResult(true);
            _ppp.AuthFailed += () => linkUp.TrySetException(new IOException("PPP MS-CHAPv2 authentication failed."));
            _ppp.Start();

            await WaitAsync(linkUp.Task, cancellationToken).ConfigureAwait(false);

            // Handshake done: stop steering IKE to the handshake waiter and start the keepalive loops.
            _ikeWaiter = null;
            StartKeepalive();
        }

        static EspSession BuildEspSession(IkeV1Phase2Keys keys, byte[] outboundSpi, byte[] inboundSpi)
        {
            EspCipherSuite outbound = EspCipherSuite.AesCbcHmacSha1(keys.OutboundEncryption, keys.OutboundIntegrity);
            EspCipherSuite inbound = EspCipherSuite.AesCbcHmacSha1(keys.InboundEncryption, keys.InboundIntegrity);
            return new EspSession(ToSpi(outboundSpi), outbound, ToSpi(inboundSpi), inbound);
        }

        async Task<byte[]> ExchangeIkeAsync(byte[] request, CancellationToken cancellationToken)
        {
            for (int attempt = 0; attempt < 5; attempt++)
            {
                var waiter = new TaskCompletionSource<byte[]>(TaskCreationOptions.RunContinuationsAsynchronously);
                _ikeWaiter = waiter;
                await _natt!.SendIkeAsync(request).ConfigureAwait(false);

                Task completed = await Task.WhenAny(waiter.Task, Task.Delay(2500, cancellationToken)).ConfigureAwait(false);
                if (completed == waiter.Task) return await waiter.Task.ConfigureAwait(false);
                cancellationToken.ThrowIfCancellationRequested();
            }
            throw new TimeoutException("No IKE response from the gateway.");
        }

        async Task ReceiveLoopAsync(CancellationToken cancellationToken)
        {
            try
            {
                while (!cancellationToken.IsCancellationRequested)
                {
                    (NatTPacketKind kind, byte[] payload) = await _natt!.ReceiveAsync(cancellationToken).ConfigureAwait(false);
                    if (kind == NatTPacketKind.Ike)
                    {
                        TaskCompletionSource<byte[]>? waiter = _ikeWaiter;
                        TaskCompletionSource<byte[]>? rekey = _rekeyWaiter;
                        if (waiter != null)
                            waiter.TrySetResult(payload);                  // a handshake reply
                        else if (rekey != null && _ike!.IsRekeyReply(payload))
                            rekey.TrySetResult(payload);                   // a rekey Quick Mode reply
                        else
                            HandleInboundIke(payload);                     // steady-state DPD / Delete
                    }
                    else if (kind == NatTPacketKind.Esp && _espActive)
                        _dataTransport?.OnEspPacket(payload);
                }
            }
            catch (OperationCanceledException) { }
            catch (Exception ex) { _ikeWaiter?.TrySetException(ex); }
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
            try { await _l2tp!.SendHelloAsync().ConfigureAwait(false); }
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
            try { await _natt!.SendIkeAsync(_ike!.BuildDpdRUThere(sequence)).ConfigureAwait(false); }
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
            try { await _natt!.SendIkeAsync(ike.BuildDpdAck(sequence)).ConfigureAwait(false); }
            catch { }
        }

        // ---- rekey: refresh the ESP CHILD SA on the live IKE SA (make-before-break) ----

        async Task RekeyPhase2Async()
        {
            if (!_keepaliveRunning) return;
            IkeV1Client ike = _ike!;
            try
            {
                byte[] reply = await ExchangeRekeyAsync(ike.BuildRekeyQuickMode1()).ConfigureAwait(false);
                if (!ike.ProcessRekeyQuickMode2(reply)) return; // keep the current SA; retry at the next interval
                await _natt!.SendIkeAsync(ike.BuildRekeyQuickMode3()).ConfigureAwait(false);

                EspSession next = BuildEspSession(ike.CreateRekeyPhase2Keys(), ike.RekeyChildOutboundSpi, ike.RekeyChildInboundSpi);
                _dataTransport!.SwapSession(next);
                ScheduleDropPreviousInbound();
            }
            catch { /* rekey failed; the current SA stays active — DPD declares the peer dead if it is truly gone */ }
        }

        async Task<byte[]> ExchangeRekeyAsync(byte[] request)
        {
            for (int attempt = 0; attempt < 5 && _keepaliveRunning; attempt++)
            {
                var waiter = new TaskCompletionSource<byte[]>(TaskCreationOptions.RunContinuationsAsynchronously);
                _rekeyWaiter = waiter;
                await _natt!.SendIkeAsync(request).ConfigureAwait(false);

                Task completed = await Task.WhenAny(waiter.Task, Task.Delay(2500)).ConfigureAwait(false);
                _rekeyWaiter = null;
                if (completed == waiter.Task) return await waiter.Task.ConfigureAwait(false);
            }
            throw new TimeoutException("No Quick Mode rekey response from the gateway.");
        }

        void ScheduleDropPreviousInbound()
        {
            _dropTimer?.Dispose();
            _dropTimer = new System.Threading.Timer(
                _ => { try { _dataTransport?.DropPreviousInbound(); } catch { } },
                null, RekeyGrace, System.Threading.Timeout.InfiniteTimeSpan);
        }

        void OnLinkLost(string reason)
        {
            if (!_keepaliveRunning) return;
            StopKeepalive();
            _espActive = false;
            SetState(L2tpIpsecConnectionState.Disconnected);
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
            return addresses.First(a => a.AddressFamily == AddressFamily.InterNetwork);
        }

        static uint ToSpi(byte[] spi) => (uint)((spi[0] << 24) | (spi[1] << 16) | (spi[2] << 8) | spi[3]);

        /// <inheritdoc/>
        public void Dispose()
        {
            StopKeepalive();
            SetState(L2tpIpsecConnectionState.Disconnected);
            _loopCts?.Cancel();
            _l2tp?.Dispose();
            _ = _natt?.DisposeAsync();
        }
    }
}
