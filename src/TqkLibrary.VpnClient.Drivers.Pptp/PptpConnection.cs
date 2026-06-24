using System.Net;
using Microsoft.Extensions.Logging;
using TqkLibrary.VpnClient.Abstractions.Diagnostics.Extensions;
using TqkLibrary.VpnClient.Abstractions.Drivers;
using TqkLibrary.VpnClient.Abstractions.Drivers.Models;
using TqkLibrary.VpnClient.Abstractions.Net;
using TqkLibrary.VpnClient.Abstractions.Transport.Interfaces;
using TqkLibrary.VpnClient.Drivers.Core;
using TqkLibrary.VpnClient.Drivers.Pptp.Enums;
using TqkLibrary.VpnClient.Drivers.Pptp.Models;
using TqkLibrary.VpnClient.Drivers.Pptp.Transport;
using TqkLibrary.VpnClient.Ppp;
using TqkLibrary.VpnClient.Ppp.Auth;
using TqkLibrary.VpnClient.Pptp;
using TqkLibrary.VpnClient.Pptp.Ccp;
using TqkLibrary.VpnClient.Pptp.Enums;
using TqkLibrary.VpnClient.Pptp.Gre;

namespace TqkLibrary.VpnClient.Drivers.Pptp
{
    /// <summary>
    /// A complete PPTP client (RFC 2637): a TCP/1723 control connection (Start-Control-Connection + Outgoing-Call),
    /// a GRE (IP proto-47) data plane keyed by the negotiated Call-IDs, MPPE (RFC 3078/3079) over CCP, and a PPP
    /// session (MS-CHAPv2) that yields the assigned IP. After <see cref="ConnectAsync"/> the tunnel carries IP
    /// traffic via the stable <see cref="ReconnectingVpnConnection{TState}.PacketChannel"/>; when auto-reconnect is
    /// enabled a dropped tunnel is re-established behind that same channel.
    /// <para>This is "L2TP/IPsec minus IPsec/L2TP, plus GRE + MPPE": the link-loss → supervisor → reconnect-loop
    /// machinery (backoff/jitter, the stable <see cref="SwappablePacketChannel"/> facade, lifetime cancellation, the
    /// state changes + structured logging, the monotonic clock) lives in <see cref="ReconnectingVpnConnection{TState}"/>
    /// (roadmap F.6). This driver keeps only its protocol logic (<see cref="EstablishAsync"/> /
    /// <see cref="CleanupAttemptResourcesAsync"/> / the Echo-Request keepalive).</para>
    /// <para><b>PPTP + MS-CHAPv2 + MPPE/RC4 is cryptographically broken</b> — provided only for interop with legacy
    /// PPTP servers. GRE needs a raw-IP transport (<see cref="IRawIpTransportFactory"/>, roadmap F.9) which requires
    /// elevation.</para>
    /// </summary>
    public sealed class PptpConnection : ReconnectingVpnConnection<PptpConnectionState>, IDisposable, IAsyncDisposable
    {
        const string DriverNameConst = "pptp";
        const int GreIpProtocol = 47; // IANA IP protocol number for GRE (native, no UDP encapsulation)
        const ushort DefaultLocalCallId = 0x4000; // our GRE Call-ID; the PAC echoes it back as its PeerCallId

        readonly string _host;
        readonly int _port;
        readonly uint _magic;
        readonly PptpTimeoutOptions _timeouts;
        readonly IRawIpTransportFactory _rawIpFactory; // required: GRE rides a raw IP proto-47 socket
        readonly PptpControlTransportFactory _controlTransportFactory;
        readonly AddressFamilyPreference _addressFamilyPreference;
        readonly IHostResolver _hostResolver;

        string? _userName;
        string? _password;
        IPAddress? _lastAssignedAddress;

        IByteStreamTransport? _controlTransport;
        PptpControlConnection? _control;
        PptpGreChannel? _gre;
        PppEngine? _ppp;
        CancellationTokenSource? _loopCts;
        System.Threading.Timer? _echoTimer;

        /// <summary>
        /// Creates a connection to the given PPTP server. <paramref name="rawIpFactory"/> carries the GRE data plane
        /// (raw IP proto-47, requires elevation). <paramref name="controlTransportFactory"/> overrides how the TCP/1723
        /// control byte stream is opened (default: a real <see cref="PptpControlTcpTransport"/>); tests inject an
        /// in-memory stream. <paramref name="loggerFactory"/> receives diagnostic traces (null logs to a no-op logger).
        /// </summary>
        public PptpConnection(string host, IRawIpTransportFactory rawIpFactory, int port = PptpControlTcpTransport.DefaultPort,
            uint magic = 0x5B3C2A1D, PptpReconnectOptions? reconnectOptions = null, PptpTimeoutOptions? timeoutOptions = null,
            PptpControlTransportFactory? controlTransportFactory = null,
            AddressFamilyPreference addressFamilyPreference = AddressFamilyPreference.Auto, IHostResolver? hostResolver = null,
            ILoggerFactory? loggerFactory = null)
            : base(DriverNameConst, reconnectOptions ?? new PptpReconnectOptions(), clock: null, loggerFactory: loggerFactory)
        {
            _host = host ?? throw new ArgumentNullException(nameof(host));
            _rawIpFactory = rawIpFactory ?? throw new ArgumentNullException(nameof(rawIpFactory));
            _port = port;
            _magic = magic;
            _timeouts = timeoutOptions ?? new PptpTimeoutOptions();
            _hostResolver = hostResolver ?? DnsHostResolver.Default;
            _addressFamilyPreference = addressFamilyPreference;
            _controlTransportFactory = controlTransportFactory
                ?? ((endpoint, ct) => DefaultControlTransportAsync(endpoint, ct));
        }

        /// <summary>The IP address assigned by the server via IPCP (tracks the latest attempt).</summary>
        public IPAddress AssignedAddress => _ppp!.AssignedAddress;

        /// <summary>The DNS server pushed by IPCP, if any (tracks the latest attempt).</summary>
        public IPAddress? AssignedDns => _ppp!.AssignedDns;

        /// <summary>Raised after a successful auto-reconnect, carrying the new address and whether it changed.</summary>
        public event Action<PptpReconnectInfo>? Reconnected;

        /// <inheritdoc/>
        protected override PptpConnectionState DisconnectedState => PptpConnectionState.Disconnected;
        /// <inheritdoc/>
        protected override PptpConnectionState ConnectingState => PptpConnectionState.Connecting;
        /// <inheritdoc/>
        protected override PptpConnectionState ConnectedState => PptpConnectionState.Connected;
        /// <inheritdoc/>
        protected override PptpConnectionState ReconnectingState => PptpConnectionState.Reconnecting;

        /// <summary>Runs the full handshake and returns once PPP/IPCP has assigned an address.</summary>
        public async Task ConnectAsync(string userName, string password, CancellationToken cancellationToken = default)
        {
            _userName = userName;
            _password = password;

            await ConnectCoreAsync(cancellationToken).ConfigureAwait(false);
            _lastAssignedAddress = _ppp!.AssignedAddress;
        }

        // Default control-transport factory: a real plain-TCP byte stream to the PAC on the configured port, connected.
        async Task<IByteStreamTransport> DefaultControlTransportAsync(VpnEndpoint endpoint, CancellationToken cancellationToken)
        {
            var transport = new PptpControlTcpTransport(endpoint.Host, endpoint.Port, _addressFamilyPreference, _hostResolver);
            await transport.ConnectAsync(cancellationToken).ConfigureAwait(false);
            return transport;
        }

        /// <summary>
        /// Brings up one full tunnel attempt from scratch: a clean-slate factory reused by the first connect and by
        /// every reconnect. On success the fresh PPP channel is installed behind the stable facade and keepalive starts.
        /// </summary>
        protected override async Task EstablishAsync(CancellationToken cancellationToken)
        {
            await CleanupAttemptResourcesAsync().ConfigureAwait(false);

            string user = _userName ?? string.Empty;
            string password = _password ?? string.Empty;
            var endpoint = new VpnEndpoint(_host, _port, _addressFamilyPreference);

            // 1) Control connection over TCP/1723: SCCRQ ⇄ SCCRP, then OCRQ ⇄ OCRP → Local/Peer Call-IDs.
            Logger.LogHandshake(DriverName, "PPTP control connection (SCCRQ/SCCRP, OCRQ/OCRP)");
            IByteStreamTransport controlTransport = await _controlTransportFactory(endpoint, cancellationToken).ConfigureAwait(false);
            _controlTransport = controlTransport;
            var control = new PptpControlConnection(controlTransport, hostName: string.Empty);
            _control = control;
            await control.EstablishControlConnectionAsync(cancellationToken).ConfigureAwait(false);
            await control.PlaceOutgoingCallAsync(DefaultLocalCallId, cancellationToken).ConfigureAwait(false);

            // 2) GRE data plane over a raw IP proto-47 socket, keyed by the negotiated Call-IDs.
            IPAddress serverIp = await _hostResolver.ResolveAsync(_host, _addressFamilyPreference, cancellationToken).ConfigureAwait(false);
            IPAddress localIp = GetLocalAddress(serverIp);
            Logger.LogHandshake(DriverName, $"PPTP GRE data plane (raw IP proto-47, localCallId={control.LocalCallId}, peerCallId={control.PeerCallId})");
            IDatagramTransport greTransport = _rawIpFactory.Create(serverIp, GreIpProtocol, localBind: localIp);
            var gre = new PptpGreChannel(greTransport, control.LocalCallId, control.PeerCallId, Logger);
            _gre = gre;

            // 3) MS-CHAPv2 over CHAP; MPPE decorator (CCP) below PPP; PPP engine drives LCP/auth/IPCP above MPPE.
            // The engine defers IPCP/IPV6CP until CCP/MPPE is open: once MPPE is active every non-LCP packet (IPCP
            // included) must be encrypted, so a network-layer Configure-Request sent before CCP opens goes out in the
            // clear, the server Protocol-Rejects it, and the stray cleartext frame desyncs the server's MPPE state.
            var auth = new MsChapV2Authenticator(user, password);
            var mppe = new MppePppFrameChannel(gre, () => (password, auth.NtResponse!));
            var ppp = new PppEngine(mppe, _magic, IPAddress.Any, authenticator: auth, deferNetworkLayer: true, logger: Logger);
            _ppp = ppp;

            // CCP/MPPE starts only after MS-CHAPv2 succeeds (the NT-Response is the MPPE key material).
            ppp.AuthSucceeded += () =>
            {
                Logger.LogHandshake(DriverName, "PPP MS-CHAPv2 authentication succeeded; starting CCP/MPPE");
                mppe.StartCcp();
            };

            // Release the deferred network layer once CCP/MPPE is open, so IPCP/IPV6CP run encrypted from their first packet.
            mppe.CcpOpened += () =>
            {
                Logger.LogHandshake(DriverName, "CCP/MPPE opened; starting the network layer (IPCP) encrypted");
                ppp.StartNetworkLayer();
            };

            var linkUp = new TaskCompletionSource<bool>(TaskCreationOptions.RunContinuationsAsynchronously);
            ppp.LinkUp += () => linkUp.TrySetResult(true);
            ppp.AuthFailed += () =>
            {
                Logger.LogHandshakeFailed(DriverName, "PPP MS-CHAPv2 authentication failed");
                linkUp.TrySetException(new VpnAuthenticationException("PPP MS-CHAPv2 authentication failed."));
            };

            gre.Start();
            ppp.Start();

            // 4) Await auth → CCP/MPPE active → IPCP link-up, bounded by the handshake timeout.
            await AwaitHandshakeAsync(mppe.CcpOpenedTask, linkUp.Task, cancellationToken).ConfigureAwait(false);

            // 5) Publish the live plane behind the stable facade and start the Echo-Request keepalive.
            Facade.SetInner(ppp.PacketChannel);
            StartKeepalive();
        }

        // Waits for the MPPE CCP to open and IPCP to bring the link up, both within the handshake timeout. An
        // AuthFailed faults linkUp (surfaced as VpnAuthenticationException); a timeout surfaces as a network timeout.
        async Task AwaitHandshakeAsync(Task ccpOpened, Task linkUp, CancellationToken cancellationToken)
        {
            using var timeout = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
            timeout.CancelAfter(_timeouts.HandshakeTimeout);
            try
            {
                await WhenAllOrCancel(timeout.Token, ccpOpened, linkUp).ConfigureAwait(false);
            }
            catch (OperationCanceledException) when (!cancellationToken.IsCancellationRequested)
            {
                throw new VpnNetworkTimeoutException(
                    "The PPTP handshake (MS-CHAPv2 / CCP-MPPE / IPCP) did not complete before the timeout.");
            }
        }

        // Awaits every task, cancelling the wait (not the tasks) when the token fires. Faults from any task propagate.
        static async Task WhenAllOrCancel(CancellationToken cancellationToken, params Task[] tasks)
        {
            var cancelled = new TaskCompletionSource<bool>(TaskCreationOptions.RunContinuationsAsynchronously);
            using (cancellationToken.Register(() => cancelled.TrySetResult(true)))
            {
                Task all = Task.WhenAll(tasks);
                if (await Task.WhenAny(all, cancelled.Task).ConfigureAwait(false) != all)
                    cancellationToken.ThrowIfCancellationRequested();
                await all.ConfigureAwait(false);
            }
        }

        // The local source address the OS routes to this server through (a throwaway connected socket; no packet sent).
        // Falls back to Any so the raw-IP transport binds the default interface if it cannot be determined.
        static IPAddress GetLocalAddress(IPAddress serverIp)
        {
            try
            {
                using var probe = new System.Net.Sockets.Socket(serverIp.AddressFamily, System.Net.Sockets.SocketType.Dgram, System.Net.Sockets.ProtocolType.Udp);
                probe.Connect(serverIp, 9); // discard port; no datagram is actually sent
                return ((IPEndPoint)probe.LocalEndPoint!).Address;
            }
            catch
            {
                return serverIp.AddressFamily == System.Net.Sockets.AddressFamily.InterNetworkV6 ? IPAddress.IPv6Any : IPAddress.Any;
            }
        }

        // ---- keepalive: control-connection Echo-Request (RFC 2637 §2.13) ----

        void StartKeepalive()
        {
            Logger.LogHandshakeCompleted(DriverName);
            MarkConnected();
            _echoTimer = new System.Threading.Timer(_ => _ = SendEchoTickAsync(), null, _timeouts.EchoInterval, _timeouts.EchoInterval);
        }

        async Task SendEchoTickAsync()
        {
            if (!IsRunning) return;
            PptpControlConnection? control = _control; // snapshot: a concurrent teardown nulls the field
            if (control == null) return;
            Logger.LogKeepalive(DriverName, "sent PPTP Echo-Request");
            try { await control.SendEchoRequestAsync().ConfigureAwait(false); }
            catch (Exception ex)
            {
                // The control connection died (the peer closed TCP/1723). Declare the link lost so the supervisor
                // re-establishes; mirrors L2TP's HELLO/DPD failure → OnLinkLost.
                OnLinkLost("PPTP control connection lost: " + ex.Message);
            }
        }

        /// <summary>Stops the per-attempt keepalive timer (disposed under the state lock on link-loss/teardown).</summary>
        protected override void StopAttemptLoop()
        {
            _echoTimer?.Dispose();
            _echoTimer = null;
        }

        // Tears down the resources of the previous attempt before a fresh one (no-op on the very first attempt).
        /// <inheritdoc/>
        protected override async Task CleanupAttemptResourcesAsync()
        {
            StopAttemptLoop();

            CancellationTokenSource? loop = _loopCts;
            _loopCts = null;
            try { loop?.Cancel(); } catch { }
            loop?.Dispose();

            // Null the GRE channel before disposing it so a stale receive loop's identity guard trips immediately;
            // disposing it closes the raw socket (unblocking its ReceiveAsync) and stops the GRE receive loop.
            PptpGreChannel? gre = _gre;
            _gre = null;
            if (gre != null)
            {
                try { await gre.DisposeAsync().ConfigureAwait(false); } catch { }
            }

            // Clear the call + stop the control connection best-effort, then drop the underlying byte stream. The
            // graceful close is time-boxed so a non-responsive (or already-closed) peer can never deadlock teardown,
            // and each step is gated on the control state so we never send a Call-Clear on a connection that has no
            // call (mirrors L2TP's time-boxed best-effort teardown).
            PptpControlConnection? control = _control;
            _control = null;
            IByteStreamTransport? controlTransport = _controlTransport;
            _controlTransport = null;
            if (control != null)
            {
                Task graceful = Task.Run(async () =>
                {
                    if (control.State == PptpControlState.CallEstablished)
                        await Swallow(() => control.ClearCallAsync()).ConfigureAwait(false);
                    if (control.State == PptpControlState.ControlConnectionEstablished || control.State == PptpControlState.CallEstablished)
                        await Swallow(() => control.StopControlConnectionAsync()).ConfigureAwait(false);
                });
                await Task.WhenAny(graceful, Task.Delay(TimeSpan.FromSeconds(2))).ConfigureAwait(false);
            }
            if (controlTransport != null)
            {
                try { await controlTransport.DisposeAsync().ConfigureAwait(false); } catch { }
            }

            _ppp?.Dispose();   // stop the PPP negotiators' Restart timers before abandoning the engine
            _ppp = null;
        }

        /// <inheritdoc/>
        protected override void OnReconnected()
        {
            IPAddress newAddress = _ppp!.AssignedAddress;
            bool changed = _lastAssignedAddress != null && !newAddress.Equals(_lastAssignedAddress);
            _lastAssignedAddress = newAddress;
            Reconnected?.Invoke(new PptpReconnectInfo(newAddress, changed));
        }

        /// <summary>
        /// Tears the tunnel down gracefully and permanently (no reconnect): the shared teardown clears the call and
        /// stops the control connection best-effort (in <see cref="CleanupAttemptResourcesAsync"/>) then disposes the
        /// transports. Best-effort and time-boxed; safe to call more than once.
        /// </summary>
        public override async Task DisconnectAsync(CancellationToken cancellationToken = default)
        {
            await DisconnectCoreAsync().ConfigureAwait(false);
            _userName = null;
            _password = null;
        }

        static async Task Swallow(Func<Task> action)
        {
            try { await action().ConfigureAwait(false); } catch { }
        }

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
