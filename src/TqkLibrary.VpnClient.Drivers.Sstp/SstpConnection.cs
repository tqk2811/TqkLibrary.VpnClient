using System.IO;
using System.Net;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Authentication;
using System.Security.Cryptography;
using Microsoft.Extensions.Logging;
using TqkLibrary.VpnClient.Abstractions.Channels;
using TqkLibrary.VpnClient.Abstractions.Channels.Interfaces;
using TqkLibrary.VpnClient.Abstractions.Diagnostics.Extensions;
using TqkLibrary.VpnClient.Abstractions.Drivers;
using TqkLibrary.VpnClient.Abstractions.Drivers.Models;
using TqkLibrary.VpnClient.Abstractions.Net;
using TqkLibrary.VpnClient.Abstractions.Transport.Interfaces;
using TqkLibrary.VpnClient.Drivers.Core;
using TqkLibrary.VpnClient.Drivers.Sstp.Enums;
using TqkLibrary.VpnClient.Drivers.Sstp.Models;
using TqkLibrary.VpnClient.Ppp;
using TqkLibrary.VpnClient.Transport.Tls;
using TqkLibrary.VpnClient.Ppp.Auth;
using TqkLibrary.VpnClient.Ppp.Ipv6;

namespace TqkLibrary.VpnClient.Drivers.Sstp
{
    /// <summary>
    /// A complete MS-SSTP client connection: TLS + SSTP control + PPP + MS-CHAPv2 + crypto binding + IPCP.
    /// After <see cref="ConnectAsync"/> the tunnel carries IP traffic via the stable <see cref="PacketChannel"/>.
    /// Keepalive (active SSTP Echo + missed-response detection) and clean teardown (Call-Disconnect) are SSTP-specific;
    /// link-loss detection, auto-reconnect (backoff/jitter), the state machine and the stable facade are factored into
    /// the shared supervisor (<see cref="ReconnectingVpnConnection"/>, roadmap F.6), mirroring the
    /// OpenConnect / OpenVPN / WireGuard / SoftEther drivers: a dropped tunnel is re-established behind that same channel.
    /// </summary>
    public sealed class SstpConnection : ReconnectingVpnConnection, IDisposable, IAsyncDisposable
    {
        static readonly TimeSpan EchoInterval = TimeSpan.FromSeconds(30);
        const int EchoMaxMissed = 3;
        const string DriverNameConst = "sstp";

        readonly string _host;
        readonly int _port;
        readonly uint _magic;
        readonly bool _enableIpv6;
        readonly SstpReconnectOptions _opts;
        readonly Func<ITlsByteStream> _transportFactory;

        readonly IPppIpv6Autoconfigurator _ipv6Autoconfig = new PppIpv6Autoconfigurator();

        string? _userName;
        string? _password;
        IPAddress? _lastAssignedAddress;
        TunnelConfig? _ipv6Config;

        SstpTransport? _transport;
        SstpPppChannel? _channel;
        PppEngine? _engine;
        CancellationTokenSource? _loopCts;

        System.Threading.Timer? _echoTimer;
        int _attemptId;
        int _echoMissed;

        /// <summary>
        /// Creates a connection to the given SSTP server. <paramref name="transportFactory"/> supplies the TLS byte
        /// stream for each attempt (default: a real <see cref="TlsByteStream"/>); an offline test injects a fake stream
        /// here to exercise the handshake/keepalive/reconnect supervisor without a live server.
        /// <paramref name="certificateValidationCallback"/> validates the server TLS certificate of the default
        /// transport (null ⇒ accept any cert); it is ignored when an explicit <paramref name="transportFactory"/> is given.
        /// Set <paramref name="enableIpv6"/> to also run IPV6CP (RFC 5072) for a link-local IPv6 address alongside IPCP
        /// (best-effort: a server without IPv6 support simply never opens IPV6CP and the IPv4 link is unaffected).
        /// <paramref name="loggerFactory"/> receives diagnostic traces (handshake/keepalive/reconnect); null logs to
        /// a no-op logger.
        /// </summary>
        public SstpConnection(string host, int port = 443, uint magic = 0x1A2B3C4D, SstpReconnectOptions? reconnectOptions = null,
            Func<ITlsByteStream>? transportFactory = null, RemoteCertificateValidationCallback? certificateValidationCallback = null,
            AddressFamilyPreference addressFamilyPreference = AddressFamilyPreference.Auto, bool enableIpv6 = false,
            ILoggerFactory? loggerFactory = null)
            : base(DriverNameConst, reconnectOptions ?? new SstpReconnectOptions(), clock: null, loggerFactory: loggerFactory)
        {
            _host = host;
            _port = port;
            _magic = magic;
            _enableIpv6 = enableIpv6;
            _opts = reconnectOptions ?? new SstpReconnectOptions();
            _transportFactory = transportFactory ?? (() => new TlsByteStream(_host, _port, certificateValidationCallback, addressFamilyPreference));
        }

        /// <summary>The IP address assigned by the server (tracks the latest attempt).</summary>
        public IPAddress AssignedAddress => _engine!.AssignedAddress;

        /// <summary>The DNS server pushed by the server, if any (tracks the latest attempt).</summary>
        public IPAddress? AssignedDns => _engine!.AssignedDns;

        /// <summary>
        /// The IPv6 address for the tunnel: the global address obtained over the link (SLAAC/DHCPv6) when one was acquired,
        /// otherwise the IPV6CP link-local — or null (IPv6 disabled / server has no IPV6CP).
        /// </summary>
        public IPAddress? AssignedAddressV6 => _ipv6Config?.AssignedAddressV6 ?? _engine?.AssignedAddressV6;

        /// <summary>
        /// The global IPv6 configuration obtained over the PPP link (prefix length, IPv6 DNS, <c>::/0</c> default route),
        /// or null when only the IPV6CP link-local is available. The driver merges this into the <see cref="TunnelConfig"/>.
        /// </summary>
        public TunnelConfig? Ipv6Config => _ipv6Config;

        /// <summary>Raised after a successful auto-reconnect, carrying the new address and whether it changed.</summary>
        public event Action<SstpReconnectInfo>? Reconnected;

        /// <summary>Connects and authenticates, returning once IPCP has assigned an address.</summary>
        public async Task ConnectAsync(string userName, string password, CancellationToken cancellationToken = default)
        {
            _userName = userName;
            _password = password;

            await ConnectCoreAsync(cancellationToken).ConfigureAwait(false);
            _lastAssignedAddress = _engine!.AssignedAddress;
        }

        // ---- one full tunnel attempt (reused by the first connect and every reconnect) ----

        /// <summary>
        /// Brings up one full tunnel attempt from scratch: a clean-slate factory reused by the first connect and by
        /// every reconnect. On success the fresh PPP channel is installed behind the stable facade and keepalive starts.
        /// </summary>
        protected override async Task EstablishAsync(CancellationToken cancellationToken)
        {
            await CleanupAttemptResourcesAsync().ConfigureAwait(false);
            int attemptId = Interlocked.Increment(ref _attemptId); // bump BEFORE the new read loop starts
            Interlocked.Exchange(ref _echoMissed, 0);

            var transport = new SstpTransport(_transportFactory(), _host, _opts.ReadTimeout);
            _transport = transport;

            // TLS + SSTP_DUPLEX_POST handshake. Reclassify the transport's generic failures into typed VPN errors.
            Logger.LogHandshake(DriverName, "TLS + SSTP_DUPLEX_POST handshake");
            try
            {
                await transport.ConnectAsync(cancellationToken).ConfigureAwait(false);
            }
            catch (OperationCanceledException)
            {
                throw; // caller cancellation propagates unchanged — not a network timeout
            }
            catch (InvalidOperationException ex)
            {
                throw new VpnServerRejectedException("The SSTP server rejected the HTTP handshake.", ex); // non-200 status
            }
            catch (SocketException ex)
            {
                throw new VpnNetworkTimeoutException("The SSTP gateway did not respond.", ex);
            }
            catch (AuthenticationException ex)
            {
                throw new VpnNetworkTimeoutException("The SSTP TLS handshake did not complete.", ex);
            }
            catch (TimeoutException ex)
            {
                throw new VpnNetworkTimeoutException("The SSTP gateway went silent during the HTTP handshake.", ex);
            }
            catch (IOException ex)
            {
                throw new VpnNetworkTimeoutException("The SSTP TLS connection closed during the handshake.", ex);
            }
            catch (Exception ex)
            {
                throw new VpnConnectionException("Failed to establish the SSTP TLS transport.", ex);
            }

            // Call Connect Request → Call Connect Ack (carries the 32-byte crypto-binding nonce).
            Logger.LogHandshake(DriverName, "Call-Connect-Request -> Call-Connect-Ack (crypto-binding nonce)");
            var encapsulatedProtocol = new SstpAttribute((byte)SstpAttributeId.EncapsulatedProtocolId, new byte[] { 0x00, 0x01 });
            await transport.SendControlAsync(SstpMessageType.CallConnectRequest, new[] { encapsulatedProtocol }, cancellationToken).ConfigureAwait(false);

            byte[] ackBody;
            try
            {
                (_, ackBody) = await transport.ReadPacketAsync(cancellationToken).ConfigureAwait(false);
            }
            catch (TimeoutException ex)
            {
                throw new VpnNetworkTimeoutException("The SSTP gateway did not return a Call-Connect-Ack in time.", ex);
            }
            SstpControlMessage ack = SstpControlCodec.Parse(ackBody);
            if (ack.MessageType == SstpMessageType.CallConnectNak)
                throw new VpnServerRejectedException("The SSTP server returned Call-Connect-Nak.");
            if (ack.MessageType != SstpMessageType.CallConnectAck)
                throw new VpnServerRejectedException($"Expected SSTP Call-Connect-Ack, got {ack.MessageType}.");

            SstpAttribute cryptoRequest = ack.Find(SstpAttributeId.CryptoBindingReq)
                ?? throw new VpnServerRejectedException("The SSTP Call-Connect-Ack has no crypto-binding request.");
            if (cryptoRequest.Value.Length < 4 + SstpConstants.NonceLength)
                throw new VpnServerRejectedException("The SSTP crypto-binding request is too short to contain a 32-byte nonce.");
            byte[] nonce = new byte[SstpConstants.NonceLength];
            Buffer.BlockCopy(cryptoRequest.Value, 4, nonce, 0, SstpConstants.NonceLength); // Reserved(3) + Bitmask(1) + Nonce(32)

            var channel = new SstpPppChannel(transport);
            channel.ControlReceived += OnControlReceived;
            _channel = channel;

            var authenticator = new MsChapV2Authenticator(_userName ?? string.Empty, _password ?? string.Empty);
            var engine = new PppEngine(channel, _magic, IPAddress.Any, authenticator: authenticator, enableIpv6: _enableIpv6, logger: Logger);
            _engine = engine;
            _ipv6Config = null;   // fresh per attempt; the previous attempt's global address must not leak
            var ipv6Up = new TaskCompletionSource<bool>(TaskCreationOptions.RunContinuationsAsynchronously);
            engine.Ipv6Up += () => ipv6Up.TrySetResult(true);

            var linkUp = new TaskCompletionSource<bool>(TaskCreationOptions.RunContinuationsAsynchronously);
            // Capture per-attempt locals (transport/authenticator/nonce) so a stale closure never sends the wrong binding.
            engine.AuthSucceeded += () =>
            {
                try
                {
                    byte[] hlak = authenticator.DeriveHlak();
                    byte[] certHash;
                    using (var sha256 = SHA256.Create())
                        certHash = sha256.ComputeHash(transport.ServerCertificate!.RawData);
                    SstpAttribute cryptoBinding = SstpCryptoBinding.BuildCryptoBinding(hlak, nonce, certHash);
                    _ = transport.SendControlAsync(SstpMessageType.CallConnected, new[] { cryptoBinding }, cancellationToken);
                }
                catch { /* binding send failed; the link simply won't come up and the handshake fails */ }
            };
            engine.AuthSucceeded += () => Logger.LogHandshake(DriverName, "PPP MS-CHAPv2 authentication succeeded; sending crypto binding");
            engine.AuthFailed += () =>
            {
                Logger.LogHandshakeFailed(DriverName, "PPP MS-CHAPv2 authentication failed");
                linkUp.TrySetException(new VpnAuthenticationException("SSTP PPP MS-CHAPv2 authentication failed."));
            };
            engine.LinkUp += () => linkUp.TrySetResult(true);

            var loopCts = CancellationTokenSource.CreateLinkedTokenSource(LifetimeToken, cancellationToken);
            _loopCts = loopCts;
            CancellationToken loopToken = loopCts.Token;
            Task loopTask = Task.Run(() => channel.RunReadLoopAsync(loopToken));
            // The read loop ending is SSTP's primary drop signal. Route it through OnReadLoopEnded, which filters out
            // a loop that ended because of cancellation (teardown) or because a newer attempt superseded this one.
            _ = loopTask.ContinueWith(
                _ => OnReadLoopEnded(attemptId, loopToken.IsCancellationRequested),
                CancellationToken.None, TaskContinuationOptions.None, TaskScheduler.Default);

            engine.Start();

            await WaitForLinkUpAsync(linkUp.Task, loopTask, channel, cancellationToken).ConfigureAwait(false);
            await AwaitIpv6GraceAsync(engine, ipv6Up.Task, cancellationToken).ConfigureAwait(false);
            await TryConfigureGlobalIpv6Async(engine, cancellationToken).ConfigureAwait(false);

            Facade.SetInner(engine.PacketChannel);
            StartKeepalive();
            // If the loop died during the handshake window (before keepalive was running) OnReadLoopEnded no-op'd; re-check.
            if (loopTask.IsCompleted) OnReadLoopEnded(attemptId, loopToken.IsCancellationRequested);
        }

        // Waits for IPCP link-up, faulting if the read loop dies first (server closed mid-handshake) or the caller cancels.
        async Task WaitForLinkUpAsync(Task<bool> linkUp, Task loopTask, SstpPppChannel channel, CancellationToken cancellationToken)
        {
            var cancelled = new TaskCompletionSource<bool>(TaskCreationOptions.RunContinuationsAsynchronously);
            using (cancellationToken.Register(() => cancelled.TrySetResult(true)))
            {
                Task done = await Task.WhenAny(linkUp, loopTask, cancelled.Task).ConfigureAwait(false);
                if (done == cancelled.Task) cancellationToken.ThrowIfCancellationRequested();
            }
            if (linkUp.IsCompleted) { await linkUp.ConfigureAwait(false); return; } // success, or rethrow AuthFailed
            throw new VpnConnectionException("The SSTP connection closed during the handshake.",
                channel.ReadError ?? new IOException("connection closed"));
        }

        // IPV6CP runs in parallel with IPCP and usually opens around the same time; give it a short grace after IPv4
        // link-up so the link-local address is surfaced in TunnelConfig. A server without IPv6 never opens IPV6CP — we
        // never fail on it (IPv6 is best-effort), and a no-op when disabled or already up keeps the IPv4 path unchanged.
        async Task AwaitIpv6GraceAsync(PppEngine engine, Task<bool> ipv6Up, CancellationToken cancellationToken)
        {
            if (!_enableIpv6 || engine.IsIpv6Up) return;
            using var grace = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
            grace.CancelAfter(TimeSpan.FromSeconds(2));
            try { await Task.WhenAny(ipv6Up, Task.Delay(Timeout.Infinite, grace.Token)).ConfigureAwait(false); }
            catch (OperationCanceledException) when (!cancellationToken.IsCancellationRequested) { } // grace elapsed, no IPv6
        }

        // After IPV6CP brings up the link-local, solicit a Router Advertisement (or DHCPv6) over the PPP link to obtain a
        // routable global IPv6 address (P1.1). Best-effort and only when IPV6CP actually opened: the interface identifier
        // is the low 64 bits of the link-local (what IPV6CP negotiated). A server with no on-link IPv6 routing leaves the
        // link-local in place; any failure here must never fail an otherwise-good IPv4 + link-local tunnel.
        async Task TryConfigureGlobalIpv6Async(PppEngine engine, CancellationToken cancellationToken)
        {
            if (!_enableIpv6 || !engine.IsIpv6Up) return;
            IPAddress? linkLocal = engine.AssignedAddressV6;
            if (linkLocal is null || linkLocal.AddressFamily != AddressFamily.InterNetworkV6) return;
            byte[] interfaceId = new byte[8];
            Array.Copy(linkLocal.GetAddressBytes(), 8, interfaceId, 0, 8);
            try
            {
                _ipv6Config = await _ipv6Autoconfig.TryConfigureAsync(engine.PacketChannel, linkLocal, interfaceId, cancellationToken).ConfigureAwait(false);
                if (_ipv6Config?.AssignedAddressV6 != null)
                    Logger.LogHandshake(DriverName, $"obtained global IPv6 {_ipv6Config.AssignedAddressV6}/{_ipv6Config.PrefixLengthV6} over the PPP link");
            }
            catch (OperationCanceledException) { throw; }                              // teardown — abort the attempt
            catch (Exception ex) { Logger.LogHandshake(DriverName, $"global IPv6 over PPP unavailable ({ex.GetType().Name}); keeping link-local"); }
        }

        // Tears down the resources of the previous attempt before a fresh one (no-op on the very first attempt).
        /// <inheritdoc/>
        protected override Task CleanupAttemptResourcesAsync()
        {
            StopAttemptLoop();

            if (_channel != null) _channel.ControlReceived -= OnControlReceived;

            CancellationTokenSource? loop = _loopCts;
            _loopCts = null;
            try { loop?.Cancel(); } catch { }
            loop?.Dispose();

            _transport?.Dispose();
            _engine?.Dispose();   // stop the PPP negotiators' Restart timers before abandoning the engine

            _transport = null;
            _channel = null;
            _engine = null;
            return Task.CompletedTask;
        }

        void OnControlReceived(SstpControlMessage message)
        {
            switch (message.MessageType)
            {
                case SstpMessageType.EchoRequest:
                    Interlocked.Exchange(ref _echoMissed, 0); // an inbound probe proves the peer is alive
                    _ = SendControlSafeAsync(SstpMessageType.EchoResponse);
                    break;
                case SstpMessageType.EchoResponse:
                    Interlocked.Exchange(ref _echoMissed, 0);
                    break;
                case SstpMessageType.CallDisconnect:
                    _ = SendControlSafeAsync(SstpMessageType.CallDisconnectAck);
                    OnLinkLost("server sent SSTP Call-Disconnect.");
                    break;
                case SstpMessageType.CallAbort:
                    OnLinkLost("server sent SSTP Call-Abort.");
                    break;
            }
        }

        // SSTP's primary drop detector. Filters a loop that ended due to cancellation (teardown) or supersession.
        void OnReadLoopEnded(int attemptId, bool wasCancelled)
        {
            if (wasCancelled) return;                                  // teardown/cleanup cancelled this loop
            if (Volatile.Read(ref _attemptId) != attemptId) return;    // a newer attempt owns the connection now
            OnLinkLost("SSTP read loop ended (" + (_channel?.ReadError?.Message ?? "EOF") + ").");
        }

        // ---- keepalive: active SSTP Echo-Request + missed-response detection ----

        void StartKeepalive()
        {
            Logger.LogHandshakeCompleted(DriverName);
            MarkConnected();
            _echoTimer = new System.Threading.Timer(_ => _ = SendEchoTickAsync(), null, EchoInterval, EchoInterval);
        }

        /// <summary>Stops the per-attempt keepalive timer (the shared supervisor drives the run/teardown flags around it).</summary>
        protected override void StopAttemptLoop()
        {
            _echoTimer?.Dispose();
            _echoTimer = null;
        }

        async Task SendEchoTickAsync()
        {
            if (!IsRunning) return;
            if (Interlocked.CompareExchange(ref _echoMissed, 0, 0) >= EchoMaxMissed)
            {
                OnLinkLost("SSTP keepalive: server stopped answering Echo-Request.");
                return;
            }
            Interlocked.Increment(ref _echoMissed);
            Logger.LogKeepalive(DriverName, "sent SSTP Echo-Request");
            try { await SendControlSafeAsync(SstpMessageType.EchoRequest).ConfigureAwait(false); }
            catch { }
        }

        // async (not a Task-returning helper) so the await sits inside the try/catch: a faulted send against a
        // disposed transport is swallowed here rather than escaping as an unobserved task exception (cf. L2TP SendDpdAckAsync).
        async Task SendControlSafeAsync(SstpMessageType type)
        {
            SstpTransport? transport = _transport;
            if (transport == null) return;
            try { await transport.SendControlAsync(type, Array.Empty<SstpAttribute>(), CancellationToken.None).ConfigureAwait(false); }
            catch { }
        }

        // ---- link-loss handling + auto-reconnect supervisor live in ReconnectingVpnConnection (roadmap F.6). ----
        // The read loop ending / missed echoes / a server Call-Disconnect/Call-Abort call the inherited OnLinkLost,
        // which arms the shared ReconnectLoopAsync.

        /// <inheritdoc/>
        protected override void OnReconnected()
        {
            IPAddress newAddress = _engine!.AssignedAddress;
            bool changed = _lastAssignedAddress != null && !newAddress.Equals(_lastAssignedAddress);
            _lastAssignedAddress = newAddress;
            Reconnected?.Invoke(new SstpReconnectInfo(newAddress, changed));
        }

        // ---- teardown ----

        /// <summary>
        /// Tears the tunnel down gracefully and permanently (no reconnect): sends a best-effort SSTP Call-Disconnect,
        /// then runs the shared teardown (cancel any reconnect in flight, cancel the read loop, dispose the transport).
        /// Best-effort and time-boxed; safe to call more than once.
        /// </summary>
        public override async Task DisconnectAsync(CancellationToken cancellationToken = default)
        {
            // Notify the peer first so it releases the call immediately instead of waiting for the stream to drop.
            await SendTeardownAsync().ConfigureAwait(false);

            await DisconnectCoreAsync().ConfigureAwait(false);

            _userName = null;
            _password = null;
        }

        async Task SendTeardownAsync()
        {
            SstpTransport? transport = _transport;
            if (transport == null) return;

            Task teardown = Task.Run(async () =>
            {
                await Swallow(() => transport.SendControlAsync(SstpMessageType.CallDisconnect, Array.Empty<SstpAttribute>())).ConfigureAwait(false);
                await Task.Delay(200).ConfigureAwait(false); // let the datagram leave before the socket closes
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
