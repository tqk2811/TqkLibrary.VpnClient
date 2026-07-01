using System;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.Logging;
using TqkLibrary.VpnClient.Abstractions.Diagnostics.Extensions;
using TqkLibrary.VpnClient.Abstractions.Drivers;
using TqkLibrary.VpnClient.Abstractions.Drivers.Models;
using TqkLibrary.VpnClient.Drivers.Core;
using TqkLibrary.VpnClient.Drivers.Tailscale.Config;
using TqkLibrary.VpnClient.Drivers.WireGuard;
using TqkLibrary.VpnClient.Drivers.WireGuard.Transport;
using TqkLibrary.VpnClient.Tailscale;
using TqkLibrary.VpnClient.Tailscale.Control;
using TqkLibrary.VpnClient.Tailscale.Control.Messages;
using TqkLibrary.VpnClient.Tailscale.Netmap;
using TqkLibrary.VpnClient.WireGuard.Config;

namespace TqkLibrary.VpnClient.Drivers.Tailscale
{
    /// <summary>
    /// The Tailscale connection. Its single establish step runs the ts2021 control plane — log into the coordination
    /// server (Headscale) with the preauth key, register the node and fetch the netmap (<see cref="TailscaleControlClient"/>)
    /// — then projects that netmap onto a multi-peer <see cref="WireGuardConfig"/> (<see cref="NetmapToWireGuardConfig"/>)
    /// and brings a real <see cref="WireGuardConnection"/> up from it. The WireGuard data plane is reused wholesale
    /// (Noise_IKpsk2 handshake + type-4 transport + crypto-routing + its own rekey/keepalive/auto-reconnect); this driver
    /// adds only the control plane that produces the peer list.
    /// <para>
    /// DERP relaying and disco NAT traversal are future work, so the netmap peers must be directly reachable. The inner
    /// WireGuard connection keeps its own auto-reconnect (the proven data-plane resilience); the outer reconnect
    /// supervisor here covers a control-plane failure during establish.
    /// </para>
    /// </summary>
    public sealed class TailscaleConnection : ReconnectingVpnConnection, IDisposable, IAsyncDisposable
    {
        const string DriverNameConst = "tailscale";

        readonly TailscaleConfig _config;
        readonly IWireGuardTransportFactory? _wireGuardTransportFactory;
        readonly Func<TailscaleConfig, ITailscaleControlClient>? _controlClientFactory;
        readonly ILoggerFactory? _loggerFactory;

        ITailscaleControlClient? _control;
        WireGuardConnection? _wireGuard;
        TunnelConfig _tunnelConfig = new TunnelConfig();

        /// <summary>
        /// Creates the connection. <paramref name="config"/> is the static profile (server URL, preauth key, the machine
        /// and node X25519 keys). <paramref name="wireGuardTransportFactory"/> overrides the WireGuard UDP transport
        /// (an in-process loopback drives the data plane offline in tests). <paramref name="controlClientFactory"/>
        /// overrides the ts2021 control client (a fake serves a canned netmap offline in tests); the default builds a
        /// real <see cref="TailscaleControlClient"/>. <paramref name="loggerFactory"/> receives diagnostic traces.
        /// </summary>
        public TailscaleConnection(TailscaleConfig config,
            TailscaleReconnectOptions? reconnectOptions = null,
            IWireGuardTransportFactory? wireGuardTransportFactory = null,
            Func<TailscaleConfig, ITailscaleControlClient>? controlClientFactory = null,
            ILoggerFactory? loggerFactory = null)
            : base(DriverNameConst, reconnectOptions ?? new TailscaleReconnectOptions(), clock: null, loggerFactory)
        {
            _config = config ?? throw new ArgumentNullException(nameof(config));
            _wireGuardTransportFactory = wireGuardTransportFactory;
            _controlClientFactory = controlClientFactory;
            _loggerFactory = loggerFactory;
        }

        /// <summary>The tunnel configuration derived from the netmap (self address, routes from peers' allowed-IPs, MTU).</summary>
        public TunnelConfig Config => _tunnelConfig;

        /// <summary>Runs the control login + netmap fetch + WireGuard bring-up and returns once the tunnel is up.</summary>
        public Task ConnectAsync(CancellationToken cancellationToken = default) => ConnectCoreAsync(cancellationToken);

        /// <inheritdoc/>
        protected override async Task EstablishAsync(CancellationToken cancellationToken)
        {
            await CleanupAttemptResourcesAsync().ConfigureAwait(false);

            // --- control plane: ts2021 login + netmap ---
            ITailscaleControlClient control = _controlClientFactory is not null
                ? _controlClientFactory(_config)
                : new TailscaleControlClientAdapter(_config);
            _control = control;

            Logger.LogHandshake(DriverName, $"ts2021 control login to {_config.ServerUrl} (preauth)");
            MapResponse map = await control.LoginAsync(_config.PreauthKey, cancellationToken).ConfigureAwait(false);
            Logger.LogHandshake(DriverName, $"netmap received: self={map.Node?.ID}, peers={(map.Peers?.Count ?? 0)}");

            // --- map the netmap onto a multi-peer WireGuard config ---
            var mapper = new NetmapToWireGuardConfig(_config.Mtu);
            WireGuardConfig wgConfig = mapper.Build(map, _config.NodePrivateKey,
                onPeerSkipped: reason => Logger.LogPacketDropped(DriverName, Abstractions.Diagnostics.Enums.VpnDropReason.NoRoute, "netmap peer skipped: " + reason));
            _tunnelConfig = wgConfig.ToTunnelConfig();
            if (wgConfig.Peers.Count == 0)
                throw new VpnConnectionException("Tailscale netmap produced no usable WireGuard peers (DERP relay is not implemented; peers must be directly reachable).");

            // --- data plane: reuse the WireGuard connection wholesale ---
            // The inner connection's host/port are placeholders (per-peer endpoints come from the netmap); the
            // crypto-router routes by allowed-IPs. The inner WireGuard keeps its own auto-reconnect (proven resilience).
            var first = wgConfig.Peers[0];
            string host = first.Endpoint?.Address.ToString() ?? "0.0.0.0";
            int port = first.Endpoint?.Port ?? 0;
            // A fixed local WG port (when configured) matches the endpoint advertised to the control plane, so peers
            // answer the handshake on the socket we bound. The in-process transport factory (tests) ignores it.
            IWireGuardTransportFactory wgFactory = _wireGuardTransportFactory
                ?? new WireGuardSocketTransportFactory(localPort: _config.WireGuardLocalPort);
            // Tailscale is a peer-to-peer mesh: every node is both initiator and responder. acceptInbound lets two .NET
            // nodes hand-shake each other (a deterministic tie-break by static public key picks one initiator per pair),
            // so the WireGuard tunnel comes up without a server — the data plane behind the ts2021 control plane.
            var wg = new WireGuardConnection(host, port, wgConfig, wgFactory,
                loggerFactory: _loggerFactory, acceptInbound: true);
            _wireGuard = wg;
            MarkRunning();
            await wg.ConnectAsync(cancellationToken).ConfigureAwait(false);

            Facade.SetInner(wg.PacketChannel);
            Logger.LogHandshakeCompleted(DriverName);
            MarkConnected();
        }

        /// <inheritdoc/>
        protected override async Task CleanupAttemptResourcesAsync()
        {
            WireGuardConnection? wg = _wireGuard;
            _wireGuard = null;
            if (wg is not null) { try { await wg.DisposeAsync().ConfigureAwait(false); } catch { } }

            ITailscaleControlClient? control = _control;
            _control = null;
            if (control is not null) { try { control.Dispose(); } catch { } }
        }

        /// <inheritdoc/>
        protected override void StopAttemptLoop() { /* no timer loop of our own; WireGuard owns its timers */ }

        /// <inheritdoc/>
        public override Task DisconnectAsync(CancellationToken cancellationToken = default) => DisconnectCoreAsync();

        /// <inheritdoc/>
        public async ValueTask DisposeAsync()
        {
            await DisconnectCoreAsync().ConfigureAwait(false);
            await CleanupAttemptResourcesAsync().ConfigureAwait(false);
            await DisposeCoreAsync().ConfigureAwait(false);
        }

        /// <inheritdoc/>
        public void Dispose() => DisposeAsync().AsTask().GetAwaiter().GetResult();
    }
}
