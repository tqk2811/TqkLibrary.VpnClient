using System;
using System.Net;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.Logging;
using TqkLibrary.VpnClient.Abstractions.Channels.Interfaces;
using TqkLibrary.VpnClient.Abstractions.Diagnostics.Extensions;
using TqkLibrary.VpnClient.Abstractions.Net;
using TqkLibrary.VpnClient.Abstractions.Transport.Interfaces;
using TqkLibrary.VpnClient.Drivers.Core;
using TqkLibrary.VpnClient.IpEncap;

namespace TqkLibrary.VpnClient.Drivers.Ayiya
{
    /// <summary>
    /// A complete AYIYA (Anything In Anything) tunnel-broker client in <b>static</b> mode: opens a connected UDP transport
    /// to the broker on the configured port, wraps it in an <see cref="AyiyaFramingTransport"/> that adds/strips + signs the
    /// AYIYA header, and binds the reused <see cref="RawIpPassthroughChannel"/> (IPv6 L3) behind the stable
    /// <see cref="ReconnectingVpnConnection.PacketChannel"/> facade so the IP stack above sees one durable IPv6 link.
    /// <para>Like the other plain-encap UDP drivers this is "WireGuard minus the handshake": the link-loss → supervisor →
    /// reconnect-loop machinery is reused from <see cref="ReconnectingVpnConnection"/> (roadmap F.6); the driver only opens
    /// the transport, computes the shared-secret hash and starts the channel. Because the carrier is an ordinary UDP socket
    /// it needs <b>no elevation and no raw IP socket</b> and traverses NAT/firewalls that pass UDP. Static mode skips the
    /// TIC control channel, so there is no automatic keepalive — a silent link loss is not detected on its own.</para>
    /// <para><b>AYIYA does NOT encrypt the payload</b> — it signs integrity (shared-secret hash) and guards replay (epoch
    /// time). Use only on a trusted path or under an outer secure layer.</para>
    /// </summary>
    public sealed class AyiyaConnection : ReconnectingVpnConnection, IDisposable, IAsyncDisposable
    {
        readonly string _host;
        readonly IAyiyaTransportFactory _transportFactory;
        readonly AyiyaOptions _options;
        readonly AddressFamilyPreference _addressFamilyPreference;
        readonly IHostResolver _hostResolver;
        readonly byte[] _secretHash;
        readonly Func<uint>? _epochClock;

        IPacketChannel? _channel;             // RawIpPassthroughChannel (owns the framing transport → UDP transport)
        AyiyaFramingTransport? _framing;      // the live signer/verifier (for optional heartbeats)

        /// <summary>
        /// Creates a connection to the given tunnel broker. <paramref name="transportFactory"/> carries the data plane (a
        /// connected UDP socket — no elevation). <paramref name="options"/> supplies the identity, shared secret, port, MTU
        /// and clock-skew tolerance. <paramref name="hostResolver"/> resolves <paramref name="host"/> (default DNS).
        /// <paramref name="epochClock"/> supplies the epoch seconds (default: system UTC clock; tests inject a deterministic
        /// one). <paramref name="loggerFactory"/> receives diagnostic traces (null logs to a no-op logger).
        /// </summary>
        public AyiyaConnection(string host, IAyiyaTransportFactory transportFactory, AyiyaOptions options,
            AyiyaReconnectOptions? reconnectOptions = null,
            AddressFamilyPreference addressFamilyPreference = AddressFamilyPreference.Auto,
            IHostResolver? hostResolver = null, Func<uint>? epochClock = null, ILoggerFactory? loggerFactory = null)
            : base("ayiya", reconnectOptions ?? new AyiyaReconnectOptions(), clock: null, loggerFactory: loggerFactory)
        {
            _host = host ?? throw new ArgumentNullException(nameof(host));
            _transportFactory = transportFactory ?? throw new ArgumentNullException(nameof(transportFactory));
            _options = options ?? throw new ArgumentNullException(nameof(options));
            _secretHash = _options.ValidateAndComputeSecretHash();
            _addressFamilyPreference = addressFamilyPreference;
            _hostResolver = hostResolver ?? DnsHostResolver.Default;
            _epochClock = epochClock;
        }

        /// <summary>The UDP destination port the tunnel is carried on (from <see cref="AyiyaOptions.Port"/>).</summary>
        public int Port => _options.Port;

        /// <summary>The MTU advertised to the IP stack (from <see cref="AyiyaOptions.Mtu"/>).</summary>
        public int Mtu => _options.Mtu;

        /// <summary>Opens the UDP transport and brings the AYIYA channel up; returns once the link is live.</summary>
        public Task ConnectAsync(CancellationToken cancellationToken = default)
            => ConnectCoreAsync(cancellationToken);

        /// <summary>
        /// Sends an AYIYA heartbeat (echo-request, next-header 59, empty payload) over the live tunnel — an optional
        /// liveness keepalive. No-op if the tunnel is not currently up.
        /// </summary>
        public ValueTask SendHeartbeatAsync(CancellationToken cancellationToken = default)
        {
            AyiyaFramingTransport? framing = _framing;
            return framing is null ? default : framing.SendHeartbeatAsync(cancellationToken);
        }

        /// <summary>
        /// Brings up one full tunnel attempt from scratch: resolve the broker, open the connected UDP transport, wrap it in
        /// the AYIYA signer/verifier and publish the reused IPv6 passthrough channel behind the stable facade. There is no
        /// handshake — the channel is live as soon as the socket is connected.
        /// </summary>
        protected override async Task EstablishAsync(CancellationToken cancellationToken)
        {
            await CleanupAttemptResourcesAsync().ConfigureAwait(false);

            IPAddress serverIp = await _hostResolver.ResolveAsync(_host, _addressFamilyPreference, cancellationToken).ConfigureAwait(false);
            var endpoint = new IPEndPoint(serverIp, _options.Port);

            Logger.LogHandshake(DriverName, $"opening AYIYA UDP transport ({endpoint}, idType {_options.IdType}, {_options.HashMethod})");
            IDatagramTransport transport = _transportFactory.Create(endpoint);
            try
            {
                await transport.ConnectAsync(cancellationToken).ConfigureAwait(false);
            }
            catch
            {
                await transport.DisposeAsync().ConfigureAwait(false);
                throw;
            }

            var framing = new AyiyaFramingTransport(transport, _options.IdType, _options.Identity, _options.HashMethod,
                _options.AuthMethod, _secretHash, _options.ClockSkewToleranceSeconds, _epochClock);

            RawIpPassthroughChannel channel;
            try
            {
                channel = new RawIpPassthroughChannel(framing, _options.Mtu, Logger);
                channel.Start();
            }
            catch
            {
                await framing.DisposeAsync().ConfigureAwait(false); // disposes the underlying UDP transport too
                throw;
            }

            _framing = framing;
            _channel = channel;
            Facade.SetInner(channel);
            Logger.LogHandshakeCompleted(DriverName);
            MarkConnected();
        }

        /// <summary>No per-attempt loop (static AYIYA has no keepalive timer). No-op.</summary>
        protected override void StopAttemptLoop()
        {
        }

        /// <summary>Tears down the previous attempt's channel (which disposes the framing transport and the underlying UDP transport).</summary>
        protected override async Task CleanupAttemptResourcesAsync()
        {
            StopAttemptLoop();

            IPacketChannel? channel = _channel;
            _channel = null;
            _framing = null;
            if (channel != null)
            {
                try { await channel.DisposeAsync().ConfigureAwait(false); } catch { }
            }
        }

        /// <summary>
        /// Tears the tunnel down gracefully and permanently (no reconnect): disposes the channel, its framing transport and
        /// the UDP transport. Best-effort; safe to call more than once.
        /// </summary>
        public override async Task DisconnectAsync(CancellationToken cancellationToken = default)
        {
            await DisconnectCoreAsync().ConfigureAwait(false);
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
