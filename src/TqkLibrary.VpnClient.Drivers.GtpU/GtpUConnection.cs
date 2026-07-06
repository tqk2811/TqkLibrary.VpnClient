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

namespace TqkLibrary.VpnClient.Drivers.GtpU
{
    /// <summary>
    /// A complete GTP-U (GPRS Tunnelling Protocol, User plane, 3GPP TS 29.281) tunnel client in <b>static mode</b>: opens a
    /// connected UDP transport to the remote gateway on the configured port (default 2152), wraps it in a
    /// <see cref="GtpUFramingTransport"/> that adds/strips the GTP-U G-PDU header (with the configured TEID), and binds the
    /// reused <see cref="RawIpPassthroughChannel"/> (the inner IP packet is carried verbatim) behind the stable
    /// <see cref="ReconnectingVpnConnection.PacketChannel"/> facade so the IP stack above sees one durable L3 link.
    /// <para>Static mode has <b>no GTP-C control plane</b>: the TEID and endpoint are configured up front. Like the other
    /// plain-encap UDP drivers this is "WireGuard minus the handshake": the link-loss → supervisor → reconnect-loop
    /// machinery is reused from <see cref="ReconnectingVpnConnection"/> (roadmap F.6); the driver only opens the transport
    /// and starts the channel. Because the carrier is an ordinary UDP socket it needs <b>no elevation and no raw IP
    /// socket</b> and traverses NAT/firewalls that pass UDP. There is no keepalive, so a silent link loss is not detected on
    /// its own.</para>
    /// <para><b>GTP-U is UNENCRYPTED</b> — it only tags the inner IP packet with a TEID. Use only on a trusted path or under
    /// IPsec ESP.</para>
    /// </summary>
    public sealed class GtpUConnection : ReconnectingVpnConnection, IDisposable, IAsyncDisposable
    {
        const string DriverNameConst = "gtpu";

        readonly string _host;
        readonly IGtpUTransportFactory _transportFactory;
        readonly GtpUOptions _options;
        readonly AddressFamilyPreference _addressFamilyPreference;
        readonly IHostResolver _hostResolver;

        IPacketChannel? _channel; // RawIpPassthroughChannel (owns the framing transport → UDP transport)

        /// <summary>
        /// Creates a connection to the given gateway. <paramref name="transportFactory"/> carries the data plane (a
        /// connected UDP socket on the configured port — no elevation). <paramref name="options"/> supplies the port, TEID,
        /// sequence flag and MTU. <paramref name="hostResolver"/> resolves <paramref name="host"/> (default DNS).
        /// <paramref name="loggerFactory"/> receives diagnostic traces (null logs to a no-op logger).
        /// </summary>
        public GtpUConnection(string host, IGtpUTransportFactory transportFactory, GtpUOptions? options = null,
            GtpUReconnectOptions? reconnectOptions = null,
            AddressFamilyPreference addressFamilyPreference = AddressFamilyPreference.Auto,
            IHostResolver? hostResolver = null, ILoggerFactory? loggerFactory = null)
            : base(DriverNameConst, reconnectOptions ?? new GtpUReconnectOptions(), clock: null, loggerFactory: loggerFactory)
        {
            _host = host ?? throw new ArgumentNullException(nameof(host));
            _transportFactory = transportFactory ?? throw new ArgumentNullException(nameof(transportFactory));
            _options = options ?? new GtpUOptions();
            _addressFamilyPreference = addressFamilyPreference;
            _hostResolver = hostResolver ?? DnsHostResolver.Default;
        }

        /// <summary>The UDP destination port the tunnel is carried on (from <see cref="GtpUOptions.Port"/>).</summary>
        public int Port => _options.Port;

        /// <summary>The MTU advertised to the IP stack (from <see cref="GtpUOptions.Mtu"/>).</summary>
        public int Mtu => _options.Mtu;

        /// <summary>Opens the UDP transport and brings the GTP-U channel up; returns once the link is live.</summary>
        public Task ConnectAsync(CancellationToken cancellationToken = default)
            => ConnectCoreAsync(cancellationToken);

        /// <summary>
        /// Brings up one full tunnel attempt from scratch: resolve the gateway, open the connected UDP transport, wrap it in
        /// the GTP-U framing decorator and publish the reused IP passthrough channel behind the stable facade. There is no
        /// handshake — the channel is live as soon as the socket is connected.
        /// </summary>
        protected override async Task EstablishAsync(CancellationToken cancellationToken)
        {
            await CleanupAttemptResourcesAsync().ConfigureAwait(false);

            IPAddress serverIp = await _hostResolver.ResolveAsync(_host, _addressFamilyPreference, cancellationToken).ConfigureAwait(false);
            var endpoint = new IPEndPoint(serverIp, _options.Port);

            Logger.LogHandshake(DriverName, $"opening GTP-U UDP transport ({endpoint}, TEID 0x{_options.Teid:X8}, seq {_options.EnableSequence})");
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

            var framing = new GtpUFramingTransport(transport, _options.Teid, _options.ExpectedInboundTeid, _options.EnableSequence);

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

            _channel = channel;
            Facade.SetInner(channel);
            Logger.LogHandshakeCompleted(DriverName);
            MarkConnected();
        }

        /// <summary>No per-attempt loop (static GTP-U has no keepalive timer). No-op.</summary>
        protected override void StopAttemptLoop()
        {
        }

        /// <summary>Tears down the previous attempt's channel (which disposes the framing transport and the underlying UDP transport).</summary>
        protected override async Task CleanupAttemptResourcesAsync()
        {
            StopAttemptLoop();

            IPacketChannel? channel = _channel;
            _channel = null;
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
