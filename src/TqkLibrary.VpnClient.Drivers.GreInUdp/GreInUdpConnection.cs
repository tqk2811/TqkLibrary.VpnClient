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
using TqkLibrary.VpnClient.IpEncap.Gre;

namespace TqkLibrary.VpnClient.Drivers.GreInUdp
{
    /// <summary>
    /// A complete GRE-in-UDP tunnel client (RFC 8086): opens a connected UDP transport to the remote gateway on the
    /// configured port (default 4754) and binds the standard GRE data-plane channel — the reused
    /// <see cref="GreTunnelChannel"/> — behind the stable
    /// <see cref="ReconnectingVpnConnection.PacketChannel"/> facade so the IP stack above sees one durable L3 link.
    /// <para>GRE-in-UDP carries the very same GRE header (RFC 2784/2890) as raw-IP GRE, but inside a UDP payload rather
    /// than on proto-47 — so it needs <b>no elevation and no raw IP socket</b> and traverses NAT/firewalls that pass
    /// UDP. This is "WireGuard minus the handshake": the link-loss → supervisor → reconnect-loop machinery is reused
    /// from <see cref="ReconnectingVpnConnection"/> (roadmap F.6); the driver only opens the transport and starts
    /// the channel. Plain encap is <i>connectionless</i> — there is no control plane (no handshake, keepalive or DPD),
    /// so a silent link loss cannot be detected and auto-reconnect does not fire on its own.</para>
    /// <para><b>GRE-in-UDP is UNENCRYPTED</b> — use only on a trusted path or under IPsec ESP.</para>
    /// </summary>
    public sealed class GreInUdpConnection : ReconnectingVpnConnection, IDisposable, IAsyncDisposable
    {
        const string DriverNameConst = "gre-udp";

        readonly string _host;
        readonly IGreUdpTransportFactory _transportFactory;
        readonly GreInUdpOptions _options;
        readonly AddressFamilyPreference _addressFamilyPreference;
        readonly IHostResolver _hostResolver;

        IPacketChannel? _channel; // GreTunnelChannel

        /// <summary>
        /// Creates a connection to the given gateway. <paramref name="transportFactory"/> carries the data plane (a
        /// connected UDP socket on the configured port — no elevation). <paramref name="options"/> selects the port,
        /// MTU and (optional) RFC 2890 GRE options. <paramref name="hostResolver"/> resolves <paramref name="host"/>
        /// (default DNS). <paramref name="loggerFactory"/> receives diagnostic traces (null logs to a no-op logger).
        /// </summary>
        public GreInUdpConnection(string host, IGreUdpTransportFactory transportFactory, GreInUdpOptions? options = null,
            GreInUdpReconnectOptions? reconnectOptions = null,
            AddressFamilyPreference addressFamilyPreference = AddressFamilyPreference.Auto,
            IHostResolver? hostResolver = null, ILoggerFactory? loggerFactory = null)
            : base(DriverNameConst, reconnectOptions ?? new GreInUdpReconnectOptions(), clock: null, loggerFactory: loggerFactory)
        {
            _host = host ?? throw new ArgumentNullException(nameof(host));
            _transportFactory = transportFactory ?? throw new ArgumentNullException(nameof(transportFactory));
            _options = options ?? new GreInUdpOptions();
            _addressFamilyPreference = addressFamilyPreference;
            _hostResolver = hostResolver ?? DnsHostResolver.Default;
        }

        /// <summary>The UDP destination port the GRE header is carried on (from <see cref="GreInUdpOptions.Port"/>).</summary>
        public int Port => _options.Port;

        /// <summary>The MTU advertised to the IP stack (from <see cref="GreInUdpOptions.Mtu"/>).</summary>
        public int Mtu => _options.Mtu;

        /// <summary>Opens the UDP transport and brings the GRE-in-UDP channel up; returns once the link is live.</summary>
        public Task ConnectAsync(CancellationToken cancellationToken = default)
            => ConnectCoreAsync(cancellationToken);

        /// <summary>
        /// Brings up one full tunnel attempt from scratch: a clean-slate factory reused by the first connect and by every
        /// reconnect. Resolves the gateway, opens the connected UDP transport on the configured port, builds the GRE
        /// channel and publishes it behind the stable facade. There is no handshake — the channel is live as soon as the
        /// socket is connected.
        /// </summary>
        protected override async Task EstablishAsync(CancellationToken cancellationToken)
        {
            await CleanupAttemptResourcesAsync().ConfigureAwait(false);

            IPAddress serverIp = await _hostResolver.ResolveAsync(_host, _addressFamilyPreference, cancellationToken).ConfigureAwait(false);
            var endpoint = new IPEndPoint(serverIp, _options.Port);

            Logger.LogHandshake(DriverName, $"opening UDP transport (GRE-in-UDP, {endpoint})");
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

            GreTunnelOptions greOptions = _options.Gre ?? new GreTunnelOptions { Mtu = _options.Mtu };
            // Pin the channel MTU to the connection's MTU regardless of any value on the caller's GRE options.
            if (greOptions.Mtu != _options.Mtu)
                greOptions = new GreTunnelOptions
                {
                    Mtu = _options.Mtu,
                    Key = greOptions.Key,
                    EmitSequenceNumber = greOptions.EmitSequenceNumber,
                    EmitChecksum = greOptions.EmitChecksum,
                };

            var channel = new GreTunnelChannel(transport, greOptions, Logger);
            channel.Start();

            _channel = channel;
            Facade.SetInner(channel);
            Logger.LogHandshakeCompleted(DriverName);
            MarkConnected();
        }

        /// <summary>No per-attempt loop (connectionless encap has no keepalive timer). No-op.</summary>
        protected override void StopAttemptLoop()
        {
        }

        /// <summary>Tears down the previous attempt's channel (which disposes the underlying UDP transport).</summary>
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
        /// Tears the tunnel down gracefully and permanently (no reconnect): disposes the GRE channel and its UDP
        /// transport. Best-effort; safe to call more than once.
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
