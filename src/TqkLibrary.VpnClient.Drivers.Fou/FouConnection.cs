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
using TqkLibrary.VpnClient.Drivers.Fou.Enums;
using TqkLibrary.VpnClient.IpEncap;
using TqkLibrary.VpnClient.IpEncap.Gre;

namespace TqkLibrary.VpnClient.Drivers.Fou
{
    /// <summary>
    /// A complete FOU / GUE (Generic X-over-UDP) tunnel client: opens a connected UDP transport to the remote gateway on
    /// the configured port and binds the inner data-plane channel — the reused <see cref="GreTunnelChannel"/> (GRE inner)
    /// or <see cref="RawIpPassthroughChannel"/> (IPIP inner) — behind the stable
    /// <see cref="ReconnectingVpnConnection.PacketChannel"/> facade so the IP stack above sees one durable L3 link. In GUE
    /// mode the transport is wrapped in a <see cref="GueFramingTransport"/> that adds/strips the 4-byte GUE variant-0
    /// header; in FOU mode the inner payload rides the UDP datagram bare (the inner protocol is fixed by the port).
    /// <para>FOU/GUE generalise GRE-in-UDP (RFC 8086): the inner payload rides an ordinary UDP datagram, so the driver
    /// needs <b>no elevation and no raw IP socket</b> and traverses NAT/firewalls that pass UDP. Like the other plain
    /// encap drivers this is "WireGuard minus the handshake": the link-loss → supervisor → reconnect-loop machinery is
    /// reused from <see cref="ReconnectingVpnConnection"/> (roadmap F.6); the driver only opens the transport and starts
    /// the channel. Plain encap is <i>connectionless</i> — there is no control plane, so a silent link loss cannot be
    /// detected and auto-reconnect does not fire on its own.</para>
    /// <para><b>FOU/GUE are UNENCRYPTED</b> — use only on a trusted path or under IPsec ESP.</para>
    /// </summary>
    public sealed class FouConnection : ReconnectingVpnConnection, IDisposable, IAsyncDisposable
    {
        readonly string _host;
        readonly IFouTransportFactory _transportFactory;
        readonly FouOptions _options;
        readonly AddressFamilyPreference _addressFamilyPreference;
        readonly IHostResolver _hostResolver;

        IPacketChannel? _channel; // GreTunnelChannel or RawIpPassthroughChannel (owns the UDP transport / GUE decorator)

        /// <summary>
        /// Creates a connection to the given gateway. <paramref name="transportFactory"/> carries the data plane (a
        /// connected UDP socket on the configured port — no elevation). <paramref name="options"/> selects the mode
        /// (FOU/GUE), inner protocol, port, MTU and (optional) RFC 2890 GRE options. <paramref name="hostResolver"/>
        /// resolves <paramref name="host"/> (default DNS). <paramref name="loggerFactory"/> receives diagnostic traces
        /// (null logs to a no-op logger).
        /// </summary>
        public FouConnection(string host, IFouTransportFactory transportFactory, FouOptions? options = null,
            FouReconnectOptions? reconnectOptions = null,
            AddressFamilyPreference addressFamilyPreference = AddressFamilyPreference.Auto,
            IHostResolver? hostResolver = null, ILoggerFactory? loggerFactory = null)
            : base(DriverNameFor(options), reconnectOptions ?? new FouReconnectOptions(), clock: null, loggerFactory: loggerFactory)
        {
            _host = host ?? throw new ArgumentNullException(nameof(host));
            _transportFactory = transportFactory ?? throw new ArgumentNullException(nameof(transportFactory));
            _options = options ?? new FouOptions();
            _addressFamilyPreference = addressFamilyPreference;
            _hostResolver = hostResolver ?? DnsHostResolver.Default;
        }

        /// <summary>The driver key for the given options' mode: <c>"gue"</c> for GUE, <c>"fou"</c> for FOU. Used as the connection's driver name.</summary>
        internal static string DriverNameFor(FouOptions? options)
            => (options?.Mode ?? FouEncapMode.Fou) == FouEncapMode.Gue ? "gue" : "fou";

        /// <summary>The UDP destination port the tunnel is carried on (from <see cref="FouOptions.Port"/>).</summary>
        public int Port => _options.Port;

        /// <summary>The MTU advertised to the IP stack (from <see cref="FouOptions.Mtu"/>).</summary>
        public int Mtu => _options.Mtu;

        /// <summary>Opens the UDP transport and brings the FOU/GUE channel up; returns once the link is live.</summary>
        public Task ConnectAsync(CancellationToken cancellationToken = default)
            => ConnectCoreAsync(cancellationToken);

        /// <summary>
        /// Brings up one full tunnel attempt from scratch: a clean-slate factory reused by the first connect and by every
        /// reconnect. Resolves the gateway, opens the connected UDP transport on the configured port, adds the GUE framing
        /// (GUE mode only), builds the inner channel and publishes it behind the stable facade. There is no handshake —
        /// the channel is live as soon as the socket is connected.
        /// </summary>
        protected override async Task EstablishAsync(CancellationToken cancellationToken)
        {
            await CleanupAttemptResourcesAsync().ConfigureAwait(false);

            IPAddress serverIp = await _hostResolver.ResolveAsync(_host, _addressFamilyPreference, cancellationToken).ConfigureAwait(false);
            var endpoint = new IPEndPoint(serverIp, _options.Port);

            Logger.LogHandshake(DriverName, $"opening UDP transport ({_options.Mode}, inner proto {_options.InnerProtocol}, {endpoint})");
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

            // GUE prepends a 4-byte header carrying the inner protocol number; FOU rides the payload bare.
            IDatagramTransport dataTransport = _options.Mode == FouEncapMode.Gue
                ? new GueFramingTransport(transport, _options.InnerProtocol)
                : transport;

            IPacketChannel channel;
            try
            {
                channel = BuildInnerChannel(dataTransport);
            }
            catch
            {
                await dataTransport.DisposeAsync().ConfigureAwait(false); // disposes the underlying UDP transport too
                throw;
            }

            _channel = channel;
            Facade.SetInner(channel);
            Logger.LogHandshakeCompleted(DriverName);
            MarkConnected();
        }

        // Selects and starts the inner data-plane channel by the configured inner protocol number, reusing the IpEncap
        // channels wholesale: GRE (47) → GreTunnelChannel; IPIP (4) / IPv6 (41) → header-less RawIpPassthroughChannel.
        IPacketChannel BuildInnerChannel(IDatagramTransport dataTransport)
        {
            switch (_options.InnerProtocol)
            {
                case IpProtocol.Gre:
                {
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
                    var gre = new GreTunnelChannel(dataTransport, greOptions, Logger);
                    gre.Start();
                    return gre;
                }
                case IpProtocol.IpInIp:
                case IpProtocol.Ipv6:
                {
                    var passthrough = new RawIpPassthroughChannel(dataTransport, _options.Mtu, Logger);
                    passthrough.Start();
                    return passthrough;
                }
                default:
                    throw new NotSupportedException(
                        $"FOU/GUE inner protocol {_options.InnerProtocol} is not supported (expected 4 = IPIP, 41 = IPv6, or 47 = GRE).");
            }
        }

        /// <summary>No per-attempt loop (connectionless encap has no keepalive timer). No-op.</summary>
        protected override void StopAttemptLoop()
        {
        }

        /// <summary>Tears down the previous attempt's channel (which disposes the underlying UDP transport / GUE decorator).</summary>
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
        /// Tears the tunnel down gracefully and permanently (no reconnect): disposes the inner channel and its UDP
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
