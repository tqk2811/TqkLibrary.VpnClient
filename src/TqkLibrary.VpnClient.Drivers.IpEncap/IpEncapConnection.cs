using System;
using System.Net;
using System.Net.Sockets;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.Logging;
using TqkLibrary.VpnClient.Abstractions.Channels.Interfaces;
using TqkLibrary.VpnClient.Abstractions.Diagnostics.Extensions;
using TqkLibrary.VpnClient.Abstractions.Drivers.Models;
using TqkLibrary.VpnClient.Abstractions.Net;
using TqkLibrary.VpnClient.Abstractions.Transport.Interfaces;
using TqkLibrary.VpnClient.Drivers.Core;
using TqkLibrary.VpnClient.Drivers.IpEncap.Enums;
using TqkLibrary.VpnClient.IpEncap;
using TqkLibrary.VpnClient.IpEncap.Gre;

namespace TqkLibrary.VpnClient.Drivers.IpEncap
{
    /// <summary>
    /// A complete plain IP-in-IP / GRE tunnel client: opens a raw-IP transport on the kind's IANA protocol number
    /// (<see cref="IpEncapKind.Gre"/>→47, <see cref="IpEncapKind.IpIp"/>→4, <see cref="IpEncapKind.Sit"/>→41) to the
    /// remote gateway and binds the matching data-plane channel — <see cref="GreTunnelChannel"/> for GRE,
    /// <see cref="RawIpPassthroughChannel"/> for IPIP/SIT — behind the stable
    /// <see cref="ReconnectingVpnConnection.PacketChannel"/> facade so the IP stack above sees one durable L3 link.
    /// <para>This is "WireGuard minus the handshake": the link-loss → supervisor → reconnect-loop machinery (the stable
    /// <see cref="SwappablePacketChannel"/> facade, lifetime cancellation, state + structured logging) is reused from
    /// <see cref="ReconnectingVpnConnection"/> (roadmap F.6); the driver only opens the transport and starts the
    /// channel. Plain encap is <i>connectionless</i> — there is no control plane (no handshake, keepalive or DPD), so a
    /// silent link loss cannot be detected and auto-reconnect does not fire on its own.</para>
    /// <para><b>GRE/IPIP/SIT are UNENCRYPTED</b> — use only on a trusted path or under IPsec ESP. The raw-IP transport
    /// (<see cref="IRawIpTransportFactory"/>, roadmap F.9) requires elevation.</para>
    /// </summary>
    public sealed class IpEncapConnection : ReconnectingVpnConnection, IDisposable, IAsyncDisposable
    {
        const string DriverNameConst = "ipencap";

        // IANA IP protocol numbers carried natively over a raw-IP socket (mirror RawIpProtocols; const here so the
        // driver depends only on the IRawIpTransportFactory abstraction, not on the Transport.RawIp project — same
        // pattern as PPTP's GreIpProtocol const).
        const int GreIpProtocol = 47;  // RFC 2784/2890
        const int IpIpProtocol = 4;    // RFC 2003
        const int SitProtocol = 41;    // RFC 4213

        readonly string _host;
        readonly IRawIpTransportFactory _rawIpFactory;
        readonly IpEncapOptions _options;
        readonly AddressFamilyPreference _addressFamilyPreference;
        readonly IHostResolver _hostResolver;

        IPacketChannel? _channel; // GreTunnelChannel or RawIpPassthroughChannel

        /// <summary>
        /// Creates a connection to the given gateway. <paramref name="rawIpFactory"/> carries the data plane (a raw IP
        /// socket on the kind's protocol number — requires elevation). <paramref name="options"/> selects the encap kind,
        /// MTU and (for GRE) the RFC 2890 options. <paramref name="hostResolver"/> resolves <paramref name="host"/>
        /// (default DNS). <paramref name="loggerFactory"/> receives diagnostic traces (null logs to a no-op logger).
        /// </summary>
        public IpEncapConnection(string host, IRawIpTransportFactory rawIpFactory, IpEncapOptions? options = null,
            IpEncapReconnectOptions? reconnectOptions = null,
            AddressFamilyPreference addressFamilyPreference = AddressFamilyPreference.Auto,
            IHostResolver? hostResolver = null, ILoggerFactory? loggerFactory = null)
            : base(DriverNameConst, reconnectOptions ?? new IpEncapReconnectOptions(), clock: null, loggerFactory: loggerFactory)
        {
            _host = host ?? throw new ArgumentNullException(nameof(host));
            _rawIpFactory = rawIpFactory ?? throw new ArgumentNullException(nameof(rawIpFactory));
            _options = options ?? new IpEncapOptions();
            _addressFamilyPreference = addressFamilyPreference;
            _hostResolver = hostResolver ?? DnsHostResolver.Default;
        }

        /// <summary>The encapsulation kind this connection carries.</summary>
        public IpEncapKind Kind => _options.Kind;

        /// <summary>The MTU advertised to the IP stack (from <see cref="IpEncapOptions.Mtu"/>).</summary>
        public int Mtu => _options.Mtu;

        /// <summary>Opens the raw-IP transport and brings the encapsulation channel up; returns once the link is live.</summary>
        public Task ConnectAsync(CancellationToken cancellationToken = default)
            => ConnectCoreAsync(cancellationToken);

        // The IANA protocol number for the configured kind.
        int ProtocolNumber => _options.Kind switch
        {
            IpEncapKind.Gre => GreIpProtocol,
            IpEncapKind.IpIp => IpIpProtocol,
            IpEncapKind.Sit => SitProtocol,
            _ => throw new ArgumentOutOfRangeException(nameof(IpEncapOptions.Kind), _options.Kind, "Unknown IP-encapsulation kind."),
        };

        /// <summary>
        /// Brings up one full tunnel attempt from scratch: a clean-slate factory reused by the first connect and by every
        /// reconnect. Resolves the gateway, opens the raw-IP transport on the kind's protocol number, builds the matching
        /// channel and publishes it behind the stable facade. There is no handshake — the channel is live as soon as the
        /// socket is open.
        /// </summary>
        protected override async Task EstablishAsync(CancellationToken cancellationToken)
        {
            await CleanupAttemptResourcesAsync().ConfigureAwait(false);

            IPAddress serverIp = await _hostResolver.ResolveAsync(_host, _addressFamilyPreference, cancellationToken).ConfigureAwait(false);
            IPAddress localIp = GetLocalAddress(serverIp);
            int protocol = ProtocolNumber;

            Logger.LogHandshake(DriverName, $"opening raw-IP transport (proto-{protocol}, {_options.Kind})");
            IDatagramTransport transport = _rawIpFactory.Create(serverIp, protocol, localBind: localIp);

            IPacketChannel channel;
            switch (_options.Kind)
            {
                case IpEncapKind.Gre:
                    var greOptions = _options.Gre ?? new GreTunnelOptions { Mtu = _options.Mtu };
                    // Pin the channel MTU to the connection's MTU regardless of any value on the caller's GRE options.
                    if (greOptions.Mtu != _options.Mtu)
                        greOptions = new GreTunnelOptions
                        {
                            Mtu = _options.Mtu,
                            Key = greOptions.Key,
                            EmitSequenceNumber = greOptions.EmitSequenceNumber,
                            EmitChecksum = greOptions.EmitChecksum,
                        };
                    var gre = new GreTunnelChannel(transport, greOptions, Logger);
                    gre.Start();
                    channel = gre;
                    break;

                case IpEncapKind.IpIp:
                case IpEncapKind.Sit:
                    var passthrough = new RawIpPassthroughChannel(transport, _options.Mtu, Logger);
                    passthrough.Start();
                    channel = passthrough;
                    break;

                default:
                    await transport.DisposeAsync().ConfigureAwait(false);
                    throw new ArgumentOutOfRangeException(nameof(IpEncapOptions.Kind), _options.Kind, "Unknown IP-encapsulation kind.");
            }

            _channel = channel;
            Facade.SetInner(channel);
            Logger.LogHandshakeCompleted(DriverName);
            MarkConnected();
        }

        // The local source address the OS routes to this gateway through (a throwaway connected UDP socket; no datagram
        // is sent). Falls back to Any so the raw-IP transport binds the default interface if it cannot be determined.
        static IPAddress GetLocalAddress(IPAddress serverIp)
        {
            try
            {
                using var probe = new Socket(serverIp.AddressFamily, SocketType.Dgram, ProtocolType.Udp);
                probe.Connect(serverIp, 9); // discard port; no datagram is actually sent
                return ((IPEndPoint)probe.LocalEndPoint!).Address;
            }
            catch
            {
                return serverIp.AddressFamily == AddressFamily.InterNetworkV6 ? IPAddress.IPv6Any : IPAddress.Any;
            }
        }

        /// <summary>No per-attempt loop (connectionless encap has no keepalive timer). No-op.</summary>
        protected override void StopAttemptLoop()
        {
        }

        /// <summary>Tears down the previous attempt's channel (which disposes the underlying raw-IP transport).</summary>
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
        /// Tears the tunnel down gracefully and permanently (no reconnect): disposes the encapsulation channel and its
        /// raw-IP transport. Best-effort; safe to call more than once.
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
