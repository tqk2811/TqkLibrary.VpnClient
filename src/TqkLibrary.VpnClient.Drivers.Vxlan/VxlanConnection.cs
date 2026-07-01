using System;
using System.Net;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.Logging;
using TqkLibrary.VpnClient.Abstractions.Diagnostics.Enums;
using TqkLibrary.VpnClient.Abstractions.Diagnostics.Extensions;
using TqkLibrary.VpnClient.Abstractions.Drivers.Models;
using TqkLibrary.VpnClient.Abstractions.Net;
using TqkLibrary.VpnClient.Abstractions.Transport.Interfaces;
using TqkLibrary.VpnClient.Drivers.Core;
using TqkLibrary.VpnClient.Drivers.Vxlan.Config;
using TqkLibrary.VpnClient.Drivers.Vxlan.DataChannel;
using TqkLibrary.VpnClient.Drivers.Vxlan.Enums;
using TqkLibrary.VpnClient.Drivers.Vxlan.Transport;
using TqkLibrary.VpnClient.Ethernet;

namespace TqkLibrary.VpnClient.Drivers.Vxlan
{
    /// <summary>
    /// A VXLAN (RFC 7348) L2-over-UDP endpoint. It opens a connected UDP transport to a static unicast remote VTEP and
    /// then carries full Ethernet frames behind an 8-byte VXLAN header (UDP/4789) as a <see cref="VxlanEthernetChannel"/>.
    /// That channel plugs into the userspace Ethernet fabric (<see cref="ArpResolver"/> on the static overlay IP + a
    /// <see cref="VirtualHost"/> bridge), which exposes the stable L3
    /// <see cref="ReconnectingVpnConnection{TState}.PacketChannel"/> the IP stack binds — mirroring the n2n driver.
    /// Unlike n2n there is <b>no control plane</b>: no registration, no keepalive, no transform, no header encryption.
    /// The 8-byte header is the whole protocol; the shared supervisor (roadmap F.6) re-opens the transport on a drop.
    /// </summary>
    public sealed class VxlanConnection : ReconnectingVpnConnection<VxlanConnectionState>, IDisposable, IAsyncDisposable
    {
        readonly string _host;
        readonly VxlanConfig _config;
        readonly IVxlanTransportFactory _transportFactory;
        readonly AddressFamilyPreference _addressFamilyPreference;
        readonly IHostResolver _hostResolver;
        readonly TunnelConfig _tunnelConfig;
        readonly MacAddress _mac;
        readonly bool _strictVni;

        IDatagramTransport? _transport;
        CancellationTokenSource? _loopCts;
        Task? _receiveTask;

        VxlanEthernetChannel? _channel;
        ArpResolver? _arp;
        VirtualHost? _host2;

        /// <summary>
        /// Creates a connection. <paramref name="host"/> is the remote VTEP host (from the connect-time endpoint);
        /// <paramref name="config"/> is the static overlay profile; <paramref name="transportFactory"/> opens the UDP
        /// socket to the remote VTEP (an in-process factory drives it offline). <paramref name="strictVni"/> drops an
        /// inbound datagram whose VNI does not match the configured one; <paramref name="loggerFactory"/> receives
        /// diagnostic traces (null = no-op).
        /// </summary>
        public VxlanConnection(string host, IVxlanTransportFactory transportFactory, VxlanConfig config,
            VxlanReconnectOptions? reconnectOptions = null,
            AddressFamilyPreference addressFamilyPreference = AddressFamilyPreference.Auto,
            IHostResolver? hostResolver = null,
            bool strictVni = false,
            ILoggerFactory? loggerFactory = null)
            : base(VxlanDriverConstants.DriverName, reconnectOptions ?? new VxlanReconnectOptions(), clock: null, loggerFactory)
        {
            _host = host ?? throw new ArgumentNullException(nameof(host));
            _config = config ?? throw new ArgumentNullException(nameof(config));
            _transportFactory = transportFactory ?? throw new ArgumentNullException(nameof(transportFactory));
            _addressFamilyPreference = addressFamilyPreference;
            _hostResolver = hostResolver ?? DnsHostResolver.Default;
            _strictVni = strictVni;
            _tunnelConfig = config.ToTunnelConfig();
            _mac = config.ResolveLocalMac(NextRandomBytes);
        }

        /// <summary>The static tunnel configuration (overlay address, prefix, DNS, routes, MTU).</summary>
        public TunnelConfig Config => _tunnelConfig;

        /// <summary>The local overlay (tunnel) IPv4 address (the static overlay address).</summary>
        public IPAddress AssignedAddress => _config.OverlayAddress;

        /// <summary>This endpoint's virtual MAC on the VXLAN L2 segment.</summary>
        public MacAddress LinkAddress => _mac;

        /// <inheritdoc/>
        protected override VxlanConnectionState DisconnectedState => VxlanConnectionState.Disconnected;
        /// <inheritdoc/>
        protected override VxlanConnectionState ConnectingState => VxlanConnectionState.Connecting;
        /// <inheritdoc/>
        protected override VxlanConnectionState ConnectedState => VxlanConnectionState.Connected;
        /// <inheritdoc/>
        protected override VxlanConnectionState ReconnectingState => VxlanConnectionState.Reconnecting;

        /// <summary>Opens the UDP transport and returns once the L2 tunnel is carrying traffic (VXLAN has no handshake).</summary>
        public Task ConnectAsync(CancellationToken cancellationToken = default) => ConnectCoreAsync(cancellationToken);

        // ---- one full tunnel attempt (reused by the first connect and every reconnect) ----

        /// <inheritdoc/>
        protected override async Task EstablishAsync(CancellationToken cancellationToken)
        {
            await CleanupAttemptResourcesAsync().ConfigureAwait(false);

            IPEndPoint endpoint = await ResolveRemoteEndpointAsync(cancellationToken).ConfigureAwait(false);
            _loopCts = CancellationTokenSource.CreateLinkedTokenSource(LifetimeToken, cancellationToken);
            CancellationToken loopToken = _loopCts.Token;

            Logger.LogHandshake(DriverName, $"opening UDP transport to {endpoint} (vni={_config.Vni}, mac={_mac})");
            VxlanTransportHandle handle = await _transportFactory.ConnectAsync(endpoint, cancellationToken).ConfigureAwait(false);
            handle.SetReceiver(OnInboundDatagram);
            _transport = handle.Datagram;
            MarkRunning(); // honour a drop detected while the data plane is still being bound
            if (handle.ReceivePump != null)
                _receiveTask = Task.Run(() => handle.ReceivePump(loopToken));

            // --- L2 data plane: the VXLAN session as an Ethernet channel, bridged to L3 via ARP + VirtualHost ---
            var channel = new VxlanEthernetChannel(_config.Vni, _mac, (wire, ct) => SendAsync(wire, ct), _config.Mtu, Logger);
            _channel = channel;

            var arp = new ArpResolver(_mac, _config.OverlayAddress, channel);
            _arp = arp;

            var virtualHost = new VirtualHost(_mac, channel, arp);
            virtualHost.InboundNonIpFrame += arp.HandleInboundFrame;   // ARP replies/requests arrive on the non-IP seam
            _host2 = virtualHost;

            _tunnelConfig.Mtu = virtualHost.Mtu;                       // link − 14: the bound stack clamps MSS for the Ethernet header
            Facade.SetInner(virtualHost);

            Logger.LogHandshake(DriverName, $"overlay {_config.OverlayAddress}/{_config.PrefixLength}; L2<->L3 bridge bound");
            Logger.LogHandshakeCompleted(DriverName);
            MarkConnected();
        }

        async Task<IPEndPoint> ResolveRemoteEndpointAsync(CancellationToken cancellationToken)
        {
            IPAddress ip = await _hostResolver.ResolveAsync(_host, _addressFamilyPreference, cancellationToken).ConfigureAwait(false);
            return new IPEndPoint(ip, _config.Port);
        }

        // ---- inbound: decode the VXLAN datagram, surface the Ethernet frame to the fabric ----

        void OnInboundDatagram(ReadOnlyMemory<byte> datagram)
        {
            VxlanEthernetChannel? channel = _channel;
            if (channel is null) return;
            if (!VxlanCodec.TryDecodeVxlan(datagram.Span, out uint vni, out ReadOnlyMemory<byte> frame))
            {
                Logger.LogPacketDropped(DriverName, VpnDropReason.Malformed, "not a VXLAN datagram (runt / I-bit clear)");
                return;
            }
            if (_strictVni && vni != _config.Vni)
            {
                Logger.LogPacketDropped(DriverName, VpnDropReason.Unexpected, $"VNI mismatch (got {vni}, expected {_config.Vni})");
                return;
            }
            channel.Deliver(frame);
        }

        ValueTask SendAsync(ReadOnlyMemory<byte> wire, CancellationToken cancellationToken = default)
        {
            IDatagramTransport? transport = _transport;
            if (transport is null) return default;
            return SendCoreAsync(transport, wire, cancellationToken);
        }

        async ValueTask SendCoreAsync(IDatagramTransport transport, ReadOnlyMemory<byte> wire, CancellationToken cancellationToken)
        {
            try { await transport.SendAsync(wire, cancellationToken).ConfigureAwait(false); }
            catch (Exception ex)
            {
                Logger.LogPacketDropped(DriverName, VpnDropReason.Unexpected, $"failed to send datagram: {ex.GetType().Name}: {ex.Message}");
            }
        }

        // ---- teardown ----

        /// <inheritdoc/>
        protected override async Task CleanupAttemptResourcesAsync()
        {
            StopAttemptLoop();

            CancellationTokenSource? loop = _loopCts;
            _loopCts = null;
            try { loop?.Cancel(); } catch { }

            Task? receive = _receiveTask;
            _receiveTask = null;
            if (receive != null) { try { await receive.ConfigureAwait(false); } catch { } }
            loop?.Dispose();

            VirtualHost? host2 = _host2; _host2 = null;
            if (host2 != null) { try { await host2.DisposeAsync().ConfigureAwait(false); } catch { } }
            ArpResolver? arp = _arp; _arp = null;
            if (arp != null) { try { await arp.DisposeAsync().ConfigureAwait(false); } catch { } }
            VxlanEthernetChannel? channel = _channel; _channel = null;
            if (channel != null) { try { await channel.DisposeAsync().ConfigureAwait(false); } catch { } }

            IDatagramTransport? transport = _transport;
            _transport = null;
            if (transport != null) { try { await transport.DisposeAsync().ConfigureAwait(false); } catch { } }
        }

        /// <inheritdoc/>
        protected override void StopAttemptLoop()
        {
            // VXLAN has no per-attempt timer (no keepalive); the receive loop is cancelled via _loopCts in cleanup.
        }

        /// <inheritdoc/>
        public override async Task DisconnectAsync(CancellationToken cancellationToken = default)
            => await DisconnectCoreAsync().ConfigureAwait(false);

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
