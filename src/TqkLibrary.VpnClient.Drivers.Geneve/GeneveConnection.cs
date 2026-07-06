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
using TqkLibrary.VpnClient.Drivers.Geneve.Config;
using TqkLibrary.VpnClient.Drivers.Geneve.DataChannel;
using TqkLibrary.VpnClient.Drivers.Geneve.Transport;
using TqkLibrary.VpnClient.Ethernet;

namespace TqkLibrary.VpnClient.Drivers.Geneve
{
    /// <summary>
    /// A Geneve (RFC 8926) L2-over-UDP endpoint. It opens a connected UDP transport to a static unicast remote endpoint and
    /// then carries full Ethernet frames behind an 8-byte Geneve base header (UDP/6081, protocol type 0x6558) as a
    /// <see cref="GeneveEthernetChannel"/>. That channel plugs into the userspace Ethernet fabric (<see cref="ArpResolver"/>
    /// on the static overlay IP + a <see cref="VirtualHost"/> bridge), which exposes the stable L3
    /// <see cref="ReconnectingVpnConnection.PacketChannel"/> the IP stack binds — the direct sibling of the VXLAN driver.
    /// Like VXLAN there is <b>no control plane</b>: no registration, no keepalive, no transform, no header encryption.
    /// The base header (plus any options) is the whole protocol; the shared supervisor (roadmap F.6) re-opens the transport
    /// on a drop. On ingress the receiver skips options by OptLen and drops any datagram carrying a critical option it
    /// cannot process (RFC 8926 §3.5, in <see cref="GeneveCodec.TryDecodeGeneve"/>).
    /// </summary>
    public sealed class GeneveConnection : ReconnectingVpnConnection, IDisposable, IAsyncDisposable
    {
        readonly string _host;
        readonly GeneveConfig _config;
        readonly IGeneveTransportFactory _transportFactory;
        readonly AddressFamilyPreference _addressFamilyPreference;
        readonly IHostResolver _hostResolver;
        readonly TunnelConfig _tunnelConfig;
        readonly MacAddress _mac;
        readonly bool _strictVni;

        IDatagramTransport? _transport;
        CancellationTokenSource? _loopCts;
        Task? _receiveTask;

        GeneveEthernetChannel? _channel;
        ArpResolver? _arp;
        VirtualHost? _host2;

        /// <summary>
        /// Creates a connection. <paramref name="host"/> is the remote host (from the connect-time endpoint);
        /// <paramref name="config"/> is the static overlay profile; <paramref name="transportFactory"/> opens the UDP
        /// socket to the remote endpoint (an in-process factory drives it offline). <paramref name="strictVni"/> drops an
        /// inbound datagram whose VNI does not match the configured one; <paramref name="loggerFactory"/> receives
        /// diagnostic traces (null = no-op).
        /// </summary>
        public GeneveConnection(string host, IGeneveTransportFactory transportFactory, GeneveConfig config,
            GeneveReconnectOptions? reconnectOptions = null,
            AddressFamilyPreference addressFamilyPreference = AddressFamilyPreference.Auto,
            IHostResolver? hostResolver = null,
            bool strictVni = false,
            ILoggerFactory? loggerFactory = null)
            : base(GeneveDriverConstants.DriverName, reconnectOptions ?? new GeneveReconnectOptions(), clock: null, loggerFactory)
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

        /// <summary>This endpoint's virtual MAC on the Geneve L2 segment.</summary>
        public MacAddress LinkAddress => _mac;

        /// <summary>Opens the UDP transport and returns once the L2 tunnel is carrying traffic (Geneve has no handshake).</summary>
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
            GeneveTransportHandle handle = await _transportFactory.ConnectAsync(endpoint, cancellationToken).ConfigureAwait(false);
            handle.SetReceiver(OnInboundDatagram);
            _transport = handle.Datagram;
            MarkRunning(); // honour a drop detected while the data plane is still being bound
            if (handle.ReceivePump != null)
                _receiveTask = Task.Run(() => handle.ReceivePump(loopToken));

            // --- L2 data plane: the Geneve session as an Ethernet channel, bridged to L3 via ARP + VirtualHost ---
            var channel = new GeneveEthernetChannel(_config.Vni, _mac, (wire, ct) => SendAsync(wire, ct), _config.Mtu, Logger);
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

        // ---- inbound: decode the Geneve datagram, surface the Ethernet frame to the fabric ----

        void OnInboundDatagram(ReadOnlyMemory<byte> datagram)
        {
            GeneveEthernetChannel? channel = _channel;
            if (channel is null) return;
            if (!GeneveCodec.TryDecodeGeneve(datagram.Span, out uint vni, out ushort protocolType, out ReadOnlyMemory<byte> frame))
            {
                Logger.LogPacketDropped(DriverName, VpnDropReason.Malformed, "not a Geneve datagram (runt / bad version / truncated or critical option)");
                return;
            }
            if (protocolType != GeneveCodec.ProtocolTypeTransparentEthernet)
            {
                Logger.LogPacketDropped(DriverName, VpnDropReason.Unexpected, $"unexpected protocol type 0x{protocolType:X4} (expected 0x6558 Ethernet)");
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
            GeneveEthernetChannel? channel = _channel; _channel = null;
            if (channel != null) { try { await channel.DisposeAsync().ConfigureAwait(false); } catch { } }

            IDatagramTransport? transport = _transport;
            _transport = null;
            if (transport != null) { try { await transport.DisposeAsync().ConfigureAwait(false); } catch { } }
        }

        /// <inheritdoc/>
        protected override void StopAttemptLoop()
        {
            // Geneve has no per-attempt timer (no keepalive); the receive loop is cancelled via _loopCts in cleanup.
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
