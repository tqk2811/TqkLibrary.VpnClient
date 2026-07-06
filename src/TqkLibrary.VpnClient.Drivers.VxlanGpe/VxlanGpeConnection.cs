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
using TqkLibrary.VpnClient.Drivers.VxlanGpe.Config;
using TqkLibrary.VpnClient.Drivers.VxlanGpe.DataChannel;
using TqkLibrary.VpnClient.Drivers.VxlanGpe.Transport;
using TqkLibrary.VpnClient.Ethernet;

namespace TqkLibrary.VpnClient.Drivers.VxlanGpe
{
    /// <summary>
    /// A VXLAN-GPE (Generic Protocol Extension, draft-ietf-nvo3-vxlan-gpe) L2-over-UDP endpoint. It opens a connected UDP
    /// transport to a static unicast remote peer and then carries full Ethernet frames behind an 8-byte VXLAN-GPE header
    /// (UDP/4790, Next Protocol 0x03 Ethernet) as a <see cref="VxlanGpeEthernetChannel"/>. That channel plugs into the
    /// userspace Ethernet fabric (<see cref="ArpResolver"/> on the static overlay IP + a <see cref="VirtualHost"/> bridge),
    /// which exposes the stable L3 <see cref="ReconnectingVpnConnection.PacketChannel"/> the IP stack binds — mirroring the
    /// VXLAN driver. Unlike VXLAN the header sets the P (Next-Protocol-present) bit and names the payload with a Next
    /// Protocol byte, so inbound datagrams whose Next Protocol is not Ethernet (or that are OAM) are dropped.
    /// Like VXLAN there is <b>no control plane</b>: no registration, no keepalive, no transform, no header encryption.
    /// The 8-byte header is the whole protocol; the shared supervisor (roadmap F.6) re-opens the transport on a drop.
    /// </summary>
    public sealed class VxlanGpeConnection : ReconnectingVpnConnection, IDisposable, IAsyncDisposable
    {
        readonly string _host;
        readonly VxlanGpeConfig _config;
        readonly IVxlanGpeTransportFactory _transportFactory;
        readonly AddressFamilyPreference _addressFamilyPreference;
        readonly IHostResolver _hostResolver;
        readonly TunnelConfig _tunnelConfig;
        readonly MacAddress _mac;
        readonly bool _strictVni;

        IDatagramTransport? _transport;
        CancellationTokenSource? _loopCts;
        Task? _receiveTask;

        VxlanGpeEthernetChannel? _channel;
        ArpResolver? _arp;
        VirtualHost? _host2;

        /// <summary>
        /// Creates a connection. <paramref name="host"/> is the remote peer host (from the connect-time endpoint);
        /// <paramref name="config"/> is the static overlay profile; <paramref name="transportFactory"/> opens the UDP socket
        /// to the remote peer (an in-process factory drives it offline). <paramref name="strictVni"/> drops an inbound
        /// datagram whose VNI does not match the configured one; <paramref name="loggerFactory"/> receives diagnostic
        /// traces (null = no-op).
        /// </summary>
        public VxlanGpeConnection(string host, IVxlanGpeTransportFactory transportFactory, VxlanGpeConfig config,
            VxlanGpeReconnectOptions? reconnectOptions = null,
            AddressFamilyPreference addressFamilyPreference = AddressFamilyPreference.Auto,
            IHostResolver? hostResolver = null,
            bool strictVni = false,
            ILoggerFactory? loggerFactory = null)
            : base(VxlanGpeDriverConstants.DriverName, reconnectOptions ?? new VxlanGpeReconnectOptions(), clock: null, loggerFactory)
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

        /// <summary>This endpoint's virtual MAC on the VXLAN-GPE L2 segment.</summary>
        public MacAddress LinkAddress => _mac;

        /// <summary>Opens the UDP transport and returns once the L2 tunnel is carrying traffic (VXLAN-GPE has no handshake).</summary>
        public Task ConnectAsync(CancellationToken cancellationToken = default) => ConnectCoreAsync(cancellationToken);

        // ---- one full tunnel attempt (reused by the first connect and every reconnect) ----

        /// <inheritdoc/>
        protected override async Task EstablishAsync(CancellationToken cancellationToken)
        {
            await CleanupAttemptResourcesAsync().ConfigureAwait(false);

            IPEndPoint endpoint = await ResolveRemoteEndpointAsync(cancellationToken).ConfigureAwait(false);
            _loopCts = CancellationTokenSource.CreateLinkedTokenSource(LifetimeToken, cancellationToken);
            CancellationToken loopToken = _loopCts.Token;

            Logger.LogHandshake(DriverName, $"opening UDP transport to {endpoint} (vni={_config.Vni}, next-proto={_config.NextProtocol}, mac={_mac})");
            VxlanGpeTransportHandle handle = await _transportFactory.ConnectAsync(endpoint, cancellationToken).ConfigureAwait(false);
            handle.SetReceiver(OnInboundDatagram);
            _transport = handle.Datagram;
            MarkRunning(); // honour a drop detected while the data plane is still being bound
            if (handle.ReceivePump != null)
                _receiveTask = Task.Run(() => handle.ReceivePump(loopToken));

            // --- L2 data plane: the VXLAN-GPE session as an Ethernet channel, bridged to L3 via ARP + VirtualHost ---
            var channel = new VxlanGpeEthernetChannel(_config.Vni, _config.NextProtocolByte, _mac, (wire, ct) => SendAsync(wire, ct), _config.Mtu, Logger);
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

        // ---- inbound: decode the VXLAN-GPE datagram, surface the Ethernet frame to the fabric ----

        void OnInboundDatagram(ReadOnlyMemory<byte> datagram)
        {
            VxlanGpeEthernetChannel? channel = _channel;
            if (channel is null) return;
            if (!VxlanGpeHeader.TryDecodeVxlanGpe(datagram.Span, out uint vni, out byte nextProtocol, out ReadOnlyMemory<byte> frame))
            {
                Logger.LogPacketDropped(DriverName, VpnDropReason.Malformed, "not a VXLAN-GPE datagram (runt / bad version / I or P bit clear / OAM)");
                return;
            }
            if (nextProtocol != VxlanGpeHeader.NextProtocolEthernet)
            {
                Logger.LogPacketDropped(DriverName, VpnDropReason.Unexpected, $"unsupported Next Protocol 0x{nextProtocol:X2} (only Ethernet 0x03 is wired)");
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
            VxlanGpeEthernetChannel? channel = _channel; _channel = null;
            if (channel != null) { try { await channel.DisposeAsync().ConfigureAwait(false); } catch { } }

            IDatagramTransport? transport = _transport;
            _transport = null;
            if (transport != null) { try { await transport.DisposeAsync().ConfigureAwait(false); } catch { } }
        }

        /// <inheritdoc/>
        protected override void StopAttemptLoop()
        {
            // VXLAN-GPE has no per-attempt timer (no keepalive); the receive loop is cancelled via _loopCts in cleanup.
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
