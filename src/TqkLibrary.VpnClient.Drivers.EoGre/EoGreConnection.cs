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
using TqkLibrary.VpnClient.Drivers.EoGre.Config;
using TqkLibrary.VpnClient.Drivers.EoGre.DataChannel;
using TqkLibrary.VpnClient.Drivers.EoGre.Enums;
using TqkLibrary.VpnClient.Drivers.EoGre.Transport;
using TqkLibrary.VpnClient.Ethernet;

namespace TqkLibrary.VpnClient.Drivers.EoGre
{
    /// <summary>
    /// An EoGRE / NVGRE (RFC 8086 + RFC 2784/2890 + RFC 7637) L2-over-UDP endpoint. It opens a connected UDP transport to a
    /// static unicast remote endpoint and then carries full Ethernet frames behind a standard GRE header (protocol type
    /// 0x6558, the reused <see cref="EoGreCodec"/> over <c>GreCodec</c>) inside a UDP payload (default 4754) as an
    /// <see cref="EoGreEthernetChannel"/>. That channel plugs into the userspace Ethernet fabric (<see cref="ArpResolver"/>
    /// on the static overlay IP + a <see cref="VirtualHost"/> bridge), which exposes the stable L3
    /// <see cref="ReconnectingVpnConnection.PacketChannel"/> the IP stack binds — the L2 sibling of the GRE-in-UDP L3
    /// driver and of VXLAN / Geneve. Like them there is <b>no control plane</b>: no registration, no keepalive, no
    /// transform, no encryption; the shared supervisor (roadmap F.6) re-opens the transport on a drop.
    /// <para>In <see cref="EoGreMode.Nvgre"/> the GRE Key carries a mandatory 24-bit VSID + 8-bit FlowID and the Checksum /
    /// Sequence fields are forced off (RFC 7637); in <see cref="EoGreMode.EoGre"/> the VSID / Checksum / Sequence are all
    /// optional per the config. Inbound datagrams whose protocol type is not 0x6558 (or whose VSID does not match, when
    /// strict) are dropped.</para>
    /// </summary>
    public sealed class EoGreConnection : ReconnectingVpnConnection, IDisposable, IAsyncDisposable
    {
        readonly string _host;
        readonly EoGreConfig _config;
        readonly EoGreMode _mode;
        readonly IEoGreTransportFactory _transportFactory;
        readonly AddressFamilyPreference _addressFamilyPreference;
        readonly IHostResolver _hostResolver;
        readonly TunnelConfig _tunnelConfig;
        readonly MacAddress _mac;

        // Effective wire parameters derived from the config + mode (NVGRE forces Checksum/Sequence off and VSID strict).
        readonly uint? _vsid;
        readonly byte _flowId;
        readonly bool _includeChecksum;
        readonly bool _emitSequence;
        readonly bool _strictVsid;

        IDatagramTransport? _transport;
        CancellationTokenSource? _loopCts;
        Task? _receiveTask;

        EoGreEthernetChannel? _channel;
        ArpResolver? _arp;
        VirtualHost? _host2;

        /// <summary>
        /// Creates a connection. <paramref name="host"/> is the remote host (from the connect-time endpoint);
        /// <paramref name="config"/> is the static overlay profile; <paramref name="mode"/> selects EoGRE vs NVGRE;
        /// <paramref name="transportFactory"/> opens the UDP socket to the remote endpoint (an in-process factory drives it
        /// offline); <paramref name="loggerFactory"/> receives diagnostic traces (null = no-op).
        /// </summary>
        public EoGreConnection(string host, IEoGreTransportFactory transportFactory, EoGreConfig config,
            EoGreMode mode = EoGreMode.EoGre,
            EoGreReconnectOptions? reconnectOptions = null,
            AddressFamilyPreference addressFamilyPreference = AddressFamilyPreference.Auto,
            IHostResolver? hostResolver = null,
            ILoggerFactory? loggerFactory = null)
            : base(mode == EoGreMode.Nvgre ? EoGreDriverConstants.DriverNameNvgre : EoGreDriverConstants.DriverNameEoGre,
                reconnectOptions ?? new EoGreReconnectOptions(), clock: null, loggerFactory)
        {
            _host = host ?? throw new ArgumentNullException(nameof(host));
            _config = config ?? throw new ArgumentNullException(nameof(config));
            _mode = mode;
            _transportFactory = transportFactory ?? throw new ArgumentNullException(nameof(transportFactory));
            _addressFamilyPreference = addressFamilyPreference;
            _hostResolver = hostResolver ?? DnsHostResolver.Default;

            config.Validate(mode);
            _tunnelConfig = config.ToTunnelConfig();
            _mac = config.ResolveLocalMac(NextRandomBytes);

            bool nvgre = mode == EoGreMode.Nvgre;
            _vsid = config.Vsid;                              // NVGRE guarantees non-null (Validate)
            _flowId = config.FlowId;
            _includeChecksum = !nvgre && config.EnableChecksum;   // NVGRE (RFC 7637) forbids the Checksum
            _emitSequence = !nvgre && config.EnableSequence;      // NVGRE (RFC 7637) forbids the Sequence Number
            _strictVsid = (nvgre || config.StrictVsid) && _vsid.HasValue;
        }

        /// <summary>The static tunnel configuration (overlay address, prefix, DNS, routes, MTU).</summary>
        public TunnelConfig Config => _tunnelConfig;

        /// <summary>The local overlay (tunnel) IPv4 address (the static overlay address).</summary>
        public IPAddress AssignedAddress => _config.OverlayAddress;

        /// <summary>This endpoint's virtual MAC on the EoGRE L2 segment.</summary>
        public MacAddress LinkAddress => _mac;

        /// <summary>Opens the UDP transport and returns once the L2 tunnel is carrying traffic (EoGRE has no handshake).</summary>
        public Task ConnectAsync(CancellationToken cancellationToken = default) => ConnectCoreAsync(cancellationToken);

        // ---- one full tunnel attempt (reused by the first connect and every reconnect) ----

        /// <inheritdoc/>
        protected override async Task EstablishAsync(CancellationToken cancellationToken)
        {
            await CleanupAttemptResourcesAsync().ConfigureAwait(false);

            IPEndPoint endpoint = await ResolveRemoteEndpointAsync(cancellationToken).ConfigureAwait(false);
            _loopCts = CancellationTokenSource.CreateLinkedTokenSource(LifetimeToken, cancellationToken);
            CancellationToken loopToken = _loopCts.Token;

            string vsidText = _vsid.HasValue ? _vsid.Value.ToString() : "none";
            Logger.LogHandshake(DriverName, $"opening UDP transport to {endpoint} (vsid={vsidText}, mac={_mac})");
            EoGreTransportHandle handle = await _transportFactory.ConnectAsync(endpoint, cancellationToken).ConfigureAwait(false);
            handle.SetReceiver(OnInboundDatagram);
            _transport = handle.Datagram;
            MarkRunning(); // honour a drop detected while the data plane is still being bound
            if (handle.ReceivePump != null)
                _receiveTask = Task.Run(() => handle.ReceivePump(loopToken));

            // --- L2 data plane: the EoGRE session as an Ethernet channel, bridged to L3 via ARP + VirtualHost ---
            var channel = new EoGreEthernetChannel(_vsid, _flowId, _includeChecksum, _emitSequence, _mac,
                (wire, ct) => SendAsync(wire, ct), _config.Mtu, Logger);
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

        // ---- inbound: decode the GRE-in-UDP datagram, surface the Ethernet frame to the fabric ----

        void OnInboundDatagram(ReadOnlyMemory<byte> datagram)
        {
            EoGreEthernetChannel? channel = _channel;
            if (channel is null) return;
            if (!EoGreCodec.TryDecodeEoGre(datagram.Span, out ushort protocolType, out ReadOnlyMemory<byte> frame, out uint? key, out _))
            {
                Logger.LogPacketDropped(DriverName, VpnDropReason.Malformed, "not a GRE datagram (runt / bad version / truncated field / bad checksum)");
                return;
            }
            if (protocolType != EoGreCodec.ProtocolTypeTransparentEthernet)
            {
                Logger.LogPacketDropped(DriverName, VpnDropReason.Unexpected, $"unexpected protocol type 0x{protocolType:X4} (expected 0x6558 Ethernet)");
                return;
            }
            if (_strictVsid)
            {
                uint? inboundVsid = null;
                if (key.HasValue) { EoGreCodec.UnpackKey(key.Value, out uint v, out _); inboundVsid = v; }
                if (inboundVsid != _vsid)
                {
                    Logger.LogPacketDropped(DriverName, VpnDropReason.Unexpected,
                        $"VSID mismatch (got {(inboundVsid.HasValue ? inboundVsid.Value.ToString() : "none")}, expected {_vsid!.Value})");
                    return;
                }
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
            EoGreEthernetChannel? channel = _channel; _channel = null;
            if (channel != null) { try { await channel.DisposeAsync().ConfigureAwait(false); } catch { } }

            IDatagramTransport? transport = _transport;
            _transport = null;
            if (transport != null) { try { await transport.DisposeAsync().ConfigureAwait(false); } catch { } }
        }

        /// <inheritdoc/>
        protected override void StopAttemptLoop()
        {
            // EoGRE has no per-attempt timer (no keepalive); the receive loop is cancelled via _loopCts in cleanup.
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
