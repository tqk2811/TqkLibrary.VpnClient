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
using TqkLibrary.VpnClient.Drivers.L2tpv3Eth.Config;
using TqkLibrary.VpnClient.Drivers.L2tpv3Eth.DataChannel;
using TqkLibrary.VpnClient.Drivers.L2tpv3Eth.Enums;
using TqkLibrary.VpnClient.Drivers.L2tpv3Eth.Transport;
using TqkLibrary.VpnClient.Ethernet;

namespace TqkLibrary.VpnClient.Drivers.L2tpv3Eth
{
    /// <summary>
    /// An L2TPv3 (RFC 3931) Ethernet-pseudowire (RFC 4719) endpoint in <b>static/unmanaged</b> mode. It opens a connected UDP
    /// transport to a static unicast remote endpoint and then carries full Ethernet frames behind an L2TPv3 data header
    /// (Session ID + optional Cookie + optional Default L2-Specific Sublayer) as a <see cref="L2tpv3EthEthernetChannel"/>. That
    /// channel plugs into the userspace Ethernet fabric (<see cref="ArpResolver"/> on the static overlay IP + a
    /// <see cref="VirtualHost"/> bridge), which exposes the stable L3 <see cref="ReconnectingVpnConnection.PacketChannel"/>
    /// the IP stack binds — the sibling of the VXLAN / Geneve drivers. Like them there is <b>no control plane</b>: no L2TP
    /// control channel, no handshake, no keepalive, no encryption. The Session IDs and Cookie are configured up front on both
    /// peers; the shared supervisor (roadmap F.6) re-opens the transport on a drop. On ingress the receiver drops any datagram
    /// that is not a data message for the configured local session (control message / zero Session ID / mismatched Session ID
    /// or Cookie / truncated header — in <see cref="L2tpv3DataHeader.TryDecodeData"/>).
    /// </summary>
    public sealed class L2tpv3EthConnection : ReconnectingVpnConnection, IDisposable, IAsyncDisposable
    {
        readonly string _host;
        readonly L2tpv3EthConfig _config;
        readonly IL2tpv3EthTransportFactory _transportFactory;
        readonly AddressFamilyPreference _addressFamilyPreference;
        readonly IHostResolver _hostResolver;
        readonly TunnelConfig _tunnelConfig;
        readonly MacAddress _mac;
        readonly byte[] _cookie;

        IDatagramTransport? _transport;
        CancellationTokenSource? _loopCts;
        Task? _receiveTask;

        L2tpv3EthEthernetChannel? _channel;
        ArpResolver? _arp;
        VirtualHost? _host2;

        /// <summary>
        /// Creates a connection. <paramref name="host"/> is the remote host (from the connect-time endpoint);
        /// <paramref name="config"/> is the static pseudowire profile; <paramref name="transportFactory"/> opens the UDP socket
        /// to the remote endpoint (an in-process factory drives it offline). <paramref name="loggerFactory"/> receives
        /// diagnostic traces (null = no-op).
        /// </summary>
        public L2tpv3EthConnection(string host, IL2tpv3EthTransportFactory transportFactory, L2tpv3EthConfig config,
            L2tpv3EthReconnectOptions? reconnectOptions = null,
            AddressFamilyPreference addressFamilyPreference = AddressFamilyPreference.Auto,
            IHostResolver? hostResolver = null,
            ILoggerFactory? loggerFactory = null)
            : base(L2tpv3EthDriverConstants.DriverName, reconnectOptions ?? new L2tpv3EthReconnectOptions(), clock: null, loggerFactory)
        {
            _host = host ?? throw new ArgumentNullException(nameof(host));
            _config = config ?? throw new ArgumentNullException(nameof(config));
            _transportFactory = transportFactory ?? throw new ArgumentNullException(nameof(transportFactory));
            _addressFamilyPreference = addressFamilyPreference;
            _hostResolver = hostResolver ?? DnsHostResolver.Default;
            _mac = config.ResolveLocalMac(NextRandomBytes);       // also validates session ids + cookie length
            _cookie = config.CookieBytes.ToArray();
            _tunnelConfig = config.ToTunnelConfig();
        }

        /// <summary>The static tunnel configuration (overlay address, prefix, DNS, routes, MTU).</summary>
        public TunnelConfig Config => _tunnelConfig;

        /// <summary>The local overlay (tunnel) IPv4 address (the static overlay address).</summary>
        public IPAddress AssignedAddress => _config.OverlayAddress;

        /// <summary>This endpoint's virtual MAC on the L2TPv3 L2 segment.</summary>
        public MacAddress LinkAddress => _mac;

        /// <summary>Opens the UDP transport and returns once the L2 pseudowire is carrying traffic (L2TPv3 static mode has no handshake).</summary>
        public Task ConnectAsync(CancellationToken cancellationToken = default) => ConnectCoreAsync(cancellationToken);

        // ---- one full tunnel attempt (reused by the first connect and every reconnect) ----

        /// <inheritdoc/>
        protected override async Task EstablishAsync(CancellationToken cancellationToken)
        {
            await CleanupAttemptResourcesAsync().ConfigureAwait(false);

            IPEndPoint endpoint = await ResolveRemoteEndpointAsync(cancellationToken).ConfigureAwait(false);
            _loopCts = CancellationTokenSource.CreateLinkedTokenSource(LifetimeToken, cancellationToken);
            CancellationToken loopToken = _loopCts.Token;

            Logger.LogHandshake(DriverName, $"opening UDP transport to {endpoint} (local-sid={_config.LocalSessionId}, remote-sid={_config.RemoteSessionId}, cookie={_cookie.Length}B, seq={_config.EnableSequencing}, mac={_mac})");
            L2tpv3EthTransportHandle handle = await _transportFactory.ConnectAsync(endpoint, cancellationToken).ConfigureAwait(false);
            handle.SetReceiver(OnInboundDatagram);
            _transport = handle.Datagram;
            MarkRunning(); // honour a drop detected while the data plane is still being bound
            if (handle.ReceivePump != null)
                _receiveTask = Task.Run(() => handle.ReceivePump(loopToken));

            // --- L2 data plane: the L2TPv3 session as an Ethernet channel, bridged to L3 via ARP + VirtualHost ---
            var channel = new L2tpv3EthEthernetChannel(_config.RemoteSessionId, _cookie, _config.EnableSequencing, _mac,
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

        // ---- inbound: decode the L2TPv3 data message, surface the Ethernet frame to the fabric ----

        void OnInboundDatagram(ReadOnlyMemory<byte> datagram)
        {
            L2tpv3EthEthernetChannel? channel = _channel;
            if (channel is null) return;
            if (!L2tpv3DataHeader.TryDecodeData(datagram.Span, _config.LocalSessionId, _cookie, _config.EnableSequencing,
                    out _, out ReadOnlyMemory<byte> frame, out L2tpv3DecodeError decodeError))
            {
                Logger.LogPacketDropped(DriverName, DropReasonFor(decodeError), DropDescriptionFor(decodeError));
                return;
            }
            channel.Deliver(frame);
        }

        static VpnDropReason DropReasonFor(L2tpv3DecodeError error) => error switch
        {
            L2tpv3DecodeError.Runt => VpnDropReason.Malformed,
            L2tpv3DecodeError.Truncated => VpnDropReason.Malformed,
            _ => VpnDropReason.Unexpected,
        };

        static string DropDescriptionFor(L2tpv3DecodeError error) => error switch
        {
            L2tpv3DecodeError.Runt => "runt (shorter than an L2TPv3 Session ID)",
            L2tpv3DecodeError.ControlMessage => "control message (T-bit set), not data",
            L2tpv3DecodeError.ZeroSessionId => "Session ID 0 (control channel)",
            L2tpv3DecodeError.SessionIdMismatch => "Session ID does not match the configured local session",
            L2tpv3DecodeError.CookieMismatch => "Cookie mismatch",
            L2tpv3DecodeError.Truncated => "truncated header (Cookie / L2-Specific Sublayer runs past the datagram)",
            _ => "not an L2TPv3 data message for this session",
        };

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
            L2tpv3EthEthernetChannel? channel = _channel; _channel = null;
            if (channel != null) { try { await channel.DisposeAsync().ConfigureAwait(false); } catch { } }

            IDatagramTransport? transport = _transport;
            _transport = null;
            if (transport != null) { try { await transport.DisposeAsync().ConfigureAwait(false); } catch { } }
        }

        /// <inheritdoc/>
        protected override void StopAttemptLoop()
        {
            // L2TPv3 static mode has no per-attempt timer (no keepalive); the receive loop is cancelled via _loopCts in cleanup.
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
