using System.Net;
using TqkLibrary.VpnClient.Abstractions.Channels.Interfaces;
using TqkLibrary.VpnClient.Abstractions.Diagnostics.Enums;
using TqkLibrary.VpnClient.Abstractions.Diagnostics.Extensions;
using TqkLibrary.VpnClient.Abstractions.Drivers;
using TqkLibrary.VpnClient.Abstractions.Drivers.Models;
using TqkLibrary.VpnClient.Abstractions.Net;
using TqkLibrary.VpnClient.Abstractions.Transport.Interfaces;
using Microsoft.Extensions.Logging;
using TqkLibrary.VpnClient.Drivers.Core;
using TqkLibrary.VpnClient.Drivers.N2n.Config;
using TqkLibrary.VpnClient.Drivers.N2n.DataChannel;
using TqkLibrary.VpnClient.Drivers.N2n.Enums;
using TqkLibrary.VpnClient.Drivers.N2n.Transport;
using TqkLibrary.VpnClient.Ethernet;
using TqkLibrary.VpnClient.N2n;
using TqkLibrary.VpnClient.N2n.Transform;
using TqkLibrary.VpnClient.N2n.Transform.Interfaces;
using TqkLibrary.VpnClient.N2n.Wire.Enums;
using TqkLibrary.VpnClient.N2n.Wire.Models;

namespace TqkLibrary.VpnClient.Drivers.N2n
{
    /// <summary>
    /// A complete n2n v3 edge client. It opens a UDP transport to the supernode, registers the edge
    /// (REGISTER_SUPER → REGISTER_SUPER_ACK), then carries full Ethernet frames as PACKET messages (relayed via the
    /// supernode) behind an L2 <see cref="N2nEthernetChannel"/>. That channel plugs into the userspace Ethernet fabric
    /// (<see cref="ArpResolver"/> on the static overlay IP + a <see cref="VirtualHost"/> bridge), which exposes the
    /// stable L3 <see cref="ReconnectingVpnConnection{TState}.PacketChannel"/> the IP stack binds — mirroring the
    /// SoftEther / OpenVPN tap drivers. A keepalive timer re-sends REGISTER_SUPER so the supernode keeps the edge
    /// registered, and the shared supervisor / auto-reconnect (roadmap F.6) re-establishes a dead tunnel. Not a server —
    /// the supernode role lives only in tests. P2P edge↔edge (REGISTER / QUERY_PEER) is left as a stretch: the
    /// supernode relay is enough for the point-to-point case.
    /// </summary>
    public sealed class N2nConnection : ReconnectingVpnConnection<N2nConnectionState>, IDisposable, IAsyncDisposable
    {
        const int MacSize = 6;

        readonly string _host;
        readonly int _port;
        readonly N2nConfig _config;
        readonly IN2nTransportFactory _transportFactory;
        readonly AddressFamilyPreference _addressFamilyPreference;
        readonly IHostResolver _hostResolver;
        readonly TunnelConfig _tunnelConfig;

        readonly N2nPacketCodec _codec = new();
        readonly IN2nTransform _transform;
        readonly MacAddress _mac;
        readonly TimeSpan _handshakeTimeout;
        // The supernode pins the auth token from the first REGISTER_SUPER and rejects (REGISTER_SUPER_NAK,
        // "authentication failed") any keepalive that carries a different one — so the token is generated ONCE per
        // connection and reused for the initial registration and every keepalive re-register.
        readonly N2nAuth _auth = N2nAuth.SimpleIdRandom();

        IDatagramTransport? _transport;
        CancellationTokenSource? _loopCts;
        Task? _receiveTask;
        System.Threading.Timer? _timer;
        volatile bool _timerRunning;

        N2nEthernetChannel? _channel;
        ArpResolver? _arp;
        VirtualHost? _host2;
        TaskCompletionSource<N2nRegisterSuperAck>? _registerAckTcs;
        uint _registerCookie;
        TimeSpan _keepAliveInterval = TimeSpan.FromSeconds(N2nDriverConstants.DefaultRegistrationLifetimeSeconds / 2);

        /// <summary>
        /// Creates a connection. <paramref name="config"/> is the static edge profile; <paramref name="transportFactory"/>
        /// opens the UDP socket to the supernode (an in-process factory drives it offline). <paramref name="clock"/>
        /// supplies the millisecond clock (tests inject a deterministic one); <paramref name="loggerFactory"/> receives
        /// diagnostic traces (null = no-op).
        /// </summary>
        public N2nConnection(string host, int port, N2nConfig config, IN2nTransportFactory transportFactory,
            N2nReconnectOptions? reconnectOptions = null,
            AddressFamilyPreference addressFamilyPreference = AddressFamilyPreference.Auto,
            IHostResolver? hostResolver = null,
            TimeSpan? handshakeTimeout = null,
            Func<long>? clock = null,
            ILoggerFactory? loggerFactory = null)
            : base(N2nDriverConstants.DriverName, reconnectOptions ?? new N2nReconnectOptions(), clock, loggerFactory)
        {
            _host = host ?? throw new ArgumentNullException(nameof(host));
            _port = port;
            _config = config ?? throw new ArgumentNullException(nameof(config));
            _transportFactory = transportFactory ?? throw new ArgumentNullException(nameof(transportFactory));
            _addressFamilyPreference = addressFamilyPreference;
            _hostResolver = hostResolver ?? DnsHostResolver.Default;
            _handshakeTimeout = handshakeTimeout ?? TimeSpan.FromSeconds(10);
            _tunnelConfig = config.ToTunnelConfig();
            _transform = BuildTransform(config);
            _mac = ResolveMac(config);
        }

        /// <summary>The static tunnel configuration (overlay address, prefix, DNS, routes, MTU).</summary>
        public TunnelConfig Config => _tunnelConfig;

        /// <summary>The local overlay (tunnel) IPv4 address (the static <c>-a</c> address).</summary>
        public IPAddress AssignedAddress => _config.OverlayAddress;

        /// <summary>This edge's virtual MAC on the n2n L2 segment.</summary>
        public MacAddress LinkAddress => _mac;

        /// <inheritdoc/>
        protected override N2nConnectionState DisconnectedState => N2nConnectionState.Disconnected;
        /// <inheritdoc/>
        protected override N2nConnectionState ConnectingState => N2nConnectionState.Connecting;
        /// <inheritdoc/>
        protected override N2nConnectionState ConnectedState => N2nConnectionState.Connected;
        /// <inheritdoc/>
        protected override N2nConnectionState ReconnectingState => N2nConnectionState.Reconnecting;

        /// <summary>Runs the REGISTER_SUPER exchange and returns once the L2 tunnel is carrying traffic.</summary>
        public Task ConnectAsync(CancellationToken cancellationToken = default) => ConnectCoreAsync(cancellationToken);

        // ---- one full tunnel attempt (reused by the first connect and every reconnect) ----

        /// <inheritdoc/>
        protected override async Task EstablishAsync(CancellationToken cancellationToken)
        {
            await CleanupAttemptResourcesAsync().ConfigureAwait(false);

            IPEndPoint endpoint = await ResolveSupernodeEndpointAsync(cancellationToken).ConfigureAwait(false);
            _loopCts = CancellationTokenSource.CreateLinkedTokenSource(LifetimeToken, cancellationToken);
            CancellationToken loopToken = _loopCts.Token;

            N2nTransportHandle handle = await _transportFactory.ConnectAsync(endpoint, cancellationToken).ConfigureAwait(false);
            handle.SetReceiver(OnInboundDatagram);
            _transport = handle.Datagram;
            MarkRunning(); // honour a drop detected while the registration is still in flight
            if (handle.ReceivePump != null)
                _receiveTask = Task.Run(() => handle.ReceivePump(loopToken));

            // --- REGISTER_SUPER → REGISTER_SUPER_ACK ---
            Logger.LogHandshake(DriverName, $"REGISTER_SUPER (community={_config.Community}, mac={_mac})");
            N2nRegisterSuperAck ack = await RegisterSuperAsync(cancellationToken).ConfigureAwait(false);
            ApplyAck(ack);

            // --- L2 data plane: the data session as an Ethernet channel, bridged to L3 via ARP + VirtualHost ---
            var channel = new N2nEthernetChannel(_codec, _config.Community, _mac.ToArray(), _transform,
                (wire, ct) => SendAsync(wire, ct), _config.Mtu);
            _channel = channel;

            var arp = new ArpResolver(_mac, _config.OverlayAddress, channel);
            _arp = arp;

            var virtualHost = new VirtualHost(_mac, channel, arp);
            virtualHost.InboundNonIpFrame += arp.HandleInboundFrame;   // ARP replies/requests arrive on the non-IP seam
            _host2 = virtualHost;

            _tunnelConfig.Mtu = virtualHost.Mtu;                       // link − 14: the bound stack clamps MSS for the Ethernet header
            Facade.SetInner(virtualHost);

            StartKeepAlive();
            Logger.LogHandshake(DriverName, $"registered; overlay {_config.OverlayAddress}/{_config.PrefixLength}; L2<->L3 bridge bound");
            Logger.LogHandshakeCompleted(DriverName);
            MarkConnected();
        }

        async Task<IPEndPoint> ResolveSupernodeEndpointAsync(CancellationToken cancellationToken)
        {
            IPAddress ip = await _hostResolver.ResolveAsync(_host, _addressFamilyPreference, cancellationToken).ConfigureAwait(false);
            return new IPEndPoint(ip, _port);
        }

        // ---- registration: send REGISTER_SUPER, wait for the supernode's REGISTER_SUPER_ACK ----

        async Task<N2nRegisterSuperAck> RegisterSuperAsync(CancellationToken cancellationToken)
        {
            var tcs = new TaskCompletionSource<N2nRegisterSuperAck>(TaskCreationOptions.RunContinuationsAsynchronously);
            _registerAckTcs = tcs;
            _registerCookie = NextCookie();

            var body = new N2nRegisterSuper
            {
                Cookie = _registerCookie,
                EdgeMac = _mac.ToArray(),
                Sock = null,                       // header N2N_FLAGS_SOCKET off: let the supernode observe our public socket
                DevAddr = BuildDevAddr(),          // advertise our static -a overlay address (what a real n2n edge with -a does)
                DevDesc = "tqkvpn",
                Auth = _auth,
                KeyTime = 0,
            };
            byte[] datagram = _codec.EncodeRegisterSuper(_config.Community, body);
            await SendAsync(datagram, cancellationToken).ConfigureAwait(false);

            using var timeoutCts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
            timeoutCts.CancelAfter(_handshakeTimeout);
            using (timeoutCts.Token.Register(() => tcs.TrySetCanceled()))
            {
                try
                {
                    return await tcs.Task.ConfigureAwait(false);
                }
                catch (OperationCanceledException) when (!cancellationToken.IsCancellationRequested)
                {
                    Logger.LogHandshakeFailed(DriverName, "no REGISTER_SUPER_ACK from the supernode within the handshake timeout");
                    throw new VpnConnectionException("n2n registration timed out: no REGISTER_SUPER_ACK from the supernode.");
                }
            }
        }

        // Adopt the supernode's reply: the registration lifetime drives the keepalive cadence; a supernode-assigned
        // subnet (dev_addr) is logged but not adopted — this edge uses its own static overlay address.
        void ApplyAck(N2nRegisterSuperAck ack)
        {
            if (ack.Lifetime > 0)
                _keepAliveInterval = TimeSpan.FromSeconds(Math.Max(1, ack.Lifetime / 2));
            string assigned = ack.DevAddr.NetBitLen > 0
                ? $"{FormatIpv4(ack.DevAddr.NetAddr)}/{ack.DevAddr.NetBitLen}"
                : "(none)";
            Logger.LogHandshake(DriverName, $"REGISTER_SUPER_ACK (lifetime={ack.Lifetime}s, sn-assigned={assigned}); using static {_config.OverlayAddress}");
        }

        // ---- inbound demux: route by n2n message type ----

        void OnInboundDatagram(ReadOnlyMemory<byte> datagram)
        {
            ReadOnlySpan<byte> span = datagram.Span;
            if (!_codec.TryPeekHeader(span, out N2nCommonHeader header)) return;

            switch (header.PacketType)
            {
                case N2nPacketType.RegisterSuperAck: OnRegisterSuperAck(span); break;
                case N2nPacketType.RegisterSuperNak: OnRegisterSuperNak(); break;
                case N2nPacketType.Packet: OnPacket(span); break;
                case N2nPacketType.ReRegisterSuper: OnReRegisterSuper(); break;
                case N2nPacketType.Register: OnRegister(span); break;
                // Ping / PeerInfo / QueryPeer are not consumed (supernode-relay point-to-point with a static address).
                default: break;
            }
        }

        void OnRegisterSuperAck(ReadOnlySpan<byte> span)
        {
            if (!_codec.TryDecodeRegisterSuperAck(span, out _, out N2nRegisterSuperAck ack)) return;
            TaskCompletionSource<N2nRegisterSuperAck>? tcs = _registerAckTcs;
            if (tcs is null) return;                       // a keepalive ACK after the tunnel is up: nothing to await
            if (ack.Cookie != _registerCookie) return;     // not our request
            tcs.TrySetResult(ack);
        }

        void OnRegisterSuperNak()
            => Logger.LogPacketDropped(DriverName, VpnDropReason.Unexpected, "supernode sent REGISTER_SUPER_NAK (community/auth rejected)");

        void OnReRegisterSuper()
        {
            // The supernode asked us to re-register early; send a fresh REGISTER_SUPER (keepalive path, no ACK awaited).
            Logger.LogHandshake(DriverName, "supernode requested re-registration");
            _ = SendKeepAliveRegisterAsync();
        }

        void OnRegister(ReadOnlySpan<byte> span)
        {
            // An edge↔edge REGISTER (P2P hole-punch attempt). Supernode-relay is sufficient here; acknowledge so the
            // peer stops retrying, but keep carrying data through the supernode.
            if (!_codec.TryDecodeRegister(span, out _, out N2nRegister reg)) return;
            var ackBody = new N2nRegisterAck { Cookie = reg.Cookie, SrcMac = _mac.ToArray(), DstMac = reg.SrcMac, Sock = reg.Sock };
            byte[] datagram = _codec.EncodeRegisterAck(_config.Community, ackBody);
            _ = SendAsync(datagram);
        }

        void OnPacket(ReadOnlySpan<byte> span)
        {
            N2nEthernetChannel? channel = _channel;
            if (channel is null) return;
            if (!_codec.TryDecodePacket(span, _transform, out _, out N2nPacket packet))
            {
                Logger.LogPacketDropped(DriverName, VpnDropReason.DecryptFailed, "PACKET failed to decode (transform mismatch / malformed)");
                return;
            }
            channel.Deliver(packet.Payload);
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

        // ---- keepalive: re-send REGISTER_SUPER so the supernode keeps this edge registered ----

        void StartKeepAlive()
        {
            _timerRunning = true;
            _timer = new System.Threading.Timer(_ => _ = KeepAliveTickAsync(), null, _keepAliveInterval, _keepAliveInterval);
        }

        async Task KeepAliveTickAsync()
        {
            if (!_timerRunning) return;
            await SendKeepAliveRegisterAsync().ConfigureAwait(false);
        }

        Task SendKeepAliveRegisterAsync()
        {
            var body = new N2nRegisterSuper
            {
                Cookie = NextCookie(),
                EdgeMac = _mac.ToArray(),
                Sock = null,
                DevAddr = BuildDevAddr(),
                DevDesc = "tqkvpn",
                Auth = _auth,
                KeyTime = 0,
            };
            byte[] datagram = _codec.EncodeRegisterSuper(_config.Community, body);
            return SendAsync(datagram).AsTask();
        }

        // ---- teardown ----

        /// <inheritdoc/>
        protected override async Task CleanupAttemptResourcesAsync()
        {
            StopAttemptLoop();

            TaskCompletionSource<N2nRegisterSuperAck>? tcs = _registerAckTcs;
            _registerAckTcs = null;
            tcs?.TrySetCanceled();

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
            N2nEthernetChannel? channel = _channel; _channel = null;
            if (channel != null) { try { await channel.DisposeAsync().ConfigureAwait(false); } catch { } }

            IDatagramTransport? transport = _transport;
            _transport = null;
            if (transport != null) { try { await transport.DisposeAsync().ConfigureAwait(false); } catch { } }
        }

        /// <inheritdoc/>
        protected override void StopAttemptLoop()
        {
            _timerRunning = false;
            _timer?.Dispose();
            _timer = null;
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

        // ---- helpers ----

        IN2nTransform BuildTransform(N2nConfig config)
        {
            switch (config.Transform)
            {
                case N2nTransformKind.Aes:
                    if (config.AesKey is null || config.AesKey.Length == 0)
                        throw new ArgumentException("N2nConfig.AesKey is required when Transform is AES.", nameof(config));
                    return new N2nAesTransform(config.AesKey);
                case N2nTransformKind.Null:
                default:
                    return new N2nNullTransform();
            }
        }

        // The configured edge MAC, or a random locally-administered unicast MAC (I/G bit clear, U/L bit set) — what an
        // n2n edge generates when no -m is given.
        MacAddress ResolveMac(N2nConfig config)
        {
            if (config.EdgeMac is not null)
            {
                if (config.EdgeMac.Length != MacSize) throw new ArgumentException("N2nConfig.EdgeMac must be 6 bytes.", nameof(config));
                return MacAddress.FromBytes(config.EdgeMac);
            }
            byte[] bytes = new byte[MacSize];
            NextRandomBytes(bytes);
            bytes[0] = (byte)((bytes[0] & 0xFE) | 0x02);
            return MacAddress.FromBytes(bytes);
        }

        uint NextCookie()
        {
            byte[] b = new byte[4];
            NextRandomBytes(b);
            uint v = ((uint)b[0] << 24) | ((uint)b[1] << 16) | ((uint)b[2] << 8) | b[3];
            return v == 0 ? 1u : v;
        }

        // The edge's static -a address as an n2n dev_addr subnet (net_addr host-order, net_bitlen = prefix). A real n2n
        // edge with -a advertises this in REGISTER_SUPER; the supernode then keeps the same dev_addr for the edge, so the
        // keepalive re-register stays the "known" edge and its auth token matches (advertising 0.0.0.0/0 made the
        // supernode hand out a dynamic address and reject the keepalive as a fresh, mismatched registration).
        N2nIpSubnet BuildDevAddr()
        {
            byte[] b = _config.OverlayAddress.GetAddressBytes();
            uint netAddr = ((uint)b[0] << 24) | ((uint)b[1] << 16) | ((uint)b[2] << 8) | b[3];
            return new N2nIpSubnet(netAddr, (byte)_config.PrefixLength);
        }

        // n2n's net_addr is a host-order uint32 (high byte = first octet); render it dotted-quad for logging.
        static string FormatIpv4(uint netAddr)
            => new IPAddress(new[] { (byte)(netAddr >> 24), (byte)(netAddr >> 16), (byte)(netAddr >> 8), (byte)netAddr }).ToString();
    }
}
