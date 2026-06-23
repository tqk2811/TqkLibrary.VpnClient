using System;
using System.Collections.Generic;
using System.Net;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.Logging;
using TqkLibrary.VpnClient.Abstractions.Channels;
using TqkLibrary.VpnClient.Abstractions.Channels.Interfaces;
using TqkLibrary.VpnClient.Abstractions.Diagnostics.Extensions;
using TqkLibrary.VpnClient.Abstractions.Drivers;
using TqkLibrary.VpnClient.Abstractions.Drivers.Models;
using TqkLibrary.VpnClient.Abstractions.Net;
using TqkLibrary.VpnClient.Abstractions.Transport.Interfaces;
using TqkLibrary.VpnClient.Crypto;
using TqkLibrary.VpnClient.Drivers.Core;
using TqkLibrary.VpnClient.Drivers.SoftEther.Enums;
using TqkLibrary.VpnClient.Drivers.SoftEther.Models;
using TqkLibrary.VpnClient.Drivers.SoftEther.Transport;
using TqkLibrary.VpnClient.Ethernet;
using TqkLibrary.VpnClient.Ethernet.Helpers;
using TqkLibrary.VpnClient.Ethernet.Models;
using TqkLibrary.VpnClient.SoftEther;
using TqkLibrary.VpnClient.SoftEther.DataChannel;
using TqkLibrary.VpnClient.SoftEther.DataChannel.Enums;
using TqkLibrary.VpnClient.SoftEther.Models;

namespace TqkLibrary.VpnClient.Drivers.SoftEther
{
    /// <summary>
    /// A complete SoftEther SSL-VPN client over a single TLS byte stream. It runs the control handshake
    /// (<see cref="SoftEtherHandshake"/>: watermark → hello → login → welcome), then switches the same stream into the
    /// data session — "Ethernet over HTTPS". The data session is exposed as an L2 <see cref="SoftEtherEthernetChannel"/>
    /// that is bridged down to a bare L3 <see cref="IPacketChannel"/> through the userspace Ethernet fabric: a
    /// <see cref="DhcpV4Configurator"/> (L2.5) leases an IP from the server's SecureNAT, then an <see cref="ArpResolver"/>
    /// (L2.3) + <see cref="VirtualHost"/> (L2.2) carry IP traffic — the IP stack binds the stable facade, never the
    /// Ethernet channel. A receive loop decodes inbound data blocks and dispatches frames; a periodic keep-alive runs
    /// for the session's lifetime, and (when enabled) a dropped session is re-established behind the same facade by the
    /// shared supervisor (<see cref="ReconnectingVpnConnection{TState}"/>, roadmap F.6), mirroring the OpenConnect /
    /// OpenVPN / WireGuard drivers. Not a server — the responder role lives only in tests.
    /// </summary>
    public sealed class SoftEtherConnection : ReconnectingVpnConnection<SoftEtherConnectionState>, IDisposable, IAsyncDisposable
    {
        static readonly TimeSpan KeepAliveTick = TimeSpan.FromSeconds(5);
        static readonly IPAddress LinkLocalPrefix = IPAddress.Parse("fe80::");   // the fe80::/64 IPv6 link-local prefix (RFC 4291 §2.5.6)
        const string DriverNameConst = "softether";
        const int MaxParallelConnections = 32;   // SoftEther caps a session at 1–32 parallel TCP connections

        readonly string _host;
        readonly int _port;
        readonly SoftEtherLoginRequest _login;
        readonly ISoftEtherTransportFactory _transportFactory;
        readonly AddressFamilyPreference _addressFamilyPreference;
        readonly SoftEtherWatermark? _watermark;
        readonly DhcpV4ConfiguratorOptions? _dhcpOptions;
        readonly Ipv6AddressConfiguratorOptions? _ipv6Options;
        readonly int _mtu;
        readonly bool _multiHost;
        readonly bool _enableIpv6;             // opt-in: also run SLAAC/DHCPv6 + NDISC v6 on the SecureNAT bridge (default IPv4-only)

        readonly MacAddress _mac;              // a stable locally-administered MAC kept across reconnects
        readonly Random _keepAliveRandom = new();   // pads idle keep-alive blocks (non-crypto; just avoids a fixed length)

        IPAddress? _assignedAddress;
        IPAddress? _lastAssignedAddress;
        TunnelConfig _config = new();

        SoftEtherMultiConnectionMux? _mux;     // the 1–32 parallel TCP/TLS connections aggregated into one data path
        SoftEtherEthernetChannel? _channel;
        VirtualHost? _host2;                   // 1-host bridge: the L2↔L3 bridge whose IPacketChannel feeds the facade
        ArpResolver? _arp;                     // 1-host bridge: IPv4 neighbour resolver sharing the data channel
        NdiscResolver? _ndisc;                 // 1-host bridge: IPv6 neighbour resolver (when enableIpv6) sharing the data channel
        DhcpV4Configurator? _dhcp;             // 1-host bridge: the DHCPv4 client (drains inbound DHCP during/after the lease)
        Ipv6AddressConfigurator? _ipv6Config;  // 1-host bridge: the SLAAC/DHCPv6 client (when enableIpv6)
        MultiHostSession? _multiHostSession;   // multi-host: the broadcast domain (uplink-as-port + N stations)
        System.Threading.Timer? _keepAliveTimer;
        int _connectionCount = 1;              // how many TCP/TLS connections the last attempt actually opened

        /// <summary>
        /// Creates a connection. <paramref name="login"/> carries the hub/user/credential + session params;
        /// <paramref name="transportFactory"/> opens the TLS byte stream (an in-process factory drives it offline);
        /// <paramref name="watermark"/> overrides the watermark POST blob (e.g. the genuine server blob);
        /// <paramref name="dhcpOptions"/> tunes the DHCPv4 exchange. When <paramref name="multiHost"/> is <c>true</c> the
        /// data session is exposed as a whole L2 broadcast domain (the data channel is attached to an
        /// <see cref="EthernetAdapter"/> as an uplink port and each station leases its own IP over the shared switch, the
        /// server's SecureNAT serving them), reachable through <see cref="MultiHostSession"/>; the default (<c>false</c>)
        /// keeps the single-host bridge. When <paramref name="enableIpv6"/> is <c>true</c> the bridge additionally runs IPv6
        /// autoconfiguration (SLAAC from a Router Advertisement, or stateful DHCPv6 — L2.6 <see cref="Ipv6AddressConfigurator"/>)
        /// plus NDISC v6 neighbour resolution (<see cref="NdiscResolver"/>) over the same SecureNAT segment, pushing
        /// <see cref="TunnelConfig.AssignedAddressV6"/>/<see cref="TunnelConfig.PrefixLengthV6"/> when the server hands out an
        /// IPv6 address; it is best-effort, so an IPv4-only SecureNAT still connects (the default <c>false</c> keeps the wire
        /// IPv4-only). <paramref name="ipv6Options"/> tunes the SLAAC/DHCPv6 exchange. <paramref name="loggerFactory"/>
        /// receives diagnostic traces (handshake/DHCP/keepalive/reconnect/drop); null logs to a no-op logger.
        /// </summary>
        public SoftEtherConnection(string host, int port, SoftEtherLoginRequest login,
            ISoftEtherTransportFactory transportFactory,
            SoftEtherReconnectOptions? reconnectOptions = null,
            AddressFamilyPreference addressFamilyPreference = AddressFamilyPreference.Auto,
            SoftEtherWatermark? watermark = null,
            DhcpV4ConfiguratorOptions? dhcpOptions = null,
            int mtu = 1500,
            bool multiHost = false,
            bool enableIpv6 = false,
            Ipv6AddressConfiguratorOptions? ipv6Options = null,
            ILoggerFactory? loggerFactory = null)
            : base(DriverNameConst, reconnectOptions ?? new SoftEtherReconnectOptions(), clock: null, loggerFactory: loggerFactory)
        {
            _host = host ?? throw new ArgumentNullException(nameof(host));
            _port = port;
            _login = login ?? throw new ArgumentNullException(nameof(login));
            _transportFactory = transportFactory ?? throw new ArgumentNullException(nameof(transportFactory));
            _addressFamilyPreference = addressFamilyPreference;
            _watermark = watermark;
            _dhcpOptions = dhcpOptions;
            _ipv6Options = ipv6Options;
            if (mtu < 1) throw new ArgumentOutOfRangeException(nameof(mtu));
            _mtu = mtu;
            _multiHost = multiHost;
            _enableIpv6 = enableIpv6;
            _mac = GenerateLocalMac();
        }

        // A locally-administered unicast MAC for the virtual L2 endpoint: clear the I/G (multicast) bit and set the
        // U/L (locally-administered) bit of octet 0, the rest random — what a software NIC does.
        MacAddress GenerateLocalMac()
        {
            byte[] bytes = new byte[MacAddress.Size];
            NextRandomBytes(bytes);
            bytes[0] = (byte)((bytes[0] & 0xFE) | 0x02);
            return MacAddress.FromBytes(bytes);
        }

        /// <summary>The tunnel configuration leased over DHCP (address, prefix, DNS, routes, MTU).</summary>
        public TunnelConfig Config => _config;

        /// <summary>The tunnel IP leased over DHCP (valid after connect).</summary>
        public IPAddress AssignedAddress => _assignedAddress ?? IPAddress.Any;

        /// <summary>
        /// The tunnel IPv6 address autoconfigured over the SecureNAT bridge (SLAAC or DHCPv6), or <c>null</c> when IPv6 is
        /// disabled or the server is IPv4-only. Mirrors <see cref="TunnelConfig.AssignedAddressV6"/>.
        /// </summary>
        public IPAddress? AssignedAddressV6 => _config.AssignedAddressV6;

        /// <summary><c>true</c> when this connection also runs IPv6 autoconfiguration (SLAAC/DHCPv6) + NDISC v6 on the bridge.</summary>
        public bool IsIpv6Enabled => _enableIpv6;

        /// <summary>This endpoint's virtual MAC address on the SoftEther L2 segment (the first/primary station in multi-host mode).</summary>
        public MacAddress LinkAddress => _mac;

        /// <summary>
        /// The number of parallel TCP/TLS connections the current session is using (the primary login connection plus
        /// any <c>additional_connect</c> ones), 1–32. Valid after connect; the data session is spread across them.
        /// </summary>
        public int ConnectionCount => _connectionCount;

        /// <summary><c>true</c> when this connection exposes the whole L2 broadcast domain (uplink-as-port) via <see cref="MultiHostSession"/>.</summary>
        public bool IsMultiHost => _multiHost;

        /// <summary>
        /// In multi-host mode, the broadcast domain riding the SoftEther data session (the data channel attached as an
        /// uplink port, plus N <see cref="EthernetHostSession"/> stations leasing their own IP over the shared switch).
        /// <c>null</c> in single-host mode or before the first connect completes.
        /// </summary>
        public MultiHostSession? MultiHostSession => _multiHostSession;

        /// <summary>Raised after a successful auto-reconnect, carrying the new address and whether it changed.</summary>
        public event Action<SoftEtherReconnectInfo>? Reconnected;

        /// <inheritdoc/>
        protected override SoftEtherConnectionState DisconnectedState => SoftEtherConnectionState.Disconnected;
        /// <inheritdoc/>
        protected override SoftEtherConnectionState ConnectingState => SoftEtherConnectionState.Connecting;
        /// <inheritdoc/>
        protected override SoftEtherConnectionState ConnectedState => SoftEtherConnectionState.Connected;
        /// <inheritdoc/>
        protected override SoftEtherConnectionState ReconnectingState => SoftEtherConnectionState.Reconnecting;

        /// <summary>Runs the full handshake + DHCP lease and returns once the tunnel is carrying traffic.</summary>
        public async Task ConnectAsync(CancellationToken cancellationToken = default)
        {
            await ConnectCoreAsync(cancellationToken).ConfigureAwait(false);
            _lastAssignedAddress = _assignedAddress;
        }

        // ---- one full tunnel attempt (reused by the first connect and every reconnect) ----

        /// <inheritdoc/>
        protected override async Task EstablishAsync(CancellationToken cancellationToken)
        {
            await CleanupAttemptResourcesAsync().ConfigureAwait(false);

            // --- TLS + control handshake (watermark → hello → login → welcome) over the primary byte stream ---
            IByteStreamTransport primary = await _transportFactory
                .ConnectAsync(_host, _port, _addressFamilyPreference, cancellationToken).ConfigureAwait(false);
            await primary.ConnectAsync(cancellationToken).ConfigureAwait(false);

            Logger.LogHandshake(DriverName, "control handshake (watermark -> hello -> login -> welcome)");
            var handshake = new SoftEtherHandshake(new SoftEtherAuth(new Sha0()), new Random());
            (SoftEtherWelcomeInfo welcome, byte[] primaryLeftover) = await handshake
                .RunAsync(primary, _host, _login, _watermark, cancellationToken).ConfigureAwait(false);
            Logger.LogHandshake(DriverName, "login accepted; switching stream into the Ethernet-over-HTTPS data session");

            // --- the server can coalesce the welcome response and the first data block(s) into one TLS record, so re-inject
            //     any bytes the handshake reader over-read into the data session (dropping them would desync the block
            //     reader and surface as a phantom "server closed"). ---
            IByteStreamTransport primaryData = primaryLeftover.Length == 0
                ? primary
                : new PrefixedByteStreamTransport(primary, primaryLeftover);

            // --- open the additional connections (up to what we requested AND the server granted), reattaching each by
            //     session key, then aggregate them into one logical data path (1 session owning N sockets) ---
            var connections = new List<IByteStreamTransport> { primaryData };
            int desired = ResolveConnectionCount(welcome.MaxConnection);
            await OpenAdditionalConnectionsAsync(handshake, welcome, desired, connections, cancellationToken).ConfigureAwait(false);

            // --- data-plane encryption: the genuine server keeps the data session inside SSL when use_encrypt is on and
            //     fast-RC4 is off (UseSSLDataEncryption — Cedar Protocol.c), which is exactly how this driver carries the
            //     data session (read/write through the same TLS byte stream). With use_encrypt off SoftEther reverts the
            //     data plane to the RAW TCP socket (Send/Recv secure=false), which this TLS transport cannot express; the
            //     driver therefore requires use_encrypt=on. fast-RC4 (raw TCP + RC4) is never requested, so no RC4 layer. ---

            SoftEtherConnectionDirection[] directions =
                SoftEtherConnectionDirectionPlanner.Plan(connections.Count, welcome.HalfConnection);
            var mux = new SoftEtherMultiConnectionMux(connections, directions, OnLinkLost);
            _mux = mux;
            _connectionCount = connections.Count;
            if (connections.Count > 1)
                Logger.LogHandshake(DriverName, $"data session spread across {connections.Count} TCP connections" +
                    (welcome.HalfConnection ? " (half-duplex)" : ""));

            // --- the stream(s) are now the data session: expose it as one L2 channel; the mux delivers inbound frames ---
            var channel = new SoftEtherEthernetChannel(_mac.ToArray(), mux.SendBlockAsync, _mtu, _login.Session.UseCompress);
            _channel = channel;
            mux.InboundFrame += channel.Deliver;   // keep-alive frames are dropped inside Deliver
            MarkRunning(); // a peer-close/fault from a receive loop below must now arm reconnect (before MarkConnected)
            mux.StartReceiveLoops();

            if (_multiHost)
                await EstablishMultiHostAsync(channel, cancellationToken).ConfigureAwait(false);
            else
                await EstablishSingleHostAsync(channel, cancellationToken).ConfigureAwait(false);

            StartKeepAlive();
            Logger.LogHandshakeCompleted(DriverName);
            MarkConnected();
        }

        // The session uses at most what we asked for (login max_connection) and the server granted (welcome
        // max_connection), clamped to the protocol's 1–32 range.
        int ResolveConnectionCount(uint serverGranted)
        {
            uint requested = _login.Session.MaxConnection == 0 ? 1 : _login.Session.MaxConnection;
            uint granted = serverGranted == 0 ? 1 : serverGranted;
            uint count = Math.Min(requested, granted);
            if (count < 1) count = 1;
            if (count > MaxParallelConnections) count = MaxParallelConnections;
            return (int)count;
        }

        // Opens (desired-1) extra TCP/TLS connections and reattaches each to the session via additional_connect. A failed
        // extra connection is non-fatal: the session still works (best-effort throughput pooling) on the connections that
        // did attach, so we log and continue with however many we have.
        async Task OpenAdditionalConnectionsAsync(SoftEtherHandshake handshake, SoftEtherWelcomeInfo welcome,
            int desired, List<IByteStreamTransport> connections, CancellationToken cancellationToken)
        {
            for (int i = 1; i < desired; i++)
            {
                IByteStreamTransport extra;
                byte[] leftover;
                try
                {
                    extra = await _transportFactory
                        .ConnectAsync(_host, _port, _addressFamilyPreference, cancellationToken).ConfigureAwait(false);
                    await extra.ConnectAsync(cancellationToken).ConfigureAwait(false);
                    leftover = await handshake.RunAdditionalConnectAsync(extra, _host, welcome.SessionKey, _watermark, cancellationToken)
                        .ConfigureAwait(false);
                }
                catch (Exception ex)
                {
                    cancellationToken.ThrowIfCancellationRequested();
                    Logger.LogHandshake(DriverName, $"additional_connect #{i} failed ({ex.GetType().Name}); continuing with {connections.Count}");
                    break;   // stop adding more; the session runs on what attached
                }
                // Re-inject any data-session bytes the server coalesced into the additional_connect ack (same desync fix).
                connections.Add(leftover.Length == 0 ? extra : new PrefixedByteStreamTransport(extra, leftover));
                Logger.LogHandshake(DriverName, $"additional_connect #{i} attached to the session");
            }
        }

        // ---- single-host bridge (default): one DHCP lease, one VirtualHost bridged down to the L3 facade ----

        async Task EstablishSingleHostAsync(SoftEtherEthernetChannel channel, CancellationToken cancellationToken)
        {
            // --- DHCP lease (SecureNAT) over the L2 segment: DHCP shares the channel and drains inbound DHCP replies ---
            Logger.LogHandshake(DriverName, "requesting DHCPv4 lease from SecureNAT (DISCOVER/OFFER/REQUEST/ACK)");
            var dhcp = new DhcpV4Configurator(_mac, channel, _dhcpOptions);
            _dhcp = dhcp;
            channel.InboundFrame += dhcp.HandleInboundFrame;   // feed inbound frames to DHCP for the OFFER/ACK
            TunnelConfig config;
            try
            {
                config = await dhcp.ConfigureAsync(cancellationToken).ConfigureAwait(false);
            }
            finally
            {
                channel.InboundFrame -= dhcp.HandleInboundFrame;
            }

            if (config.AssignedAddress is null || config.AssignedAddress.AddressFamily != System.Net.Sockets.AddressFamily.InterNetwork)
                throw new VpnConnectionException("SoftEther DHCP did not lease an IPv4 address (SecureNAT serves IPv4 via DHCP; ARP is IPv4-only).");

            // --- bring up the L2↔L3 bridge on the leased address; the IP stack binds the facade, never the channel ---
            var arp = new ArpResolver(_mac, config.AssignedAddress, channel);
            _arp = arp;

            // --- IPv6 (opt-in): run NDISC v6 + SLAAC/DHCPv6 on the same segment, best-effort. An IPv4-only SecureNAT
            //     yields no v6 address, which is fine — the tunnel still comes up on IPv4. ---
            INeighborResolver resolver = arp;
            Action<ReadOnlyMemory<byte>>? ipSeam = null;
            if (_enableIpv6)
            {
                IPAddress linkLocal = LinkLocalAddress(_mac);
                var ndisc = new NdiscResolver(_mac, linkLocal, channel);
                _ndisc = ndisc;
                var ipv6Config = new Ipv6AddressConfigurator(_mac, linkLocal, channel, ndisc, _ipv6Options);
                _ipv6Config = ipv6Config;
                resolver = new DualStackNeighborResolver(arp, ndisc, ownsInnerResolvers: false);
                ipSeam = p => { ndisc.HandleInboundFrame(p); ipv6Config.HandleInboundFrame(p); };   // NDISC + DHCPv6 ride inside ordinary IPv6
                await ConfigureIpv6BestEffortAsync(channel, config, ndisc, ipv6Config, cancellationToken).ConfigureAwait(false);
            }

            var virtualHost = new VirtualHost(_mac, channel, resolver);
            virtualHost.InboundNonIpFrame += arp.HandleInboundFrame;     // ARP replies/requests arrive on the non-IP seam
            virtualHost.InboundIpPacket += dhcp.HandleInboundFrame;      // a renewal DHCP reply rides ordinary IPv4
            if (ipSeam != null)
                virtualHost.InboundIpPacket += ipSeam;                  // NDISC/DHCPv6 ride inside ordinary IPv6
            _host2 = virtualHost;

            config.Mtu = virtualHost.Mtu;                               // link − 14: the bound stack clamps MSS for the Ethernet header
            _config = config;
            _assignedAddress = config.AssignedAddress;
            Facade.SetInner(virtualHost);
            string v6 = config.AssignedAddressV6 != null ? $" + IPv6 {config.AssignedAddressV6}" : "";
            Logger.LogHandshake(DriverName, $"DHCP lease {config.AssignedAddress}{v6}; L2<->L3 bridge bound");
        }

        // Forms the host's IPv6 link-local address (fe80::/64 + Modified EUI-64 of the MAC, RFC 4291 §2.5.1) — the source
        // NDISC/SLAAC/DHCPv6 send from before any global address is configured. Reuses the SLAAC interface-identifier codec.
        static IPAddress LinkLocalAddress(MacAddress mac)
            => SlaacAddress.Combine(LinkLocalPrefix, 64, SlaacAddress.ModifiedEui64(mac));

        // Runs SLAAC/DHCPv6 and merges any IPv6 address/DNS/route into the v4 config. Best-effort: a server that does not
        // advertise IPv6 (no RA, no DHCPv6) leaves the config IPv4-only rather than failing the whole tunnel.
        async Task ConfigureIpv6BestEffortAsync(SoftEtherEthernetChannel channel, TunnelConfig config, NdiscResolver ndisc, Ipv6AddressConfigurator ipv6Config, CancellationToken cancellationToken)
        {
            Logger.LogHandshake(DriverName, "requesting IPv6 autoconfiguration from SecureNAT (RS/RA -> SLAAC or DHCPv6)");
            // During the exchange the VirtualHost is not yet bound, so feed inbound frames (RA + DHCPv6 reply) straight from
            // the data channel; once the bridge is up they ride VirtualHost.InboundIpPacket instead.
            channel.InboundFrame += ndisc.HandleInboundFrame;
            channel.InboundFrame += ipv6Config.HandleInboundFrame;
            try
            {
                TunnelConfig v6 = await ipv6Config.ConfigureAsync(cancellationToken).ConfigureAwait(false);
                config.AssignedAddressV6 = v6.AssignedAddressV6;
                config.PrefixLengthV6 = v6.PrefixLengthV6;
                foreach (IPAddress dns in v6.DnsServers)
                    config.DnsServers.Add(dns);
                foreach (string route in v6.Routes)
                    config.Routes.Add(route);
                Logger.LogHandshake(DriverName, $"IPv6 autoconfiguration succeeded: {v6.AssignedAddressV6}/{v6.PrefixLengthV6}");
            }
            catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
            {
                throw;
            }
            catch (Exception ex)
            {
                // No RA / no DHCPv6 lease (IPv4-only SecureNAT): keep IPv4 working, drop only the IPv6 leg.
                Logger.LogHandshake(DriverName, $"IPv6 autoconfiguration skipped ({ex.GetType().Name}: {ex.Message}); continuing IPv4-only");
            }
            finally
            {
                channel.InboundFrame -= ndisc.HandleInboundFrame;
                channel.InboundFrame -= ipv6Config.HandleInboundFrame;
            }
        }

        // ---- multi-host broadcast domain: attach the data channel as an uplink port, then DHCP the first station ----

        async Task EstablishMultiHostAsync(SoftEtherEthernetChannel channel, CancellationToken cancellationToken)
        {
            // The data channel is one port (an uplink) of an in-memory switch; every station rides its own port. The
            // SecureNAT server answers ARP/DHCP per station, so flood/forward bridges the whole broadcast domain.
            var adapter = new EthernetAdapter(new EthernetAdapterOptions { SwitchMtu = _mtu });
            adapter.ConnectUplink(channel);                              // detached when the adapter (switch) is disposed
            var session = new MultiHostSession(adapter, ownsAdapter: true);
            _multiHostSession = session;
            Logger.LogHandshake(DriverName, "attached SoftEther data channel as an uplink port on the L2 broadcast domain");

            // The first/primary station leases its IP and feeds the connection's stable L3 facade (keeping the single-host
            // API: PacketChannel/Config/AssignedAddress). Additional stations are added via OpenSessionAsync.
            EthernetHostSession primary = await AddStationAsync(_mac, cancellationToken).ConfigureAwait(false);
            _config = primary.Config;
            _assignedAddress = primary.Config.AssignedAddress;
            Facade.SetInner(primary.PacketChannel);
            Logger.LogHandshake(DriverName, $"primary station DHCP lease {primary.Config.AssignedAddress}; broadcast domain bound");
        }

        /// <summary>
        /// Adds a station to the multi-host broadcast domain with MAC <paramref name="mac"/>: it leases its own IPv4 over
        /// the shared switch (the SecureNAT server serving it) and is surfaced as an <see cref="EthernetHostSession"/>. When
        /// the connection has IPv6 enabled the station also runs SLAAC/DHCPv6 + NDISC v6 on the shared switch (best-effort).
        /// </summary>
        /// <exception cref="InvalidOperationException">This connection is not in multi-host mode.</exception>
        public async ValueTask<EthernetHostSession> AddStationAsync(MacAddress mac, CancellationToken cancellationToken = default)
        {
            MultiHostSession? session = _multiHostSession;
            if (session is null)
                throw new InvalidOperationException("This SoftEther connection is single-host; construct it with multiHost: true to add stations.");

            ArpResolver? arpRef = null;
            EthernetHostSession station = await session.AddStationAsync(mac, port =>
            {
                // Before DHCP the station has no IP, so ARP starts on 0.0.0.0; once the lease lands we set the real
                // address (SetLocalAddress) so the station answers ARP for itself and sends ARP with the right sender-IP.
                var arp = new ArpResolver(mac, IPAddress.Any, port);
                arpRef = arp;
                var dhcp = new DhcpV4Configurator(mac, port, _dhcpOptions);

                if (!_enableIpv6)
                    return new EthernetHostSpec(arp)
                    {
                        Configurator = dhcp,
                        NonIpFrameHandler = arp.HandleInboundFrame,      // ARP rides the non-IP seam
                        IpPacketHandler = dhcp.HandleInboundFrame,       // DHCP rides inside ordinary IPv4
                    };

                // Dual-stack station: ARP for v4 + NDISC for v6, DHCPv4 (required) + SLAAC/DHCPv6 (best-effort).
                IPAddress linkLocal = LinkLocalAddress(mac);
                var ndisc = new NdiscResolver(mac, linkLocal, port);
                var ipv6Config = new Ipv6AddressConfigurator(mac, linkLocal, port, ndisc, _ipv6Options);
                var dualResolver = new DualStackNeighborResolver(arp, ndisc);                        // owns ARP + NDISC
                var dualConfig = new DualStackAddressConfigurator(dhcp, new BestEffortIpv6Configurator(ipv6Config));
                return new EthernetHostSpec(dualResolver)
                {
                    Configurator = dualConfig,
                    NonIpFrameHandler = arp.HandleInboundFrame,          // ARP rides the non-IP seam
                    // NDISC (incl. RA), DHCPv4 and DHCPv6 all ride inside ordinary IP.
                    IpPacketHandler = p =>
                    {
                        ndisc.HandleInboundFrame(p);
                        dhcp.HandleInboundFrame(p);
                        ipv6Config.HandleInboundFrame(p);
                    },
                };
            }, cancellationToken).ConfigureAwait(false);

            if (station.Config.AssignedAddress is null || station.Config.AssignedAddress.AddressFamily != System.Net.Sockets.AddressFamily.InterNetwork)
            {
                await session.RemoveStationAsync(mac).ConfigureAwait(false);
                throw new VpnConnectionException("SoftEther DHCP did not lease an IPv4 address for the station (SecureNAT serves IPv4 via DHCP; ARP is IPv4-only).");
            }
            arpRef?.SetLocalAddress(station.Config.AssignedAddress);     // ARP now answers for the leased address
            return station;
        }

        // Wraps an Ipv6AddressConfigurator so a server that advertises no IPv6 (no RA / no DHCPv6 lease) yields an empty
        // IPv6 config instead of throwing — letting DualStackAddressConfigurator keep the IPv4 leg of a station on an
        // IPv4-only SecureNAT. Cancellation still propagates.
        sealed class BestEffortIpv6Configurator : IAddressConfigurator, IAsyncDisposable
        {
            readonly Ipv6AddressConfigurator _inner;
            public BestEffortIpv6Configurator(Ipv6AddressConfigurator inner) => _inner = inner;

            public async ValueTask<TunnelConfig> ConfigureAsync(CancellationToken cancellationToken = default)
            {
                try { return await _inner.ConfigureAsync(cancellationToken).ConfigureAwait(false); }
                catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested) { throw; }
                catch { return new TunnelConfig(); }   // IPv4-only SecureNAT: no v6 address, drop only the IPv6 leg
            }

            public ValueTask DisposeAsync() => _inner.DisposeAsync();
        }

        // ---- send/receive of data blocks is owned by the multi-connection mux (round-robin across N sockets,
        //      one decode loop per receive-capable socket). The channel writes/receives through it. ----

        // ---- keep-alive: send the SoftEther idle keep-alive frame periodically so the session stays open ----

        void StartKeepAlive()
            => _keepAliveTimer = new System.Threading.Timer(_ => _ = KeepAliveTickAsync(), null, KeepAliveTick, KeepAliveTick);

        async Task KeepAliveTickAsync()
        {
            if (!IsRunning) return;
            SoftEtherMultiConnectionMux? mux = _mux;
            if (mux is null) return;
            try
            {
                // The genuine client sends a keep-alive as a distinct keep-alive block (count = KEEP_ALIVE_MAGIC), not a
                // framed payload, so the server's switch never treats it as an Ethernet frame. Pad it with a little random.
                byte[] block = SoftEtherDataFrameCodec.EncodeKeepAlive(_keepAliveRandom.Next(1, 64), _keepAliveRandom);
                await mux.SendBlockAsync(block).ConfigureAwait(false);
                Logger.LogKeepalive(DriverName, "sent SoftEther idle keep-alive block");
            }
            catch { /* a missed keep-alive is harmless; a receive loop trips link-loss if the peer goes away */ }
        }

        // ---- link-loss handling + auto-reconnect supervisor live in ReconnectingVpnConnection (roadmap F.6). ----
        // A receive loop (peer-close / fault) inside the mux calls the inherited OnLinkLost, which arms the shared
        // ReconnectLoopAsync.

        /// <inheritdoc/>
        protected override void OnReconnected()
        {
            IPAddress newAddress = _assignedAddress ?? IPAddress.Any;
            bool changed = _lastAssignedAddress != null && !newAddress.Equals(_lastAssignedAddress);
            _lastAssignedAddress = newAddress;
            Reconnected?.Invoke(new SoftEtherReconnectInfo(newAddress, changed));
        }

        // ---- teardown ----

        /// <inheritdoc/>
        protected override async Task CleanupAttemptResourcesAsync()
        {
            StopAttemptLoop();

            // L2 fabric: disposing the host detaches + disposes the channel; the resolver/DHCP release any pending work.
            VirtualHost? host2 = _host2;
            _host2 = null;
            if (host2 != null) { try { await host2.DisposeAsync().ConfigureAwait(false); } catch { } }

            ArpResolver? arp = _arp;
            _arp = null;
            if (arp != null) { try { await arp.DisposeAsync().ConfigureAwait(false); } catch { } }

            NdiscResolver? ndisc = _ndisc;
            _ndisc = null;
            if (ndisc != null) { try { await ndisc.DisposeAsync().ConfigureAwait(false); } catch { } }

            DhcpV4Configurator? dhcp = _dhcp;
            _dhcp = null;
            if (dhcp != null) { try { await dhcp.DisposeAsync().ConfigureAwait(false); } catch { } }

            Ipv6AddressConfigurator? ipv6Config = _ipv6Config;
            _ipv6Config = null;
            if (ipv6Config != null) { try { await ipv6Config.DisposeAsync().ConfigureAwait(false); } catch { } }

            // multi-host fabric: disposing the session disposes the owned adapter (switch + every station + the uplink
            // port). The uplink port never disposes our data channel, so we dispose it ourselves below.
            MultiHostSession? multiHost = _multiHostSession;
            _multiHostSession = null;
            if (multiHost != null) { try { await multiHost.DisposeAsync().ConfigureAwait(false); } catch { } }

            SoftEtherEthernetChannel? channel = _channel;
            _channel = null;
            if (channel != null && host2 is null) { try { await channel.DisposeAsync().ConfigureAwait(false); } catch { } }

            // The mux owns every TCP/TLS connection + its receive loops; disposing it cancels the loops and closes all sockets.
            SoftEtherMultiConnectionMux? mux = _mux;
            _mux = null;
            if (mux != null) { try { await mux.DisposeAsync().ConfigureAwait(false); } catch { } }
            _connectionCount = 1;
        }

        /// <inheritdoc/>
        protected override void StopAttemptLoop()
        {
            _keepAliveTimer?.Dispose();
            _keepAliveTimer = null;
        }

        // ---- dispose ----

        /// <inheritdoc/>
        public async ValueTask DisposeAsync()
        {
            try { await DisconnectAsync().ConfigureAwait(false); } catch { }
            await DisposeCoreAsync().ConfigureAwait(false);
        }

        /// <inheritdoc/>
        public void Dispose() => DisposeAsync().AsTask().GetAwaiter().GetResult();
    }
}
