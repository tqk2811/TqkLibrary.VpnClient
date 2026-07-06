using System;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.Logging;
using TqkLibrary.VpnClient.Abstractions.Drivers.Enums;
using TqkLibrary.VpnClient.Abstractions.Drivers.Interfaces;
using TqkLibrary.VpnClient.Abstractions.Drivers.Models;
using TqkLibrary.VpnClient.Drivers.L2tpv3Eth.Config;
using TqkLibrary.VpnClient.Drivers.L2tpv3Eth.Transport;

namespace TqkLibrary.VpnClient.Drivers.L2tpv3Eth
{
    /// <summary>
    /// The L2TPv3 (RFC 3931) Ethernet-pseudowire (RFC 4719) protocol driver, <b>static/unmanaged</b> mode. It is configured
    /// with a static <see cref="L2tpv3EthConfig"/> (the local/remote Session IDs, the shared Cookie, sequencing, this
    /// endpoint's static overlay IP + MAC, MTU); the connect-time <see cref="VpnEndpoint"/> supplies the remote host/port.
    /// L2TPv3 static endpoints set their own overlay address, so the tunnel address / routes / MTU come straight from the
    /// config (<see cref="AddressAssignment.OutOfBand"/>). L2 Ethernet over UDP with the L2TPv3 data header (Session ID +
    /// optional Cookie + optional Default L2-Specific Sublayer) — no control plane, no encryption, no keepalive, no L2TP
    /// control channel; the remote endpoint is a static unicast peer. The sibling of the VXLAN / Geneve drivers.
    /// </summary>
    public sealed class L2tpv3EthDriver : IVpnProtocolDriver
    {
        readonly L2tpv3EthConfig _config;
        readonly L2tpv3EthReconnectOptions? _reconnectOptions;
        readonly IL2tpv3EthTransportFactory? _transportFactory;
        readonly ILoggerFactory? _loggerFactory;

        /// <summary>
        /// Creates the driver. <paramref name="config"/> is the static pseudowire profile; <paramref name="reconnectOptions"/>
        /// tunes (or disables) auto-reconnect; <paramref name="transportFactory"/> overrides the UDP transport (an in-process
        /// loopback drives the driver offline in tests; null ⇒ the production <see cref="L2tpv3EthUdpTransportFactory"/>).
        /// <paramref name="loggerFactory"/> receives diagnostic traces (null = no logging).
        /// </summary>
        public L2tpv3EthDriver(L2tpv3EthConfig config,
            L2tpv3EthReconnectOptions? reconnectOptions = null,
            IL2tpv3EthTransportFactory? transportFactory = null,
            ILoggerFactory? loggerFactory = null)
        {
            _config = config ?? throw new ArgumentNullException(nameof(config));
            _reconnectOptions = reconnectOptions;
            _transportFactory = transportFactory;
            _loggerFactory = loggerFactory;
        }

        /// <inheritdoc/>
        public string Name => L2tpv3EthDriverConstants.DriverName;

        /// <inheritdoc/>
        public VpnDriverCapabilities Capabilities { get; } = new VpnDriverCapabilities
        {
            LinkLayer = VpnLinkLayer.L2Ethernet,                 // Ethernet frames behind an L2TPv3 data header
            UsesPpp = false,
            MultiHostModel = MultiHostModel.None,                // single endpoint, static unicast remote peer
            TransportKinds = VpnTransportKind.Udp,               // L2TPv3-over-UDP (no-admin variant; default dst 1701)
            SecurityKinds = VpnSecurityKind.None,                // L2TPv3 data is a bare header — no encryption
            AuthMethods = VpnAuthMethod.None,                    // static/unmanaged — no control plane, no authentication
            AddressAssignment = AddressAssignment.OutOfBand,     // the endpoint sets its own static overlay address
            // RequiresRawIpSocket / RequiresElevation stay false: plain UDP, no elevation.
        };

        /// <inheritdoc/>
        public async Task<IVpnConnection> ConnectAsync(VpnEndpoint endpoint, VpnCredentials credentials, CancellationToken cancellationToken = default)
        {
            if (endpoint is null) throw new ArgumentNullException(nameof(endpoint));

            IL2tpv3EthTransportFactory factory = _transportFactory ?? new L2tpv3EthUdpTransportFactory();
            var connection = new L2tpv3EthConnection(endpoint.Host, factory, _config,
                reconnectOptions: _reconnectOptions,
                addressFamilyPreference: endpoint.AddressFamilyPreference,
                loggerFactory: _loggerFactory);
            try
            {
                await connection.ConnectAsync(cancellationToken).ConfigureAwait(false);
                var session = new L2tpv3EthVpnSession(connection.PacketChannel, connection.Config);
                return new L2tpv3EthVpnConnection(connection, session);
            }
            catch
            {
                await connection.DisposeAsync().ConfigureAwait(false);
                throw;
            }
        }
    }
}
