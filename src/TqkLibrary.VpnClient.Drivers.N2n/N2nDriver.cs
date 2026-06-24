using Microsoft.Extensions.Logging;
using TqkLibrary.VpnClient.Abstractions.Drivers.Enums;
using TqkLibrary.VpnClient.Abstractions.Drivers.Interfaces;
using TqkLibrary.VpnClient.Abstractions.Drivers.Models;
using TqkLibrary.VpnClient.Drivers.N2n.Config;
using TqkLibrary.VpnClient.Drivers.N2n.Transport;

namespace TqkLibrary.VpnClient.Drivers.N2n
{
    /// <summary>
    /// The n2n v3 protocol driver. It is configured with a static <see cref="N2nConfig"/> (the community, this edge's
    /// static overlay IP + MAC, the payload transform); the connect-time <see cref="VpnEndpoint"/> supplies the
    /// supernode host/port. n2n edges set their own overlay address (<c>-a</c>), so the tunnel address / routes / MTU
    /// come straight from the config (<see cref="AddressAssignment.OutOfBand"/>). L2 Ethernet mesh over UDP via a
    /// supernode relay (P2P hole-punching bypassed — the relay is enough point-to-point).
    /// </summary>
    public sealed class N2nDriver : IVpnProtocolDriver
    {
        readonly N2nConfig _config;
        readonly N2nReconnectOptions? _reconnectOptions;
        readonly IN2nTransportFactory? _transportFactory;
        readonly ILoggerFactory? _loggerFactory;

        /// <summary>
        /// Creates the driver. <paramref name="config"/> is the static edge profile; <paramref name="reconnectOptions"/>
        /// tunes (or disables) auto-reconnect; <paramref name="transportFactory"/> overrides the UDP transport (an
        /// in-process loopback drives the driver offline in tests). <paramref name="loggerFactory"/> receives diagnostic
        /// traces (null = no logging).
        /// </summary>
        public N2nDriver(N2nConfig config,
            N2nReconnectOptions? reconnectOptions = null,
            IN2nTransportFactory? transportFactory = null,
            ILoggerFactory? loggerFactory = null)
        {
            _config = config ?? throw new ArgumentNullException(nameof(config));
            _reconnectOptions = reconnectOptions;
            _transportFactory = transportFactory;
            _loggerFactory = loggerFactory;
        }

        /// <inheritdoc/>
        public string Name => N2nDriverConstants.DriverName;

        /// <inheritdoc/>
        public VpnDriverCapabilities Capabilities { get; } = new VpnDriverCapabilities
        {
            LinkLayer = VpnLinkLayer.L2Ethernet,                 // Ethernet frames as PACKET messages
            UsesPpp = false,
            MultiHostModel = MultiHostModel.None,                // single edge, supernode-relayed point-to-point
            TransportKinds = VpnTransportKind.Udp,               // n2n is UDP-only
            SecurityKinds = VpnSecurityKind.None,                // optional AES-CBC transform (no standard kind matches)
            AuthMethods = VpnAuthMethod.PreSharedKey,            // the shared community name (+ optional password)
            AddressAssignment = AddressAssignment.OutOfBand,     // the edge sets its own static overlay address
        };

        /// <inheritdoc/>
        public async Task<IVpnConnection> ConnectAsync(VpnEndpoint endpoint, VpnCredentials credentials, CancellationToken cancellationToken = default)
        {
            if (endpoint is null) throw new ArgumentNullException(nameof(endpoint));

            IN2nTransportFactory factory = _transportFactory ?? new N2nSocketTransportFactory();
            int port = endpoint.Port > 0 ? endpoint.Port : N2nDriverConstants.DefaultSupernodePort;
            var connection = new N2nConnection(endpoint.Host, port, _config, factory,
                reconnectOptions: _reconnectOptions,
                addressFamilyPreference: endpoint.AddressFamilyPreference,
                loggerFactory: _loggerFactory);
            try
            {
                await connection.ConnectAsync(cancellationToken).ConfigureAwait(false);
                var session = new N2nVpnSession(connection.PacketChannel, connection.Config);
                return new N2nVpnConnection(connection, session);
            }
            catch
            {
                await connection.DisposeAsync().ConfigureAwait(false);
                throw;
            }
        }
    }
}
