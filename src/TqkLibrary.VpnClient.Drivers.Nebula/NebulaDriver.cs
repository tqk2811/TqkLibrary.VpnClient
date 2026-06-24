using Microsoft.Extensions.Logging;
using TqkLibrary.VpnClient.Abstractions.Drivers.Enums;
using TqkLibrary.VpnClient.Abstractions.Drivers.Interfaces;
using TqkLibrary.VpnClient.Abstractions.Drivers.Models;
using TqkLibrary.VpnClient.Drivers.Nebula.Config;
using TqkLibrary.VpnClient.Drivers.Nebula.Transport;

namespace TqkLibrary.VpnClient.Drivers.Nebula
{
    /// <summary>
    /// The Nebula protocol driver. It is configured with a static <see cref="NebulaConfig"/> (the network CA, this
    /// host's certificate + X25519 key, the peer's static endpoint, the overlay address and MTU); the connect-time
    /// <see cref="VpnEndpoint"/> supplies the peer host/port when the config leaves it unset. Nebula bakes the overlay
    /// address into the host certificate, so the tunnel address/DNS/routes come straight from the config
    /// (<see cref="AddressAssignment.OutOfBand"/>). Point-to-point with a static endpoint (lighthouse discovery bypassed).
    /// </summary>
    public sealed class NebulaDriver : IVpnProtocolDriver
    {
        readonly NebulaConfig _config;
        readonly NebulaReconnectOptions? _reconnectOptions;
        readonly INebulaTransportFactory? _transportFactory;
        readonly ILoggerFactory? _loggerFactory;

        /// <summary>
        /// Creates the driver. <paramref name="config"/> is the static profile; <paramref name="reconnectOptions"/>
        /// tunes (or disables) auto-reconnect; <paramref name="transportFactory"/> overrides the UDP transport (an
        /// in-process loopback drives the driver offline in tests). <paramref name="loggerFactory"/> receives diagnostic
        /// traces (null = no logging).
        /// </summary>
        public NebulaDriver(NebulaConfig config,
            NebulaReconnectOptions? reconnectOptions = null,
            INebulaTransportFactory? transportFactory = null,
            ILoggerFactory? loggerFactory = null)
        {
            _config = config ?? throw new ArgumentNullException(nameof(config));
            _reconnectOptions = reconnectOptions;
            _transportFactory = transportFactory;
            _loggerFactory = loggerFactory;
        }

        /// <inheritdoc/>
        public string Name => "nebula";

        /// <inheritdoc/>
        public VpnDriverCapabilities Capabilities { get; } = new VpnDriverCapabilities
        {
            LinkLayer = VpnLinkLayer.L3Ip,                       // bare IP packets, no link header
            UsesPpp = false,
            MultiHostModel = MultiHostModel.None,                // single point-to-point peer (static endpoint)
            TransportKinds = VpnTransportKind.Udp,               // Nebula is UDP-only
            SecurityKinds = VpnSecurityKind.Noise,               // Noise_IX + AES-256-GCM transport
            AuthMethods = VpnAuthMethod.Certificate,             // Ed25519-signed host certificate
            AddressAssignment = AddressAssignment.OutOfBand,     // overlay address baked into the certificate
        };

        /// <inheritdoc/>
        public async Task<IVpnConnection> ConnectAsync(VpnEndpoint endpoint, VpnCredentials credentials, CancellationToken cancellationToken = default)
        {
            if (endpoint is null) throw new ArgumentNullException(nameof(endpoint));

            INebulaTransportFactory factory = _transportFactory ?? new NebulaSocketTransportFactory();
            var connection = new NebulaConnection(endpoint.Host, endpoint.Port, _config, factory,
                reconnectOptions: _reconnectOptions,
                addressFamilyPreference: endpoint.AddressFamilyPreference,
                loggerFactory: _loggerFactory);
            try
            {
                await connection.ConnectAsync(cancellationToken).ConfigureAwait(false);
                var session = new NebulaVpnSession(connection.PacketChannel, connection.Config);
                return new NebulaVpnConnection(connection, session);
            }
            catch
            {
                await connection.DisposeAsync().ConfigureAwait(false);
                throw;
            }
        }
    }
}
