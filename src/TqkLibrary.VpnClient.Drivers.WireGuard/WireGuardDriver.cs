using TqkLibrary.VpnClient.Abstractions.Drivers.Enums;
using TqkLibrary.VpnClient.Abstractions.Drivers.Interfaces;
using TqkLibrary.VpnClient.Abstractions.Drivers.Models;
using TqkLibrary.VpnClient.Drivers.WireGuard.Transport;
using TqkLibrary.VpnClient.WireGuard.Config;

namespace TqkLibrary.VpnClient.Drivers.WireGuard
{
    /// <summary>
    /// The WireGuard protocol driver. It is configured with a static <see cref="WireGuardConfig"/> (the
    /// point-to-point <c>[Interface]</c> + one <c>[Peer]</c>: private/peer keys, optional PSK, allowed-ips, MTU); the
    /// connect-time <see cref="VpnEndpoint"/> supplies the server host/port. WireGuard does no in-tunnel address
    /// negotiation, so the tunnel address/DNS/routes come straight from the config (<see cref="AddressAssignment.OutOfBand"/>).
    /// Full-tunnel point-to-point (allowed-ips <c>0.0.0.0/0, ::/0</c>) is wired; multi-peer routing is future work.
    /// </summary>
    public sealed class WireGuardDriver : IVpnProtocolDriver
    {
        readonly WireGuardConfig _config;
        readonly WireGuardReconnectOptions? _reconnectOptions;
        readonly IWireGuardTransportFactory? _transportFactory;

        /// <summary>
        /// Creates the driver. <paramref name="config"/> is the static point-to-point profile;
        /// <paramref name="reconnectOptions"/> tunes (or disables) auto-reconnect; <paramref name="transportFactory"/>
        /// overrides the UDP transport (an in-process loopback drives the driver offline in tests).
        /// </summary>
        public WireGuardDriver(WireGuardConfig config,
            WireGuardReconnectOptions? reconnectOptions = null,
            IWireGuardTransportFactory? transportFactory = null)
        {
            _config = config ?? throw new ArgumentNullException(nameof(config));
            _reconnectOptions = reconnectOptions;
            _transportFactory = transportFactory;
        }

        /// <inheritdoc/>
        public string Name => "wireguard";

        /// <inheritdoc/>
        public VpnDriverCapabilities Capabilities { get; } = new VpnDriverCapabilities
        {
            LinkLayer = VpnLinkLayer.L3Ip,                       // bare IP packets, no link header
            UsesPpp = false,
            MultiHostModel = MultiHostModel.None,                // single point-to-point peer
            TransportKinds = VpnTransportKind.Udp,               // WireGuard is UDP-only
            SecurityKinds = VpnSecurityKind.Noise,               // Noise_IKpsk2 + ChaCha20-Poly1305 transport
            AuthMethods = VpnAuthMethod.PreSharedKey,            // static keys (+ optional PSK)
            AddressAssignment = AddressAssignment.OutOfBand,     // address configured statically, not negotiated
        };

        /// <inheritdoc/>
        public async Task<IVpnConnection> ConnectAsync(VpnEndpoint endpoint, VpnCredentials credentials, CancellationToken cancellationToken = default)
        {
            if (endpoint is null) throw new ArgumentNullException(nameof(endpoint));

            IWireGuardTransportFactory factory = _transportFactory ?? new WireGuardSocketTransportFactory();
            var connection = new WireGuardConnection(endpoint.Host, endpoint.Port, _config, factory,
                reconnectOptions: _reconnectOptions,
                addressFamilyPreference: endpoint.AddressFamilyPreference);
            try
            {
                await connection.ConnectAsync(cancellationToken).ConfigureAwait(false);
                var session = new WireGuardVpnSession(connection.PacketChannel, connection.Config);
                return new WireGuardVpnConnection(connection, session);
            }
            catch
            {
                await connection.DisposeAsync().ConfigureAwait(false);
                throw;
            }
        }
    }
}
