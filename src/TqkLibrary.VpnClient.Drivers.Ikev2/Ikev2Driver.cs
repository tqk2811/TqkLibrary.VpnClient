using TqkLibrary.VpnClient.Abstractions.Drivers.Enums;
using TqkLibrary.VpnClient.Abstractions.Drivers.Interfaces;
using TqkLibrary.VpnClient.Abstractions.Drivers.Models;

namespace TqkLibrary.VpnClient.Drivers.Ikev2
{
    /// <summary>The IKEv2-native protocol driver (RFC 7296 PSK over NAT-T, CP virtual IP, ESP tunnel mode — no PPP).</summary>
    public sealed class Ikev2Driver : IVpnProtocolDriver
    {
        readonly Ikev2ReconnectOptions? _reconnectOptions;

        /// <summary>Creates the driver; <paramref name="reconnectOptions"/> tunes (or disables) auto-reconnect.</summary>
        public Ikev2Driver(Ikev2ReconnectOptions? reconnectOptions = null)
        {
            _reconnectOptions = reconnectOptions;
        }

        /// <inheritdoc/>
        public string Name => "ikev2";

        /// <inheritdoc/>
        public VpnDriverCapabilities Capabilities { get; } = new VpnDriverCapabilities
        {
            LinkLayer = VpnLinkLayer.L3Ip,
            UsesPpp = false,
            MultiHostModel = MultiHostModel.None,
            TransportKinds = VpnTransportKind.Udp,
            SecurityKinds = VpnSecurityKind.Esp,
            AuthMethods = VpnAuthMethod.PreSharedKey,
            AddressAssignment = AddressAssignment.ConfigPush,
        };

        /// <inheritdoc/>
        public async Task<IVpnConnection> ConnectAsync(VpnEndpoint endpoint, VpnCredentials credentials, CancellationToken cancellationToken = default)
        {
            byte[]? psk = credentials.PreSharedKey;
            if (psk is null || psk.Length == 0)
                throw new ArgumentException(
                    "IKEv2 requires a pre-shared key. Set VpnCredentials.PreSharedKey.", nameof(credentials));

            var connection = new Ikev2Connection(endpoint.Host, psk, reconnectOptions: _reconnectOptions,
                addressFamilyPreference: endpoint.AddressFamilyPreference);
            try
            {
                await connection.ConnectAsync(cancellationToken).ConfigureAwait(false);

                var config = new TunnelConfig { AssignedAddress = connection.AssignedAddress };
                if (connection.AssignedDns != null) config.DnsServers.Add(connection.AssignedDns);

                var session = new Ikev2VpnSession(connection.PacketChannel, config);
                connection.Reconnected += info => session.ApplyReconnect(info, connection.AssignedDns);
                return new Ikev2VpnConnection(connection, session);
            }
            catch
            {
                await connection.DisposeAsync().ConfigureAwait(false);
                throw;
            }
        }
    }
}
