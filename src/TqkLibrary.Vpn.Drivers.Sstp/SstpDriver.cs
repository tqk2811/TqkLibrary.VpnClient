using TqkLibrary.Vpn.Abstractions.Drivers.Enums;
using TqkLibrary.Vpn.Abstractions.Drivers.Interfaces;
using TqkLibrary.Vpn.Abstractions.Drivers.Models;

namespace TqkLibrary.Vpn.Drivers.Sstp
{
    /// <summary>The MS-SSTP protocol driver (TLS over 443, PPP, MS-CHAPv2).</summary>
    public sealed class SstpDriver : IVpnProtocolDriver
    {
        /// <inheritdoc/>
        public string Name => "sstp";

        /// <inheritdoc/>
        public VpnDriverCapabilities Capabilities { get; } = new VpnDriverCapabilities
        {
            LinkLayer = VpnLinkLayer.L3Ip,
            UsesPpp = true,
            MultiHostModel = MultiHostModel.None,
            TransportKinds = VpnTransportKind.Tls,
            SecurityKinds = VpnSecurityKind.Tls,
            AuthMethods = VpnAuthMethod.UserPassword,
            AddressAssignment = AddressAssignment.Ipcp,
        };

        /// <inheritdoc/>
        public async Task<IVpnConnection> ConnectAsync(VpnEndpoint endpoint, VpnCredentials credentials, CancellationToken cancellationToken = default)
        {
            var connection = new SstpConnection(endpoint.Host, endpoint.Port);
            try
            {
                await connection.ConnectAsync(credentials.Username ?? string.Empty, credentials.Password ?? string.Empty, cancellationToken)
                    .ConfigureAwait(false);

                var config = new TunnelConfig { AssignedAddress = connection.AssignedAddress };
                if (connection.AssignedDns != null) config.DnsServers.Add(connection.AssignedDns);

                var session = new SstpVpnSession(connection.PacketChannel, config);
                return new SstpVpnConnection(connection, session);
            }
            catch
            {
                connection.Dispose();
                throw;
            }
        }
    }
}
