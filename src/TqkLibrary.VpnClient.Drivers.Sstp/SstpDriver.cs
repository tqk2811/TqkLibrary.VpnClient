using System.Net.Security;
using Microsoft.Extensions.Logging;
using TqkLibrary.VpnClient.Abstractions.Drivers.Enums;
using TqkLibrary.VpnClient.Abstractions.Drivers.Interfaces;
using TqkLibrary.VpnClient.Abstractions.Drivers.Models;

namespace TqkLibrary.VpnClient.Drivers.Sstp
{
    /// <summary>The MS-SSTP protocol driver (TLS over 443, PPP, MS-CHAPv2).</summary>
    public sealed class SstpDriver : IVpnProtocolDriver
    {
        readonly SstpReconnectOptions? _reconnectOptions;
        readonly RemoteCertificateValidationCallback? _certificateValidationCallback;
        readonly bool _enableIpv6;
        readonly ILoggerFactory? _loggerFactory;

        /// <summary>
        /// Creates the driver; <paramref name="reconnectOptions"/> tunes (or disables) auto-reconnect and
        /// <paramref name="certificateValidationCallback"/> validates the server TLS certificate (<c>null</c> ⇒ accept
        /// any cert — the SSTP identity is bound by its crypto binding, not PKI). Set <paramref name="enableIpv6"/> to
        /// also run IPV6CP for a link-local IPv6 address (best-effort; the IPv4 path is unaffected).
        /// <paramref name="loggerFactory"/> receives diagnostic traces (null = no logging).
        /// </summary>
        public SstpDriver(SstpReconnectOptions? reconnectOptions = null, RemoteCertificateValidationCallback? certificateValidationCallback = null,
            bool enableIpv6 = false, ILoggerFactory? loggerFactory = null)
        {
            _reconnectOptions = reconnectOptions;
            _certificateValidationCallback = certificateValidationCallback;
            _enableIpv6 = enableIpv6;
            _loggerFactory = loggerFactory;
        }

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
            var connection = new SstpConnection(endpoint.Host, endpoint.Port, reconnectOptions: _reconnectOptions,
                certificateValidationCallback: _certificateValidationCallback, addressFamilyPreference: endpoint.AddressFamilyPreference,
                enableIpv6: _enableIpv6, loggerFactory: _loggerFactory);
            try
            {
                await connection.ConnectAsync(credentials.Username ?? string.Empty, credentials.Password ?? string.Empty, cancellationToken)
                    .ConfigureAwait(false);

                var config = new TunnelConfig { AssignedAddress = connection.AssignedAddress, AssignedAddressV6 = connection.AssignedAddressV6 };
                if (connection.AssignedDns != null) config.DnsServers.Add(connection.AssignedDns);

                var session = new SstpVpnSession(connection.PacketChannel, config);
                connection.Reconnected += info => session.ApplyReconnect(info, connection.AssignedDns);
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
