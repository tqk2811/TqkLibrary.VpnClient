using System.Net.Security;
using TqkLibrary.VpnClient.Abstractions.Drivers.Enums;
using TqkLibrary.VpnClient.Abstractions.Drivers.Interfaces;
using TqkLibrary.VpnClient.Abstractions.Drivers.Models;
using TqkLibrary.VpnClient.Drivers.OpenConnect.Transport;

namespace TqkLibrary.VpnClient.Drivers.OpenConnect
{
    /// <summary>
    /// The OpenConnect (Cisco AnyConnect / ocserv) protocol driver. The connect-time <see cref="VpnEndpoint"/> supplies
    /// the gateway host/port (443 by default) and the <see cref="VpnCredentials"/> the username/password the ocserv
    /// auth form expects. OpenConnect assigns the tunnel address in-band through the <c>X-CSTP-*</c> CONNECT headers
    /// (<see cref="AddressAssignment.ConfigPush"/>), carries bare IP packets over CSTP-over-TLS (no PPP), and runs
    /// <c>X-CSTP-DPD</c> dead-peer-detection + an idle keep-alive. <b>TLS-only</b> — the DTLS data path is roadmap V5.c.
    /// </summary>
    public sealed class OpenConnectDriver : IVpnProtocolDriver
    {
        readonly OpenConnectReconnectOptions? _reconnectOptions;
        readonly IOpenConnectTransportFactory? _transportFactory;
        readonly RemoteCertificateValidationCallback? _serverCertificateValidation;
        readonly string _groupSelect;
        readonly int _requestedMtu;

        /// <summary>
        /// Creates the driver. <paramref name="reconnectOptions"/> tunes (or disables) auto-reconnect;
        /// <paramref name="transportFactory"/> overrides the TLS byte-stream transport (an in-process loopback drives the
        /// driver offline in tests; the default opens a real TLS socket); <paramref name="serverCertificateValidation"/>
        /// validates the gateway certificate (null = accept any); <paramref name="groupSelect"/> picks an ocserv auth
        /// group; <paramref name="requestedMtu"/> is advertised in <c>X-CSTP-Base-MTU</c>.
        /// </summary>
        public OpenConnectDriver(
            OpenConnectReconnectOptions? reconnectOptions = null,
            IOpenConnectTransportFactory? transportFactory = null,
            RemoteCertificateValidationCallback? serverCertificateValidation = null,
            string groupSelect = "",
            int requestedMtu = 1400)
        {
            _reconnectOptions = reconnectOptions;
            _transportFactory = transportFactory;
            _serverCertificateValidation = serverCertificateValidation;
            _groupSelect = groupSelect ?? string.Empty;
            if (requestedMtu < 1) throw new ArgumentOutOfRangeException(nameof(requestedMtu));
            _requestedMtu = requestedMtu;
        }

        /// <inheritdoc/>
        public string Name => "openconnect";

        /// <inheritdoc/>
        public VpnDriverCapabilities Capabilities { get; } = new VpnDriverCapabilities
        {
            LinkLayer = VpnLinkLayer.L3Ip,                       // CSTP carries bare IP packets, no link header
            UsesPpp = false,                                     // address is in-band via X-CSTP-*, not IPCP
            MultiHostModel = MultiHostModel.None,                // one assigned IP per connection
            TransportKinds = VpnTransportKind.Tls,               // TLS-only here; DTLS is roadmap V5.c
            SecurityKinds = VpnSecurityKind.Tls,
            AuthMethods = VpnAuthMethod.UserPassword,            // ocserv config-auth username/password form
            AddressAssignment = AddressAssignment.ConfigPush,    // X-CSTP-Address / X-CSTP-DNS / X-CSTP-Split-Include
        };

        /// <inheritdoc/>
        public async Task<IVpnConnection> ConnectAsync(VpnEndpoint endpoint, VpnCredentials credentials, CancellationToken cancellationToken = default)
        {
            if (endpoint is null) throw new ArgumentNullException(nameof(endpoint));
            if (credentials is null) throw new ArgumentNullException(nameof(credentials));

            IOpenConnectTransportFactory factory = _transportFactory
                ?? new OpenConnectSocketTransportFactory(_serverCertificateValidation);

            var connection = new OpenConnectConnection(endpoint.Host, endpoint.Port, factory,
                username: credentials.Username,
                password: credentials.Password,
                groupSelect: _groupSelect,
                reconnectOptions: _reconnectOptions,
                addressFamilyPreference: endpoint.AddressFamilyPreference,
                requestedMtu: _requestedMtu);
            try
            {
                await connection.ConnectAsync(cancellationToken).ConfigureAwait(false);
                var session = new OpenConnectVpnSession(connection.PacketChannel, connection.Config);
                return new OpenConnectVpnConnection(connection, session);
            }
            catch
            {
                await connection.DisposeAsync().ConfigureAwait(false);
                throw;
            }
        }
    }
}
