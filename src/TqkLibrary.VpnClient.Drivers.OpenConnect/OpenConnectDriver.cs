using System.Net.Security;
using TqkLibrary.VpnClient.Abstractions.Drivers.Enums;
using TqkLibrary.VpnClient.Abstractions.Drivers.Interfaces;
using TqkLibrary.VpnClient.Abstractions.Drivers.Models;
using TqkLibrary.VpnClient.Drivers.OpenConnect.Transport;
using TqkLibrary.VpnClient.Transport.Dtls;

namespace TqkLibrary.VpnClient.Drivers.OpenConnect
{
    /// <summary>
    /// The OpenConnect (Cisco AnyConnect / ocserv) protocol driver. The connect-time <see cref="VpnEndpoint"/> supplies
    /// the gateway host/port (443 by default) and the <see cref="VpnCredentials"/> the username/password the ocserv
    /// auth form expects. OpenConnect assigns the tunnel address in-band through the <c>X-CSTP-*</c> CONNECT headers
    /// (<see cref="AddressAssignment.ConfigPush"/>), carries bare IP packets over CSTP (no PPP), and runs
    /// <c>X-CSTP-DPD</c> dead-peer-detection + an idle keep-alive. When DTLS is enabled and the gateway advertises the
    /// <c>X-DTLS-*</c> headers the data plane runs over a parallel DTLS 1.2 datagram channel (V5.c), falling back to
    /// CSTP-over-TLS when DTLS is unavailable or its handshake fails.
    /// </summary>
    public sealed class OpenConnectDriver : IVpnProtocolDriver
    {
        readonly OpenConnectReconnectOptions? _reconnectOptions;
        readonly IOpenConnectTransportFactory? _transportFactory;
        readonly IOpenConnectDatagramTransportFactory? _datagramTransportFactory;
        readonly RemoteCertificateValidationCallback? _serverCertificateValidation;
        readonly DtlsServerCertificateValidationCallback? _dtlsCertificateValidation;
        readonly bool _enableDtls;
        readonly string _groupSelect;
        readonly int _requestedMtu;

        /// <summary>
        /// Creates the driver. <paramref name="reconnectOptions"/> tunes (or disables) auto-reconnect;
        /// <paramref name="transportFactory"/> overrides the TLS byte-stream transport (an in-process loopback drives the
        /// driver offline in tests; the default opens a real TLS socket); <paramref name="serverCertificateValidation"/>
        /// validates the gateway certificate (null = accept any); <paramref name="groupSelect"/> picks an ocserv auth
        /// group; <paramref name="requestedMtu"/> is advertised in <c>X-CSTP-Base-MTU</c>. <paramref name="enableDtls"/>
        /// (default true) advertises and uses the DTLS data path; <paramref name="datagramTransportFactory"/> overrides
        /// the UDP pipe the DTLS path opens (in-process loopback in tests; the default opens a real UDP socket);
        /// <paramref name="dtlsCertificateValidation"/> validates the gateway's DTLS certificate (null = accept any).
        /// </summary>
        public OpenConnectDriver(
            OpenConnectReconnectOptions? reconnectOptions = null,
            IOpenConnectTransportFactory? transportFactory = null,
            RemoteCertificateValidationCallback? serverCertificateValidation = null,
            string groupSelect = "",
            int requestedMtu = 1400,
            bool enableDtls = true,
            IOpenConnectDatagramTransportFactory? datagramTransportFactory = null,
            DtlsServerCertificateValidationCallback? dtlsCertificateValidation = null)
        {
            _reconnectOptions = reconnectOptions;
            _transportFactory = transportFactory;
            _datagramTransportFactory = datagramTransportFactory;
            _serverCertificateValidation = serverCertificateValidation;
            _dtlsCertificateValidation = dtlsCertificateValidation;
            _enableDtls = enableDtls;
            _groupSelect = groupSelect ?? string.Empty;
            if (requestedMtu < 1) throw new ArgumentOutOfRangeException(nameof(requestedMtu));
            _requestedMtu = requestedMtu;

            Capabilities = new VpnDriverCapabilities
            {
                LinkLayer = VpnLinkLayer.L3Ip,                       // CSTP carries bare IP packets, no link header
                UsesPpp = false,                                     // address is in-band via X-CSTP-*, not IPCP
                MultiHostModel = MultiHostModel.None,                // one assigned IP per connection
                // DTLS data path when enabled (with a TLS fallback), else TLS-only.
                TransportKinds = enableDtls ? VpnTransportKind.Tls | VpnTransportKind.Dtls : VpnTransportKind.Tls,
                SecurityKinds = enableDtls ? VpnSecurityKind.Tls | VpnSecurityKind.Dtls : VpnSecurityKind.Tls,
                AuthMethods = VpnAuthMethod.UserPassword,            // ocserv config-auth username/password form
                AddressAssignment = AddressAssignment.ConfigPush,    // X-CSTP-Address / X-CSTP-DNS / X-CSTP-Split-Include
            };
        }

        /// <inheritdoc/>
        public string Name => "openconnect";

        /// <inheritdoc/>
        public VpnDriverCapabilities Capabilities { get; }

        /// <inheritdoc/>
        public async Task<IVpnConnection> ConnectAsync(VpnEndpoint endpoint, VpnCredentials credentials, CancellationToken cancellationToken = default)
        {
            if (endpoint is null) throw new ArgumentNullException(nameof(endpoint));
            if (credentials is null) throw new ArgumentNullException(nameof(credentials));

            IOpenConnectTransportFactory factory = _transportFactory
                ?? new OpenConnectSocketTransportFactory(_serverCertificateValidation);

            // DTLS path is opt-in: enabled by default with a real UDP socket factory; a test injects an in-process one.
            IOpenConnectDatagramTransportFactory? datagramFactory = _enableDtls
                ? _datagramTransportFactory ?? new OpenConnectSocketDatagramTransportFactory()
                : null;

            var connection = new OpenConnectConnection(endpoint.Host, endpoint.Port, factory,
                username: credentials.Username,
                password: credentials.Password,
                groupSelect: _groupSelect,
                reconnectOptions: _reconnectOptions,
                addressFamilyPreference: endpoint.AddressFamilyPreference,
                requestedMtu: _requestedMtu,
                datagramFactory: datagramFactory,
                dtlsCertificateValidation: _dtlsCertificateValidation);
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
