using System.Net.Security;
using Microsoft.Extensions.Logging;
using TqkLibrary.VpnClient.Abstractions.Drivers;
using TqkLibrary.VpnClient.Abstractions.Drivers.Enums;
using TqkLibrary.VpnClient.Abstractions.Drivers.Interfaces;
using TqkLibrary.VpnClient.Abstractions.Drivers.Models;
using TqkLibrary.VpnClient.Drivers.SoftEther.Transport;
using TqkLibrary.VpnClient.SoftEther;
using TqkLibrary.VpnClient.SoftEther.Enums;
using TqkLibrary.VpnClient.SoftEther.Models;

namespace TqkLibrary.VpnClient.Drivers.SoftEther
{
    /// <summary>
    /// The SoftEther SSL-VPN protocol driver. It is configured with the target Virtual Hub (plus optional session
    /// params); the connect-time <see cref="VpnEndpoint"/> supplies the server host/port and <see cref="VpnCredentials"/>
    /// the user name + password (hashed locally to <c>secure_password</c>, SHA-0). The data plane is Ethernet-over-TLS:
    /// the server's SecureNAT leases the tunnel IP over DHCP (<see cref="AddressAssignment.Dhcp"/>) on an L2 segment.
    /// By default it bridges that segment down to a single L3 session; with <c>multiHost</c> it exposes the whole L2
    /// broadcast domain (the data channel becomes an uplink port on an in-memory switch and each station leases its own
    /// IP), surfacing one <see cref="IVpnSession"/> per station via <see cref="IVpnConnection.OpenSessionAsync"/> (L2.8).
    /// </summary>
    public sealed class SoftEtherDriver : IVpnProtocolDriver
    {
        readonly string _hubName;
        readonly SoftEtherSessionParams _session;
        readonly SoftEtherReconnectOptions? _reconnectOptions;
        readonly ISoftEtherTransportFactory? _transportFactory;
        readonly RemoteCertificateValidationCallback? _serverCertificateValidation;
        readonly SoftEtherWatermark? _watermark;
        readonly bool _multiHost;
        readonly bool _enableIpv6;
        readonly ILoggerFactory? _loggerFactory;

        /// <summary>
        /// Creates the driver targeting <paramref name="hubName"/> (e.g. <c>"DEFAULT"</c>). <paramref name="session"/>
        /// overrides the session params (parallel connections, encrypt/compress flags); <paramref name="reconnectOptions"/>
        /// tunes (or disables) auto-reconnect; <paramref name="transportFactory"/> overrides the TLS transport (an
        /// in-process loopback drives the driver offline in tests); <paramref name="serverCertificateValidation"/> validates
        /// the server TLS certificate (null = accept any, since SoftEther binds identity through its own auth);
        /// <paramref name="watermark"/> overrides the watermark POST blob — a real SoftEther server rejects the default
        /// placeholder (HTTP 403), so pass the genuine blob (e.g. loaded at runtime from a file) to interop with one. When
        /// <paramref name="multiHost"/> is <c>true</c> the connection exposes the whole L2 broadcast domain (uplink-as-port);
        /// <c>OpenSessionAsync</c> then adds a station instead of throwing. When <paramref name="enableIpv6"/> is <c>true</c>
        /// the bridge also runs IPv6 autoconfiguration (SLAAC/DHCPv6 — L2.6) + NDISC v6 over SecureNAT, best-effort (an
        /// IPv4-only SecureNAT still connects); the default keeps the wire IPv4-only so existing behaviour is unchanged.
        /// <paramref name="loggerFactory"/> receives diagnostic traces (null = no logging).
        /// </summary>
        public SoftEtherDriver(string hubName,
            SoftEtherSessionParams? session = null,
            SoftEtherReconnectOptions? reconnectOptions = null,
            ISoftEtherTransportFactory? transportFactory = null,
            RemoteCertificateValidationCallback? serverCertificateValidation = null,
            SoftEtherWatermark? watermark = null,
            bool multiHost = false,
            bool enableIpv6 = false,
            ILoggerFactory? loggerFactory = null)
        {
            _hubName = hubName ?? throw new ArgumentNullException(nameof(hubName));
            _session = session ?? new SoftEtherSessionParams();
            _reconnectOptions = reconnectOptions;
            _transportFactory = transportFactory;
            _serverCertificateValidation = serverCertificateValidation;
            _watermark = watermark;
            _multiHost = multiHost;
            _enableIpv6 = enableIpv6;
            _loggerFactory = loggerFactory;
        }

        /// <inheritdoc/>
        public string Name => "softether";

        /// <inheritdoc/>
        public VpnDriverCapabilities Capabilities { get; } = new VpnDriverCapabilities
        {
            LinkLayer = VpnLinkLayer.L2Ethernet,                 // Ethernet frames over TLS
            UsesPpp = false,
            SupportsMultiHost = true,                            // a whole L2 broadcast domain (EthernetAdapter, L2.8)
            MultiHostModel = MultiHostModel.L2BroadcastDomain,   // N MAC/IP stations sharing one in-memory switch
            TransportKinds = VpnTransportKind.Tcp,               // TLS over TCP (HTTPS)
            SecurityKinds = VpnSecurityKind.Tls,                 // TLS byte stream
            AuthMethods = VpnAuthMethod.UserPassword,            // SHA-0 secure_password
            AddressAssignment = AddressAssignment.Dhcp,          // SecureNAT leases the IP over DHCP
        };

        /// <inheritdoc/>
        public async Task<IVpnConnection> ConnectAsync(VpnEndpoint endpoint, VpnCredentials credentials, CancellationToken cancellationToken = default)
        {
            if (endpoint is null) throw new ArgumentNullException(nameof(endpoint));
            if (credentials is null) throw new ArgumentNullException(nameof(credentials));
            if (string.IsNullOrEmpty(credentials.Username))
                throw new VpnAuthenticationException("SoftEther login requires a user name.");

            var login = new SoftEtherLoginRequest
            {
                HubName = _hubName,
                UserName = credentials.Username!,
                AuthType = SoftEtherAuthType.Password,
                Password = credentials.Password ?? string.Empty,
                Session = _session,
            };

            ISoftEtherTransportFactory factory = _transportFactory
                ?? new SoftEtherTlsTransportFactory(_serverCertificateValidation);

            var connection = new SoftEtherConnection(endpoint.Host, endpoint.Port, login, factory,
                reconnectOptions: _reconnectOptions,
                addressFamilyPreference: endpoint.AddressFamilyPreference,
                watermark: _watermark,
                multiHost: _multiHost,
                enableIpv6: _enableIpv6,
                loggerFactory: _loggerFactory);
            try
            {
                await connection.ConnectAsync(cancellationToken).ConfigureAwait(false);
                var session = new SoftEtherVpnSession(connection.PacketChannel, connection.Config);
                return new SoftEtherVpnConnection(connection, session);
            }
            catch
            {
                await connection.DisposeAsync().ConfigureAwait(false);
                throw;
            }
        }
    }
}
