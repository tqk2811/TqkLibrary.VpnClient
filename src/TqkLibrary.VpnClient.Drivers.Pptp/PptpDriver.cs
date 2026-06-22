using Microsoft.Extensions.Logging;
using TqkLibrary.VpnClient.Abstractions.Drivers.Enums;
using TqkLibrary.VpnClient.Abstractions.Drivers.Interfaces;
using TqkLibrary.VpnClient.Abstractions.Drivers.Models;
using TqkLibrary.VpnClient.Abstractions.Transport.Interfaces;

namespace TqkLibrary.VpnClient.Drivers.Pptp
{
    /// <summary>
    /// The PPTP protocol driver (RFC 2637): a TCP/1723 control connection, a GRE (proto-47) data plane, MPPE
    /// (RFC 3078/3079) over CCP, and PPP/MS-CHAPv2. GRE requires a raw-IP transport (<see cref="IRawIpTransportFactory"/>,
    /// roadmap F.9) and therefore elevation.
    /// <para><b>PPTP + MS-CHAPv2 + MPPE/RC4 is legacy and cryptographically insecure</b> — provided only for interop
    /// with legacy PPTP servers; prefer L2TP/IPsec, IKEv2, OpenVPN or WireGuard for any new deployment.</para>
    /// </summary>
    public sealed class PptpDriver : IVpnProtocolDriver
    {
        readonly IRawIpTransportFactory _rawIpFactory;
        readonly PptpReconnectOptions? _reconnectOptions;
        readonly PptpTimeoutOptions? _timeoutOptions;
        readonly PptpControlTransportFactory? _controlTransportFactory;
        readonly ILoggerFactory? _loggerFactory;

        /// <summary>
        /// Creates the driver. <paramref name="rawIpFactory"/> carries the GRE data plane (raw IP proto-47, requires
        /// elevation; pass <c>new RawIpTransportFactory()</c> from <c>TqkLibrary.VpnClient.Transport.RawIp</c>).
        /// <paramref name="reconnectOptions"/> tunes (or disables) auto-reconnect; <paramref name="timeoutOptions"/>
        /// tunes the handshake timeout and Echo keepalive interval; <paramref name="controlTransportFactory"/> overrides
        /// how the TCP/1723 control byte stream is opened (default: real TCP; tests inject an in-memory stream);
        /// <paramref name="loggerFactory"/> receives diagnostic traces (null = no logging).
        /// </summary>
        public PptpDriver(IRawIpTransportFactory rawIpFactory, PptpReconnectOptions? reconnectOptions = null,
            PptpTimeoutOptions? timeoutOptions = null, PptpControlTransportFactory? controlTransportFactory = null,
            ILoggerFactory? loggerFactory = null)
        {
            _rawIpFactory = rawIpFactory ?? throw new ArgumentNullException(nameof(rawIpFactory));
            _reconnectOptions = reconnectOptions;
            _timeoutOptions = timeoutOptions;
            _controlTransportFactory = controlTransportFactory;
            _loggerFactory = loggerFactory;
        }

        /// <inheritdoc/>
        public string Name => "pptp";

        /// <inheritdoc/>
        public VpnDriverCapabilities Capabilities { get; } = new VpnDriverCapabilities
        {
            LinkLayer = VpnLinkLayer.L3Ip,
            UsesPpp = true,
            MultiHostModel = MultiHostModel.None,
            TransportKinds = VpnTransportKind.Tcp | VpnTransportKind.RawIp, // control on TCP/1723, data on GRE (raw IP proto-47)
            SecurityKinds = VpnSecurityKind.Mppe,                          // legacy/insecure: MS-CHAPv2 + MPPE/RC4
            AuthMethods = VpnAuthMethod.UserPassword,                       // MS-CHAPv2
            AddressAssignment = AddressAssignment.Ipcp,
            RequiresRawIpSocket = true,                                     // GRE needs a raw IP socket
            RequiresElevation = true,                                       // raw IP proto-47 requires admin/root/CAP_NET_RAW
        };

        /// <inheritdoc/>
        public async Task<IVpnConnection> ConnectAsync(VpnEndpoint endpoint, VpnCredentials credentials, CancellationToken cancellationToken = default)
        {
            int port = endpoint.Port > 0 ? endpoint.Port : Transport.PptpControlTcpTransport.DefaultPort;
            var connection = new PptpConnection(endpoint.Host, _rawIpFactory, port,
                reconnectOptions: _reconnectOptions, timeoutOptions: _timeoutOptions,
                controlTransportFactory: _controlTransportFactory,
                addressFamilyPreference: endpoint.AddressFamilyPreference, loggerFactory: _loggerFactory);
            try
            {
                await connection.ConnectAsync(credentials.Username ?? string.Empty, credentials.Password ?? string.Empty, cancellationToken)
                    .ConfigureAwait(false);

                var config = new TunnelConfig { AssignedAddress = connection.AssignedAddress };
                if (connection.AssignedDns != null) config.DnsServers.Add(connection.AssignedDns);

                var session = new PptpVpnSession(connection.PacketChannel, config);
                connection.Reconnected += info => session.ApplyReconnect(info, connection.AssignedDns);
                return new PptpVpnConnection(connection, session);
            }
            catch
            {
                connection.Dispose();
                throw;
            }
        }
    }
}
