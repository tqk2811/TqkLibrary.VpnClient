using Microsoft.Extensions.Logging;
using TqkLibrary.VpnClient.Abstractions.Drivers.Enums;
using TqkLibrary.VpnClient.Abstractions.Drivers.Interfaces;
using TqkLibrary.VpnClient.Abstractions.Drivers.Models;
using TqkLibrary.VpnClient.Abstractions.Transport.Interfaces;
using TqkLibrary.VpnClient.Drivers.L2tpIpsec.Enums;

namespace TqkLibrary.VpnClient.Drivers.L2tpIpsec
{
    /// <summary>The L2TP/IPsec protocol driver (IKEv1 PSK over NAT-T, ESP transport mode, L2TP, PPP/MS-CHAPv2).</summary>
    public sealed class L2tpIpsecDriver : IVpnProtocolDriver
    {
        readonly L2tpIpsecReconnectOptions? _reconnectOptions;
        readonly L2tpIpsecTimeoutOptions? _timeoutOptions;
        readonly L2tpIpsecNatTraversalMode _natTraversalMode;
        readonly bool _enableIpv6;
        readonly ILoggerFactory? _loggerFactory;
        readonly IRawIpTransportFactory? _rawIpFactory;

        /// <summary>
        /// Creates the driver; <paramref name="reconnectOptions"/> tunes (or disables) auto-reconnect,
        /// <paramref name="timeoutOptions"/> tunes the IKE/L2TP handshake timeouts and retransmit caps,
        /// <paramref name="natTraversalMode"/> selects how NAT-T is negotiated (default: always force NAT-T),
        /// <paramref name="enableIpv6"/> also runs IPV6CP for a link-local IPv6 address (best-effort; IPv4 unaffected),
        /// <paramref name="loggerFactory"/> receives diagnostic traces (null = no logging), and
        /// <paramref name="rawIpFactory"/> (with <see cref="L2tpIpsecNatTraversalMode.HonestFirst"/>) enables the native
        /// ESP (proto-50) carrier for a no-NAT gateway — requires elevation; null keeps the client no-admin.
        /// </summary>
        public L2tpIpsecDriver(L2tpIpsecReconnectOptions? reconnectOptions = null, L2tpIpsecTimeoutOptions? timeoutOptions = null,
            L2tpIpsecNatTraversalMode natTraversalMode = L2tpIpsecNatTraversalMode.ForcedNatT, bool enableIpv6 = false,
            ILoggerFactory? loggerFactory = null, IRawIpTransportFactory? rawIpFactory = null)
        {
            _reconnectOptions = reconnectOptions;
            _timeoutOptions = timeoutOptions;
            _natTraversalMode = natTraversalMode;
            _enableIpv6 = enableIpv6;
            _loggerFactory = loggerFactory;
            _rawIpFactory = rawIpFactory;
        }

        /// <inheritdoc/>
        public string Name => "l2tp-ipsec";

        /// <inheritdoc/>
        public VpnDriverCapabilities Capabilities { get; } = new VpnDriverCapabilities
        {
            LinkLayer = VpnLinkLayer.L3Ip,
            UsesPpp = true,
            MultiHostModel = MultiHostModel.None,
            TransportKinds = VpnTransportKind.Udp,
            SecurityKinds = VpnSecurityKind.Esp,
            AuthMethods = VpnAuthMethod.UserPassword | VpnAuthMethod.PreSharedKey,
            AddressAssignment = AddressAssignment.Ipcp,
        };

        /// <inheritdoc/>
        public async Task<IVpnConnection> ConnectAsync(VpnEndpoint endpoint, VpnCredentials credentials, CancellationToken cancellationToken = default)
        {
            byte[]? psk = credentials.PreSharedKey;
            if (psk is null || psk.Length == 0)
                throw new ArgumentException(
                    "L2TP/IPsec requires a pre-shared key. Set VpnCredentials.PreSharedKey (VPN Gate's group PSK is \"vpn\").",
                    nameof(credentials));

            var connection = new L2tpIpsecConnection(endpoint.Host, psk, reconnectOptions: _reconnectOptions,
                timeoutOptions: _timeoutOptions, natTraversalMode: _natTraversalMode,
                addressFamilyPreference: endpoint.AddressFamilyPreference, enableIpv6: _enableIpv6,
                loggerFactory: _loggerFactory, rawIpFactory: _rawIpFactory);
            try
            {
                await connection.ConnectAsync(credentials.Username ?? string.Empty, credentials.Password ?? string.Empty, cancellationToken)
                    .ConfigureAwait(false);

                var config = new TunnelConfig { AssignedAddress = connection.AssignedAddress, AssignedAddressV6 = connection.AssignedAddressV6 };
                if (connection.AssignedDns != null) config.DnsServers.Add(connection.AssignedDns);

                var session = new L2tpIpsecVpnSession(connection.PacketChannel, config);
                connection.Reconnected += info => session.ApplyReconnect(info, connection.AssignedDns);
                return new L2tpIpsecVpnConnection(connection, session);
            }
            catch
            {
                connection.Dispose();
                throw;
            }
        }
    }
}
