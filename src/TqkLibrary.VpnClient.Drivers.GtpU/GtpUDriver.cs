using System;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.Logging;
using TqkLibrary.VpnClient.Abstractions.Drivers.Enums;
using TqkLibrary.VpnClient.Abstractions.Drivers.Interfaces;
using TqkLibrary.VpnClient.Abstractions.Drivers.Models;

namespace TqkLibrary.VpnClient.Drivers.GtpU
{
    /// <summary>
    /// The GTP-U (GPRS Tunnelling Protocol, User plane, 3GPP TS 29.281) tunnel driver in <b>static mode</b> (key
    /// <c>"gtpu"</c>): carries an inner IP packet inside a UDP payload (default port 2152) behind an 8-byte GTP-U G-PDU
    /// header (message type 255) tagged with a configured TEID, then binds the reused IpEncap passthrough data-plane channel
    /// behind a stable L3 packet channel. Static mode has <b>no GTP-C control plane</b> — the TEID and endpoint are arranged
    /// out of band. Because the carrier is an ordinary UDP socket, it needs <b>no elevation and no raw IP socket</b> and
    /// traverses NAT/firewalls that pass UDP.
    /// <para><b>GTP-U is UNENCRYPTED</b> — it only tags the inner IP packet with a TEID (no authentication or encryption).
    /// Use only on a trusted path or under IPsec ESP.</para>
    /// </summary>
    public sealed class GtpUDriver : IVpnProtocolDriver
    {
        readonly IGtpUTransportFactory _transportFactory;
        readonly GtpUOptions _options;
        readonly GtpUReconnectOptions? _reconnectOptions;
        readonly ILoggerFactory? _loggerFactory;

        /// <summary>
        /// Creates the driver. <paramref name="options"/> supplies the UDP port, TEID, sequence flag and MTU (default: port
        /// 2152, TEID 0, no sequence); <paramref name="reconnectOptions"/> tunes (or disables) auto-reconnect.
        /// <paramref name="transportFactory"/> carries the data plane over a connected UDP socket (needs no elevation); when
        /// null the production <see cref="GtpUUdpTransportFactory"/> is used. <paramref name="loggerFactory"/> receives
        /// diagnostic traces (null = no logging).
        /// </summary>
        public GtpUDriver(GtpUOptions? options = null, GtpUReconnectOptions? reconnectOptions = null,
            IGtpUTransportFactory? transportFactory = null, ILoggerFactory? loggerFactory = null)
        {
            _transportFactory = transportFactory ?? new GtpUUdpTransportFactory();
            _options = options ?? new GtpUOptions();
            _reconnectOptions = reconnectOptions;
            _loggerFactory = loggerFactory;
        }

        /// <inheritdoc/>
        public string Name => "gtpu";

        /// <inheritdoc/>
        public VpnDriverCapabilities Capabilities { get; } = new VpnDriverCapabilities
        {
            LinkLayer = VpnLinkLayer.L3Ip,
            UsesPpp = false,
            MultiHostModel = MultiHostModel.None,
            TransportKinds = VpnTransportKind.Udp,           // data rides an ordinary UDP datagram pipe (port 2152)
            SecurityKinds = VpnSecurityKind.None,            // UNENCRYPTED — trust the path or layer IPsec ESP above
            AuthMethods = VpnAuthMethod.None,                // no control plane → no authentication (the TEID is not a secret)
            AddressAssignment = AddressAssignment.OutOfBand, // no GTP-C — the tunnel address is arranged out of band
            RequiresRawIpSocket = false,                     // the inner payload rides UDP, not a bare protocol number
            RequiresElevation = false,                       // an ordinary UDP socket needs no admin/root/CAP_NET_RAW
        };

        /// <inheritdoc/>
        public async Task<IVpnConnection> ConnectAsync(VpnEndpoint endpoint, VpnCredentials credentials, CancellationToken cancellationToken = default)
        {
            if (endpoint is null) throw new ArgumentNullException(nameof(endpoint));

            var connection = new GtpUConnection(endpoint.Host, _transportFactory, _options,
                reconnectOptions: _reconnectOptions,
                addressFamilyPreference: endpoint.AddressFamilyPreference,
                loggerFactory: _loggerFactory);
            try
            {
                await connection.ConnectAsync(cancellationToken).ConfigureAwait(false);

                var config = new TunnelConfig { Mtu = _options.Mtu };
                var session = new GtpUVpnSession(connection.PacketChannel, config);
                return new GtpUVpnConnection(connection, session);
            }
            catch
            {
                await connection.DisposeAsync().ConfigureAwait(false);
                throw;
            }
        }
    }
}
