using System;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.Logging;
using TqkLibrary.VpnClient.Abstractions.Drivers.Enums;
using TqkLibrary.VpnClient.Abstractions.Drivers.Interfaces;
using TqkLibrary.VpnClient.Abstractions.Drivers.Models;

namespace TqkLibrary.VpnClient.Drivers.Fou
{
    /// <summary>
    /// The FOU / GUE (Generic X-over-UDP) tunnel driver: carries an inner IP-protocol payload (IPIP proto 4/41 or GRE
    /// proto 47) inside a UDP payload — bare (Linux Foo-over-UDP, the inner protocol is inferred from the UDP dst port) or
    /// behind a 4-byte GUE variant-0 header (draft-ietf-intarea-gue, the header carries the inner protocol number) — then
    /// binds the reused IpEncap data-plane channel behind a stable L3 packet channel. Generalises GRE-in-UDP (RFC 8086).
    /// Because the carrier is an ordinary UDP socket, it needs <b>no elevation and no raw IP socket</b> and traverses
    /// NAT/firewalls that pass UDP. There is no control plane (no handshake, no auth, no keepalive) — the address must be
    /// arranged out of band. The <see cref="Name"/> is <c>"gue"</c> for GUE mode and <c>"fou"</c> for FOU mode.
    /// <para><b>FOU/GUE are UNENCRYPTED</b> — use only on a trusted path or under IPsec ESP.</para>
    /// </summary>
    public sealed class FouDriver : IVpnProtocolDriver
    {
        readonly IFouTransportFactory _transportFactory;
        readonly FouOptions _options;
        readonly FouReconnectOptions? _reconnectOptions;
        readonly ILoggerFactory? _loggerFactory;

        /// <summary>
        /// Creates the driver. <paramref name="options"/> selects the mode (FOU/GUE), inner protocol, UDP port, MTU and GRE
        /// options (default: FOU mode, GRE inner, port 6080); <paramref name="reconnectOptions"/> tunes (or disables)
        /// auto-reconnect. <paramref name="transportFactory"/> carries the data plane over a connected UDP socket (needs no
        /// elevation); when null the production <see cref="FouUdpTransportFactory"/> is used. <paramref name="loggerFactory"/>
        /// receives diagnostic traces (null = no logging).
        /// </summary>
        public FouDriver(FouOptions? options = null, FouReconnectOptions? reconnectOptions = null,
            IFouTransportFactory? transportFactory = null, ILoggerFactory? loggerFactory = null)
        {
            _transportFactory = transportFactory ?? new FouUdpTransportFactory();
            _options = options ?? new FouOptions();
            _reconnectOptions = reconnectOptions;
            _loggerFactory = loggerFactory;
        }

        /// <inheritdoc/>
        public string Name => FouConnection.DriverNameFor(_options);

        /// <inheritdoc/>
        public VpnDriverCapabilities Capabilities { get; } = new VpnDriverCapabilities
        {
            LinkLayer = VpnLinkLayer.L3Ip,
            UsesPpp = false,
            MultiHostModel = MultiHostModel.None,
            TransportKinds = VpnTransportKind.Udp,           // data rides an ordinary UDP datagram pipe
            SecurityKinds = VpnSecurityKind.None,            // UNENCRYPTED — trust the path or layer IPsec ESP above
            AuthMethods = VpnAuthMethod.None,                // no control plane → no authentication
            AddressAssignment = AddressAssignment.OutOfBand, // no IPCP/DHCP — the tunnel address is arranged out of band
            RequiresRawIpSocket = false,                     // the inner payload rides UDP, not a bare protocol number
            RequiresElevation = false,                       // an ordinary UDP socket needs no admin/root/CAP_NET_RAW
        };

        /// <inheritdoc/>
        public async Task<IVpnConnection> ConnectAsync(VpnEndpoint endpoint, VpnCredentials credentials, CancellationToken cancellationToken = default)
        {
            if (endpoint is null) throw new ArgumentNullException(nameof(endpoint));

            var connection = new FouConnection(endpoint.Host, _transportFactory, _options,
                reconnectOptions: _reconnectOptions,
                addressFamilyPreference: endpoint.AddressFamilyPreference,
                loggerFactory: _loggerFactory);
            try
            {
                await connection.ConnectAsync(cancellationToken).ConfigureAwait(false);

                var config = new TunnelConfig { Mtu = _options.Mtu };
                var session = new FouVpnSession(connection.PacketChannel, config);
                return new FouVpnConnection(connection, session);
            }
            catch
            {
                await connection.DisposeAsync().ConfigureAwait(false);
                throw;
            }
        }
    }
}
