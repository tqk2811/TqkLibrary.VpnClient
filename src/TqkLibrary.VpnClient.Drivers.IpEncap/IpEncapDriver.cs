using System;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.Logging;
using TqkLibrary.VpnClient.Abstractions.Drivers.Enums;
using TqkLibrary.VpnClient.Abstractions.Drivers.Interfaces;
using TqkLibrary.VpnClient.Abstractions.Drivers.Models;
using TqkLibrary.VpnClient.Abstractions.Transport.Interfaces;
using TqkLibrary.VpnClient.Drivers.IpEncap.Enums;

namespace TqkLibrary.VpnClient.Drivers.IpEncap
{
    /// <summary>
    /// The plain IP-in-IP / GRE tunnel driver (RFC 2784/2890 GRE proto-47, RFC 2003 IPIP proto-4, RFC 4213 SIT/6in4
    /// proto-41): opens a raw-IP transport on the kind's protocol number and binds the matching data-plane channel behind
    /// a stable L3 packet channel. There is no control plane (no handshake, no auth, no keepalive) — the address must be
    /// arranged out of band. The raw-IP transport (<see cref="IRawIpTransportFactory"/>, roadmap F.9) requires elevation.
    /// <para><b>GRE/IPIP/SIT are UNENCRYPTED</b> — use only on a trusted path or under IPsec ESP.</para>
    /// </summary>
    public sealed class IpEncapDriver : IVpnProtocolDriver
    {
        readonly IRawIpTransportFactory _rawIpFactory;
        readonly IpEncapOptions _options;
        readonly IpEncapReconnectOptions? _reconnectOptions;
        readonly ILoggerFactory? _loggerFactory;

        /// <summary>
        /// Creates the driver. <paramref name="rawIpFactory"/> carries the data plane (a raw IP socket on the kind's
        /// protocol number — requires elevation; pass <c>new RawIpTransportFactory()</c> from
        /// <c>TqkLibrary.VpnClient.Transport.RawIp</c>). <paramref name="options"/> selects the encap kind / MTU / GRE
        /// options (default GRE). <paramref name="reconnectOptions"/> tunes (or disables) auto-reconnect;
        /// <paramref name="loggerFactory"/> receives diagnostic traces (null = no logging).
        /// </summary>
        public IpEncapDriver(IRawIpTransportFactory rawIpFactory, IpEncapOptions? options = null,
            IpEncapReconnectOptions? reconnectOptions = null, ILoggerFactory? loggerFactory = null)
        {
            _rawIpFactory = rawIpFactory ?? throw new ArgumentNullException(nameof(rawIpFactory));
            _options = options ?? new IpEncapOptions();
            _reconnectOptions = reconnectOptions;
            _loggerFactory = loggerFactory;
        }

        /// <inheritdoc/>
        public string Name => "ipencap";

        /// <inheritdoc/>
        public VpnDriverCapabilities Capabilities { get; } = new VpnDriverCapabilities
        {
            LinkLayer = VpnLinkLayer.L3Ip,
            UsesPpp = false,
            MultiHostModel = MultiHostModel.None,
            TransportKinds = VpnTransportKind.RawIp,        // data rides a raw IP socket on a bare protocol number
            SecurityKinds = VpnSecurityKind.None,           // UNENCRYPTED — trust the path or layer IPsec ESP above
            AuthMethods = VpnAuthMethod.None,               // no control plane → no authentication
            AddressAssignment = AddressAssignment.OutOfBand,// no IPCP/DHCP — the tunnel address is arranged out of band
            RequiresRawIpSocket = true,                     // bare protocol number needs a raw IP socket
            RequiresElevation = true,                       // raw IP requires admin/root/CAP_NET_RAW
        };

        /// <inheritdoc/>
        public async Task<IVpnConnection> ConnectAsync(VpnEndpoint endpoint, VpnCredentials credentials, CancellationToken cancellationToken = default)
        {
            if (endpoint is null) throw new ArgumentNullException(nameof(endpoint));

            var connection = new IpEncapConnection(endpoint.Host, _rawIpFactory, _options,
                reconnectOptions: _reconnectOptions,
                addressFamilyPreference: endpoint.AddressFamilyPreference,
                loggerFactory: _loggerFactory);
            try
            {
                await connection.ConnectAsync(cancellationToken).ConfigureAwait(false);

                var config = new TunnelConfig { Mtu = _options.Mtu };
                var session = new IpEncapVpnSession(connection.PacketChannel, config);
                return new IpEncapVpnConnection(connection, session);
            }
            catch
            {
                await connection.DisposeAsync().ConfigureAwait(false);
                throw;
            }
        }
    }
}
