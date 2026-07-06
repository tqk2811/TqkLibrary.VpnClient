using System;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.Logging;
using TqkLibrary.VpnClient.Abstractions.Drivers.Enums;
using TqkLibrary.VpnClient.Abstractions.Drivers.Interfaces;
using TqkLibrary.VpnClient.Abstractions.Drivers.Models;
using TqkLibrary.VpnClient.Drivers.Geneve.Config;
using TqkLibrary.VpnClient.Drivers.Geneve.Transport;

namespace TqkLibrary.VpnClient.Drivers.Geneve
{
    /// <summary>
    /// The Geneve (RFC 8926) protocol driver. It is configured with a static <see cref="GeneveConfig"/> (the VNI, this
    /// endpoint's static overlay IP + MAC, MTU); the connect-time <see cref="VpnEndpoint"/> supplies the remote host/port.
    /// Geneve endpoints set their own overlay address, so the tunnel address / routes / MTU come straight from the config
    /// (<see cref="AddressAssignment.OutOfBand"/>). L2 Ethernet over UDP/6081 with an 8-byte base header (+ optional TLV
    /// options) — no control plane, no encryption, no keepalive, no registration; the remote endpoint is a static unicast
    /// peer. The direct sibling of the VXLAN driver.
    /// </summary>
    public sealed class GeneveDriver : IVpnProtocolDriver
    {
        readonly GeneveConfig _config;
        readonly GeneveReconnectOptions? _reconnectOptions;
        readonly IGeneveTransportFactory? _transportFactory;
        readonly ILoggerFactory? _loggerFactory;

        /// <summary>
        /// Creates the driver. <paramref name="config"/> is the static overlay profile; <paramref name="reconnectOptions"/>
        /// tunes (or disables) auto-reconnect; <paramref name="transportFactory"/> overrides the UDP transport (an
        /// in-process loopback drives the driver offline in tests; null ⇒ the production <see cref="GeneveUdpTransportFactory"/>).
        /// <paramref name="loggerFactory"/> receives diagnostic traces (null = no logging).
        /// </summary>
        public GeneveDriver(GeneveConfig config,
            GeneveReconnectOptions? reconnectOptions = null,
            IGeneveTransportFactory? transportFactory = null,
            ILoggerFactory? loggerFactory = null)
        {
            _config = config ?? throw new ArgumentNullException(nameof(config));
            _reconnectOptions = reconnectOptions;
            _transportFactory = transportFactory;
            _loggerFactory = loggerFactory;
        }

        /// <inheritdoc/>
        public string Name => GeneveDriverConstants.DriverName;

        /// <inheritdoc/>
        public VpnDriverCapabilities Capabilities { get; } = new VpnDriverCapabilities
        {
            LinkLayer = VpnLinkLayer.L2Ethernet,                 // Ethernet frames behind an 8-byte Geneve base header
            UsesPpp = false,
            MultiHostModel = MultiHostModel.None,                // single endpoint, static unicast remote peer
            TransportKinds = VpnTransportKind.Udp,               // Geneve is UDP-only (dst 6081)
            SecurityKinds = VpnSecurityKind.None,                // Geneve is a bare header — no encryption
            AuthMethods = VpnAuthMethod.None,                    // no control plane, no authentication
            AddressAssignment = AddressAssignment.OutOfBand,     // the endpoint sets its own static overlay address
            // RequiresRawIpSocket / RequiresElevation stay false: plain UDP, no elevation.
        };

        /// <inheritdoc/>
        public async Task<IVpnConnection> ConnectAsync(VpnEndpoint endpoint, VpnCredentials credentials, CancellationToken cancellationToken = default)
        {
            if (endpoint is null) throw new ArgumentNullException(nameof(endpoint));

            IGeneveTransportFactory factory = _transportFactory ?? new GeneveUdpTransportFactory();
            var connection = new GeneveConnection(endpoint.Host, factory, _config,
                reconnectOptions: _reconnectOptions,
                addressFamilyPreference: endpoint.AddressFamilyPreference,
                loggerFactory: _loggerFactory);
            try
            {
                await connection.ConnectAsync(cancellationToken).ConfigureAwait(false);
                var session = new GeneveVpnSession(connection.PacketChannel, connection.Config);
                return new GeneveVpnConnection(connection, session);
            }
            catch
            {
                await connection.DisposeAsync().ConfigureAwait(false);
                throw;
            }
        }
    }
}
