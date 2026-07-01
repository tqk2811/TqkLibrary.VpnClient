using System;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.Logging;
using TqkLibrary.VpnClient.Abstractions.Drivers.Enums;
using TqkLibrary.VpnClient.Abstractions.Drivers.Interfaces;
using TqkLibrary.VpnClient.Abstractions.Drivers.Models;
using TqkLibrary.VpnClient.Drivers.Vxlan.Config;
using TqkLibrary.VpnClient.Drivers.Vxlan.Transport;

namespace TqkLibrary.VpnClient.Drivers.Vxlan
{
    /// <summary>
    /// The VXLAN (RFC 7348) protocol driver. It is configured with a static <see cref="VxlanConfig"/> (the VNI, this
    /// endpoint's static overlay IP + MAC, MTU); the connect-time <see cref="VpnEndpoint"/> supplies the remote VTEP
    /// host/port. VXLAN endpoints set their own overlay address, so the tunnel address / routes / MTU come straight from
    /// the config (<see cref="AddressAssignment.OutOfBand"/>). L2 Ethernet over UDP/4789 with an 8-byte header — no
    /// control plane, no encryption, no keepalive, no registration; the remote VTEP is a static unicast peer.
    /// </summary>
    public sealed class VxlanDriver : IVpnProtocolDriver
    {
        readonly VxlanConfig _config;
        readonly VxlanReconnectOptions? _reconnectOptions;
        readonly IVxlanTransportFactory? _transportFactory;
        readonly ILoggerFactory? _loggerFactory;

        /// <summary>
        /// Creates the driver. <paramref name="config"/> is the static overlay profile; <paramref name="reconnectOptions"/>
        /// tunes (or disables) auto-reconnect; <paramref name="transportFactory"/> overrides the UDP transport (an
        /// in-process loopback drives the driver offline in tests; null ⇒ the production <see cref="VxlanUdpTransportFactory"/>).
        /// <paramref name="loggerFactory"/> receives diagnostic traces (null = no logging).
        /// </summary>
        public VxlanDriver(VxlanConfig config,
            VxlanReconnectOptions? reconnectOptions = null,
            IVxlanTransportFactory? transportFactory = null,
            ILoggerFactory? loggerFactory = null)
        {
            _config = config ?? throw new ArgumentNullException(nameof(config));
            _reconnectOptions = reconnectOptions;
            _transportFactory = transportFactory;
            _loggerFactory = loggerFactory;
        }

        /// <inheritdoc/>
        public string Name => VxlanDriverConstants.DriverName;

        /// <inheritdoc/>
        public VpnDriverCapabilities Capabilities { get; } = new VpnDriverCapabilities
        {
            LinkLayer = VpnLinkLayer.L2Ethernet,                 // Ethernet frames behind an 8-byte VXLAN header
            UsesPpp = false,
            MultiHostModel = MultiHostModel.None,                // single endpoint, static unicast remote VTEP
            TransportKinds = VpnTransportKind.Udp,               // VXLAN is UDP-only (dst 4789)
            SecurityKinds = VpnSecurityKind.None,                // VXLAN is a bare header — no encryption
            AuthMethods = VpnAuthMethod.None,                    // no control plane, no authentication
            AddressAssignment = AddressAssignment.OutOfBand,     // the endpoint sets its own static overlay address
            // RequiresRawIpSocket / RequiresElevation stay false: plain UDP, no elevation.
        };

        /// <inheritdoc/>
        public async Task<IVpnConnection> ConnectAsync(VpnEndpoint endpoint, VpnCredentials credentials, CancellationToken cancellationToken = default)
        {
            if (endpoint is null) throw new ArgumentNullException(nameof(endpoint));

            IVxlanTransportFactory factory = _transportFactory ?? new VxlanUdpTransportFactory();
            var connection = new VxlanConnection(endpoint.Host, factory, _config,
                reconnectOptions: _reconnectOptions,
                addressFamilyPreference: endpoint.AddressFamilyPreference,
                loggerFactory: _loggerFactory);
            try
            {
                await connection.ConnectAsync(cancellationToken).ConfigureAwait(false);
                var session = new VxlanVpnSession(connection.PacketChannel, connection.Config);
                return new VxlanVpnConnection(connection, session);
            }
            catch
            {
                await connection.DisposeAsync().ConfigureAwait(false);
                throw;
            }
        }
    }
}
