using System;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.Logging;
using TqkLibrary.VpnClient.Abstractions.Drivers.Enums;
using TqkLibrary.VpnClient.Abstractions.Drivers.Interfaces;
using TqkLibrary.VpnClient.Abstractions.Drivers.Models;
using TqkLibrary.VpnClient.Drivers.VxlanGpe.Config;
using TqkLibrary.VpnClient.Drivers.VxlanGpe.Transport;

namespace TqkLibrary.VpnClient.Drivers.VxlanGpe
{
    /// <summary>
    /// The VXLAN-GPE (Generic Protocol Extension, draft-ietf-nvo3-vxlan-gpe) protocol driver. It is configured with a static
    /// <see cref="VxlanGpeConfig"/> (the VNI, Next Protocol, this endpoint's static overlay IP + MAC, MTU); the connect-time
    /// <see cref="VpnEndpoint"/> supplies the remote peer host/port. VXLAN-GPE endpoints set their own overlay address, so
    /// the tunnel address / routes / MTU come straight from the config (<see cref="AddressAssignment.OutOfBand"/>).
    /// L2 Ethernet over UDP/4790 with an 8-byte header carrying an explicit Next Protocol — no control plane, no encryption,
    /// no keepalive, no registration; the remote peer is a static unicast VTEP.
    /// </summary>
    public sealed class VxlanGpeDriver : IVpnProtocolDriver
    {
        readonly VxlanGpeConfig _config;
        readonly VxlanGpeReconnectOptions? _reconnectOptions;
        readonly IVxlanGpeTransportFactory? _transportFactory;
        readonly ILoggerFactory? _loggerFactory;

        /// <summary>
        /// Creates the driver. <paramref name="config"/> is the static overlay profile; <paramref name="reconnectOptions"/>
        /// tunes (or disables) auto-reconnect; <paramref name="transportFactory"/> overrides the UDP transport (an in-process
        /// loopback drives the driver offline in tests; null ⇒ the production <see cref="VxlanGpeUdpTransportFactory"/>).
        /// <paramref name="loggerFactory"/> receives diagnostic traces (null = no logging).
        /// </summary>
        public VxlanGpeDriver(VxlanGpeConfig config,
            VxlanGpeReconnectOptions? reconnectOptions = null,
            IVxlanGpeTransportFactory? transportFactory = null,
            ILoggerFactory? loggerFactory = null)
        {
            _config = config ?? throw new ArgumentNullException(nameof(config));
            _reconnectOptions = reconnectOptions;
            _transportFactory = transportFactory;
            _loggerFactory = loggerFactory;
        }

        /// <inheritdoc/>
        public string Name => VxlanGpeDriverConstants.DriverName;

        /// <inheritdoc/>
        public VpnDriverCapabilities Capabilities { get; } = new VpnDriverCapabilities
        {
            LinkLayer = VpnLinkLayer.L2Ethernet,                 // Ethernet frames behind an 8-byte VXLAN-GPE header
            UsesPpp = false,
            MultiHostModel = MultiHostModel.None,                // single endpoint, static unicast remote peer
            TransportKinds = VpnTransportKind.Udp,               // VXLAN-GPE is UDP-only (dst 4790)
            SecurityKinds = VpnSecurityKind.None,                // VXLAN-GPE is a bare header — no encryption
            AuthMethods = VpnAuthMethod.None,                    // no control plane, no authentication
            AddressAssignment = AddressAssignment.OutOfBand,     // the endpoint sets its own static overlay address
            // RequiresRawIpSocket / RequiresElevation stay false: plain UDP, no elevation.
        };

        /// <inheritdoc/>
        public async Task<IVpnConnection> ConnectAsync(VpnEndpoint endpoint, VpnCredentials credentials, CancellationToken cancellationToken = default)
        {
            if (endpoint is null) throw new ArgumentNullException(nameof(endpoint));

            IVxlanGpeTransportFactory factory = _transportFactory ?? new VxlanGpeUdpTransportFactory();
            var connection = new VxlanGpeConnection(endpoint.Host, factory, _config,
                reconnectOptions: _reconnectOptions,
                addressFamilyPreference: endpoint.AddressFamilyPreference,
                loggerFactory: _loggerFactory);
            try
            {
                await connection.ConnectAsync(cancellationToken).ConfigureAwait(false);
                var session = new VxlanGpeVpnSession(connection.PacketChannel, connection.Config);
                return new VxlanGpeVpnConnection(connection, session);
            }
            catch
            {
                await connection.DisposeAsync().ConfigureAwait(false);
                throw;
            }
        }
    }
}
