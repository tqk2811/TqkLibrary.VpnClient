using System;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.Logging;
using TqkLibrary.VpnClient.Abstractions.Drivers.Enums;
using TqkLibrary.VpnClient.Abstractions.Drivers.Interfaces;
using TqkLibrary.VpnClient.Abstractions.Drivers.Models;
using TqkLibrary.VpnClient.Drivers.EoGre.Config;
using TqkLibrary.VpnClient.Drivers.EoGre.Enums;
using TqkLibrary.VpnClient.Drivers.EoGre.Transport;

namespace TqkLibrary.VpnClient.Drivers.EoGre
{
    /// <summary>
    /// The EoGRE / NVGRE (RFC 8086 + RFC 2784/2890 + RFC 7637) protocol driver. It is configured with a static
    /// <see cref="EoGreConfig"/> (the optional/mandatory VSID + FlowID, this endpoint's static overlay IP + MAC, MTU) and a
    /// <see cref="EoGreMode"/>; the connect-time <see cref="VpnEndpoint"/> supplies the remote host/port. EoGRE endpoints
    /// set their own overlay address, so the tunnel address / routes / MTU come straight from the config
    /// (<see cref="AddressAssignment.OutOfBand"/>). L2 Ethernet behind a GRE header (protocol type 0x6558) over UDP/4754 —
    /// no control plane, no encryption, no keepalive, no registration; the remote endpoint is a static unicast peer. The
    /// GRE codec is reused wholesale from <c>TqkLibrary.VpnClient.IpEncap</c>. The L2 sibling of the GRE-in-UDP L3 driver.
    /// <para>The <see cref="Name"/> is <c>"nvgre"</c> in <see cref="EoGreMode.Nvgre"/> and <c>"eogre"</c> otherwise.</para>
    /// </summary>
    public sealed class EoGreDriver : IVpnProtocolDriver
    {
        readonly EoGreConfig _config;
        readonly EoGreMode _mode;
        readonly EoGreReconnectOptions? _reconnectOptions;
        readonly IEoGreTransportFactory? _transportFactory;
        readonly ILoggerFactory? _loggerFactory;

        /// <summary>
        /// Creates the driver. <paramref name="config"/> is the static overlay profile; <paramref name="mode"/> selects
        /// EoGRE (key <c>"eogre"</c>) vs NVGRE (key <c>"nvgre"</c>); <paramref name="reconnectOptions"/> tunes (or disables)
        /// auto-reconnect; <paramref name="transportFactory"/> overrides the UDP transport (an in-process loopback drives the
        /// driver offline in tests; null ⇒ the production <see cref="EoGreUdpTransportFactory"/>).
        /// <paramref name="loggerFactory"/> receives diagnostic traces (null = no logging).
        /// </summary>
        /// <exception cref="ArgumentException"><paramref name="mode"/> is NVGRE but the config has no VSID.</exception>
        public EoGreDriver(EoGreConfig config, EoGreMode mode = EoGreMode.EoGre,
            EoGreReconnectOptions? reconnectOptions = null,
            IEoGreTransportFactory? transportFactory = null,
            ILoggerFactory? loggerFactory = null)
        {
            _config = config ?? throw new ArgumentNullException(nameof(config));
            _mode = mode;
            _reconnectOptions = reconnectOptions;
            _transportFactory = transportFactory;
            _loggerFactory = loggerFactory;
            config.Validate(mode); // fail fast on a misconfigured NVGRE (missing VSID) / out-of-range VSID
        }

        /// <inheritdoc/>
        public string Name => _mode == EoGreMode.Nvgre ? EoGreDriverConstants.DriverNameNvgre : EoGreDriverConstants.DriverNameEoGre;

        /// <inheritdoc/>
        public VpnDriverCapabilities Capabilities { get; } = new VpnDriverCapabilities
        {
            LinkLayer = VpnLinkLayer.L2Ethernet,                 // Ethernet frames behind a GRE header (protocol type 0x6558)
            UsesPpp = false,
            MultiHostModel = MultiHostModel.None,                // single endpoint, static unicast remote peer
            TransportKinds = VpnTransportKind.Udp,               // GRE-in-UDP (dst 4754) — no raw proto-47 socket
            SecurityKinds = VpnSecurityKind.None,                // EoGRE/NVGRE only tunnel the L2 frame — no encryption
            AuthMethods = VpnAuthMethod.None,                    // no control plane, no authentication
            AddressAssignment = AddressAssignment.OutOfBand,     // the endpoint sets its own static overlay address
            // RequiresRawIpSocket / RequiresElevation stay false: plain UDP, no elevation.
        };

        /// <inheritdoc/>
        public async Task<IVpnConnection> ConnectAsync(VpnEndpoint endpoint, VpnCredentials credentials, CancellationToken cancellationToken = default)
        {
            if (endpoint is null) throw new ArgumentNullException(nameof(endpoint));

            IEoGreTransportFactory factory = _transportFactory ?? new EoGreUdpTransportFactory();
            var connection = new EoGreConnection(endpoint.Host, factory, _config, _mode,
                reconnectOptions: _reconnectOptions,
                addressFamilyPreference: endpoint.AddressFamilyPreference,
                loggerFactory: _loggerFactory);
            try
            {
                await connection.ConnectAsync(cancellationToken).ConfigureAwait(false);
                var session = new EoGreVpnSession(connection.PacketChannel, connection.Config);
                return new EoGreVpnConnection(connection, session);
            }
            catch
            {
                await connection.DisposeAsync().ConfigureAwait(false);
                throw;
            }
        }
    }
}
