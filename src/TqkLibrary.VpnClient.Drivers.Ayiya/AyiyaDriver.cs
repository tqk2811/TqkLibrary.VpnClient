using System;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.Logging;
using TqkLibrary.VpnClient.Abstractions.Drivers.Enums;
using TqkLibrary.VpnClient.Abstractions.Drivers.Interfaces;
using TqkLibrary.VpnClient.Abstractions.Drivers.Models;

namespace TqkLibrary.VpnClient.Drivers.Ayiya
{
    /// <summary>
    /// The AYIYA (Anything In Anything, draft-massar-v6ops-ayiya-02) tunnel-broker driver (key <c>"ayiya"</c>) in
    /// <b>static</b> mode: carries an IPv6 packet inside a UDP payload behind an AYIYA header (field header + epoch time +
    /// identity + signature), integrity-signed with the shared-secret hash (aiccu algorithm) and replay-guarded by the
    /// epoch time, then binds the reused IPv6 passthrough channel behind a stable L3 packet channel. Because the carrier is
    /// an ordinary UDP socket it needs <b>no elevation and no raw IP socket</b> and traverses NAT/firewalls that pass UDP.
    /// Static mode skips the TIC control channel — the endpoint, identity and shared secret are configured up front.
    /// <para><b>AYIYA does NOT encrypt the payload</b> — it signs integrity and guards replay only. Use only on a trusted
    /// path or under an outer secure layer.</para>
    /// </summary>
    public sealed class AyiyaDriver : IVpnProtocolDriver
    {
        readonly IAyiyaTransportFactory _transportFactory;
        readonly AyiyaOptions _options;
        readonly AyiyaReconnectOptions? _reconnectOptions;
        readonly Func<uint>? _epochClock;
        readonly ILoggerFactory? _loggerFactory;

        /// <summary>
        /// Creates the driver. <paramref name="options"/> supplies the identity, shared secret, UDP port, MTU and clock-skew
        /// tolerance (required); <paramref name="reconnectOptions"/> tunes (or disables) auto-reconnect.
        /// <paramref name="transportFactory"/> carries the data plane over a connected UDP socket (needs no elevation); when
        /// null the production <see cref="AyiyaUdpTransportFactory"/> is used. <paramref name="epochClock"/> supplies the
        /// epoch seconds (default: system UTC clock). <paramref name="loggerFactory"/> receives diagnostic traces (null = no logging).
        /// </summary>
        public AyiyaDriver(AyiyaOptions options, AyiyaReconnectOptions? reconnectOptions = null,
            IAyiyaTransportFactory? transportFactory = null, Func<uint>? epochClock = null, ILoggerFactory? loggerFactory = null)
        {
            _options = options ?? throw new ArgumentNullException(nameof(options));
            _transportFactory = transportFactory ?? new AyiyaUdpTransportFactory();
            _reconnectOptions = reconnectOptions;
            _epochClock = epochClock;
            _loggerFactory = loggerFactory;
        }

        /// <inheritdoc/>
        public string Name => "ayiya";

        /// <inheritdoc/>
        public VpnDriverCapabilities Capabilities { get; } = new VpnDriverCapabilities
        {
            LinkLayer = VpnLinkLayer.L3Ip,
            UsesPpp = false,
            MultiHostModel = MultiHostModel.None,
            TransportKinds = VpnTransportKind.Udp,             // data rides an ordinary UDP datagram pipe
            SecurityKinds = VpnSecurityKind.None,              // payload UNENCRYPTED — AYIYA signs integrity, does not encrypt
            AuthMethods = VpnAuthMethod.PreSharedKey,          // shared secret authenticates each datagram (SHA-1 keyed)
            AddressAssignment = AddressAssignment.OutOfBand,   // static mode — the tunnel address is arranged out of band
            RequiresRawIpSocket = false,                       // the payload rides UDP, not a bare protocol number
            RequiresElevation = false,                         // an ordinary UDP socket needs no admin/root/CAP_NET_RAW
        };

        /// <inheritdoc/>
        public async Task<IVpnConnection> ConnectAsync(VpnEndpoint endpoint, VpnCredentials credentials, CancellationToken cancellationToken = default)
        {
            if (endpoint is null) throw new ArgumentNullException(nameof(endpoint));

            var connection = new AyiyaConnection(endpoint.Host, _transportFactory, _options,
                reconnectOptions: _reconnectOptions,
                addressFamilyPreference: endpoint.AddressFamilyPreference,
                epochClock: _epochClock,
                loggerFactory: _loggerFactory);
            try
            {
                await connection.ConnectAsync(cancellationToken).ConfigureAwait(false);

                TunnelConfig config = _options.ToTunnelConfig();
                var session = new AyiyaVpnSession(connection.PacketChannel, config);
                return new AyiyaVpnConnection(connection, session);
            }
            catch
            {
                await connection.DisposeAsync().ConfigureAwait(false);
                throw;
            }
        }
    }
}
