using Microsoft.Extensions.Logging;
using TqkLibrary.VpnClient.Abstractions.Drivers.Enums;
using TqkLibrary.VpnClient.Abstractions.Drivers.Interfaces;
using TqkLibrary.VpnClient.Abstractions.Drivers.Models;
using TqkLibrary.VpnClient.Ipsec.Ike.V2.Models;
using TqkLibrary.VpnClient.Ipsec.Ike.V2.Payloads;

namespace TqkLibrary.VpnClient.Drivers.Ikev2
{
    /// <summary>The IKEv2-native protocol driver (RFC 7296 PSK over NAT-T, CP virtual IP, ESP tunnel mode — no PPP).</summary>
    public sealed class Ikev2Driver : IVpnProtocolDriver
    {
        readonly Ikev2ReconnectOptions? _reconnectOptions;
        readonly ILoggerFactory? _loggerFactory;
        readonly IkeCertificateTrust? _responderTrust;
        readonly IReadOnlyList<TrafficSelector>? _initiatorSelectors;
        readonly IReadOnlyList<TrafficSelector>? _responderSelectors;

        /// <summary>
        /// Creates the driver; <paramref name="reconnectOptions"/> tunes (or disables) auto-reconnect and
        /// <paramref name="loggerFactory"/> receives diagnostic traces (null = no logging).
        /// <para>When <paramref name="responderTrust"/> is supplied the driver verifies a gateway that authenticates with
        /// a certificate (RFC 7296 §2.15 digital signature) against that trust — an untrusted certificate or a bad
        /// signature is rejected with <see cref="Abstractions.Drivers.VpnServerRejectedException"/>. The optional
        /// <paramref name="initiatorSelectors"/> / <paramref name="responderSelectors"/> request several traffic
        /// selectors (split-tunnel subnets, RFC 7296 §3.13); null offers a single match-all IPv4 selector as before.</para>
        /// </summary>
        public Ikev2Driver(Ikev2ReconnectOptions? reconnectOptions = null, ILoggerFactory? loggerFactory = null,
            IkeCertificateTrust? responderTrust = null,
            IReadOnlyList<TrafficSelector>? initiatorSelectors = null,
            IReadOnlyList<TrafficSelector>? responderSelectors = null)
        {
            _reconnectOptions = reconnectOptions;
            _loggerFactory = loggerFactory;
            _responderTrust = responderTrust;
            _initiatorSelectors = initiatorSelectors;
            _responderSelectors = responderSelectors;
        }

        /// <inheritdoc/>
        public string Name => "ikev2";

        /// <inheritdoc/>
        public VpnDriverCapabilities Capabilities => new VpnDriverCapabilities
        {
            LinkLayer = VpnLinkLayer.L3Ip,
            UsesPpp = false,
            MultiHostModel = MultiHostModel.None,
            TransportKinds = VpnTransportKind.Udp,
            SecurityKinds = VpnSecurityKind.Esp,
            // The gateway is always authenticated by PSK or EAP; certificate (digital-signature) verification of the
            // responder is added when this driver instance was configured with a certificate trust anchor.
            AuthMethods = VpnAuthMethod.PreSharedKey | VpnAuthMethod.Eap
                | (_responderTrust is not null ? VpnAuthMethod.Certificate : VpnAuthMethod.None),
            AddressAssignment = AddressAssignment.ConfigPush,
        };

        /// <inheritdoc/>
        public async Task<IVpnConnection> ConnectAsync(VpnEndpoint endpoint, VpnCredentials credentials, CancellationToken cancellationToken = default)
        {
            byte[]? psk = credentials.PreSharedKey;
            if (psk is null || psk.Length == 0)
                throw new ArgumentException(
                    "IKEv2 requires a pre-shared key (it authenticates the gateway). Set VpnCredentials.PreSharedKey.", nameof(credentials));

            // A user name + password switches the initiator to EAP-MSCHAPv2 (RFC 7296 §2.16); without them the
            // initiator authenticates with the PSK too. A user name with no password (or vice versa) is ambiguous.
            string? eapUserName = credentials.Username;
            string? eapPassword = credentials.Password;
            if (string.IsNullOrEmpty(eapUserName) != string.IsNullOrEmpty(eapPassword))
                throw new ArgumentException(
                    "IKEv2 EAP-MSCHAPv2 needs both VpnCredentials.Username and VpnCredentials.Password (or neither, for PSK auth).",
                    nameof(credentials));

            var connection = new Ikev2Connection(endpoint.Host, psk, reconnectOptions: _reconnectOptions,
                addressFamilyPreference: endpoint.AddressFamilyPreference,
                eapUserName: string.IsNullOrEmpty(eapUserName) ? null : eapUserName,
                eapPassword: string.IsNullOrEmpty(eapPassword) ? null : eapPassword,
                responderTrust: _responderTrust,
                initiatorSelectors: _initiatorSelectors,
                responderSelectors: _responderSelectors,
                loggerFactory: _loggerFactory);
            try
            {
                await connection.ConnectAsync(cancellationToken).ConfigureAwait(false);

                var config = new TunnelConfig { AssignedAddress = connection.AssignedAddress };
                if (connection.AssignedDns != null) config.DnsServers.Add(connection.AssignedDns);

                var session = new Ikev2VpnSession(connection.PacketChannel, config);
                connection.Reconnected += info => session.ApplyReconnect(info, connection.AssignedDns);
                return new Ikev2VpnConnection(connection, session);
            }
            catch
            {
                await connection.DisposeAsync().ConfigureAwait(false);
                throw;
            }
        }
    }
}
