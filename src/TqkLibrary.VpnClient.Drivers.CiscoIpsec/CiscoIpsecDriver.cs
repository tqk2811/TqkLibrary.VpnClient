using System.Text;
using Microsoft.Extensions.Logging;
using TqkLibrary.VpnClient.Abstractions.Drivers.Enums;
using TqkLibrary.VpnClient.Abstractions.Drivers.Interfaces;
using TqkLibrary.VpnClient.Abstractions.Drivers.Models;

namespace TqkLibrary.VpnClient.Drivers.CiscoIpsec
{
    /// <summary>
    /// The Cisco IPsec / EzVPN remote-access protocol driver: IKEv1 <b>Aggressive Mode</b> with a group PSK, then
    /// <b>XAUTH</b> (user name/password) and <b>Mode-Config</b> (pulls the virtual IP/DNS) over forced NAT-T, finishing
    /// with a Quick Mode that installs an ESP <b>tunnel-mode</b> CHILD SA. The decapsulated inner IP packets ride
    /// straight to the userspace stack — no PPP, no L2TP.
    /// <para><b>Security note:</b> Aggressive Mode + group PSK is a known-weak Phase 1 (the responder's HASH_R lets an
    /// eavesdropper mount an offline dictionary attack on the group PSK). This driver exists only to interop with legacy
    /// Cisco-compatible gateways (strongSwan/vpnc EzVPN); prefer IKEv2 or L2TP/IPsec Main Mode where available.</para>
    /// </summary>
    public sealed class CiscoIpsecDriver : IVpnProtocolDriver
    {
        readonly string _groupName;
        readonly CiscoIpsecReconnectOptions? _reconnectOptions;
        readonly ILoggerFactory? _loggerFactory;

        /// <summary>
        /// Creates the driver for the Aggressive Mode group named <paramref name="groupName"/> (the gateway selects the
        /// group PSK by this name, sent in the clear in message 1). The group PSK is supplied per connect via
        /// <see cref="VpnCredentials.PreSharedKey"/>, and the XAUTH user name/password via
        /// <see cref="VpnCredentials.Username"/> / <see cref="VpnCredentials.Password"/>.
        /// <paramref name="reconnectOptions"/> tunes (or disables) auto-reconnect; <paramref name="loggerFactory"/>
        /// receives diagnostic traces (handshake/XAUTH/DPD/rekey/reconnect) — null logs to a no-op logger.
        /// </summary>
        public CiscoIpsecDriver(string groupName, CiscoIpsecReconnectOptions? reconnectOptions = null,
            ILoggerFactory? loggerFactory = null)
        {
            _groupName = groupName ?? throw new ArgumentNullException(nameof(groupName));
            _reconnectOptions = reconnectOptions;
            _loggerFactory = loggerFactory;
        }

        /// <inheritdoc/>
        public string Name => "cisco-ipsec";

        /// <inheritdoc/>
        public VpnDriverCapabilities Capabilities { get; } = new VpnDriverCapabilities
        {
            LinkLayer = VpnLinkLayer.L3Ip,
            UsesPpp = false,                                       // ESP tunnel mode → IP channel directly (no PPP/L2TP)
            MultiHostModel = MultiHostModel.None,
            TransportKinds = VpnTransportKind.Udp,
            SecurityKinds = VpnSecurityKind.Esp,
            // The gateway is authenticated by the group PSK (Aggressive Mode); the user is authenticated by XAUTH
            // (user name/password). Both halves are required.
            AuthMethods = VpnAuthMethod.PreSharedKey | VpnAuthMethod.UserPassword,
            AddressAssignment = AddressAssignment.ConfigPush,      // Mode-Config pushes the virtual IP/DNS
        };

        /// <inheritdoc/>
        public async Task<IVpnConnection> ConnectAsync(VpnEndpoint endpoint, VpnCredentials credentials, CancellationToken cancellationToken = default)
        {
            byte[]? groupPsk = credentials.PreSharedKey;
            if (groupPsk is null || groupPsk.Length == 0)
                throw new ArgumentException(
                    "Cisco IPsec requires the group pre-shared key (the Aggressive Mode group secret). Set VpnCredentials.PreSharedKey.",
                    nameof(credentials));

            // XAUTH needs both the user name and the password; a half-filled credential is a configuration mistake.
            if (string.IsNullOrEmpty(credentials.Username) || string.IsNullOrEmpty(credentials.Password))
                throw new ArgumentException(
                    "Cisco IPsec XAUTH requires both VpnCredentials.Username and VpnCredentials.Password.",
                    nameof(credentials));

            var connection = new CiscoIpsecConnection(endpoint.Host, _groupName, groupPsk,
                credentials.Username!, credentials.Password!,
                reconnectOptions: _reconnectOptions,
                addressFamilyPreference: endpoint.AddressFamilyPreference,
                loggerFactory: _loggerFactory);
            try
            {
                await connection.ConnectAsync(cancellationToken).ConfigureAwait(false);

                var config = new TunnelConfig { AssignedAddress = connection.AssignedAddress };
                if (connection.AssignedDns != null) config.DnsServers.Add(connection.AssignedDns);

                var session = new CiscoIpsecVpnSession(connection.PacketChannel, config);
                connection.Reconnected += info => session.ApplyReconnect(info, connection.AssignedDns);
                return new CiscoIpsecVpnConnection(connection, session);
            }
            catch
            {
                await connection.DisposeAsync().ConfigureAwait(false);
                throw;
            }
        }
    }
}
