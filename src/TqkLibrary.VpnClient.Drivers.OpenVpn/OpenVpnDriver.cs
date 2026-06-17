using System.Net.Security;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using TqkLibrary.VpnClient.Abstractions.Drivers.Enums;
using TqkLibrary.VpnClient.Abstractions.Drivers.Interfaces;
using TqkLibrary.VpnClient.Abstractions.Drivers.Models;
using TqkLibrary.VpnClient.Drivers.OpenVpn.Transport;
using TqkLibrary.VpnClient.OpenVpn;
using TqkLibrary.VpnClient.OpenVpn.Config;
using TqkLibrary.VpnClient.OpenVpn.Enums;

namespace TqkLibrary.VpnClient.Drivers.OpenVpn
{
    /// <summary>
    /// The OpenVPN protocol driver (community-server compatible). It is configured with an <see cref="OpenVpnProfile"/>
    /// (the parsed <c>.ovpn</c>) that supplies the device/transport/cipher and the <c>tls-auth</c>/<c>tls-crypt</c>
    /// static keys; the connect-time <see cref="VpnEndpoint"/> gives the server address and <see cref="VpnCredentials"/>
    /// the optional <c>auth-user-pass</c>. tun-mode (L3) outputs bare IP; tap-mode (L2) bridges Ethernet frames through
    /// the userspace L2 fabric (<c>OpenVpnTapChannel</c> → <c>EthernetAdapter</c>) and advertises an
    /// <see cref="VpnLinkLayer.L2Ethernet"/> / <see cref="MultiHostModel.L2BroadcastDomain"/> capability (L2.8).
    /// </summary>
    public sealed class OpenVpnDriver : IVpnProtocolDriver
    {
        readonly OpenVpnProfile _profile;
        readonly X509CertificateCollection? _clientCertificates;
        readonly RemoteCertificateValidationCallback? _serverCertificateValidation;
        readonly IOpenVpnControlWrap? _controlWrap;
        readonly OpenVpnReconnectOptions? _reconnectOptions;

        /// <summary>
        /// Creates the driver. <paramref name="profile"/> is the parsed configuration; <paramref name="clientCertificates"/>
        /// authenticate the client (OpenVPN cert auth) when the server requires it; <paramref name="serverCertificateValidation"/>
        /// validates the server certificate (null = accept any — supply a real CA check for production);
        /// <paramref name="controlWrap"/> overrides the <c>tls-auth</c>/<c>tls-crypt</c> wrap built from the profile's
        /// inline static keys (supply one when the key is referenced by file path); <paramref name="reconnectOptions"/>
        /// tunes (or disables) auto-reconnect.
        /// </summary>
        public OpenVpnDriver(OpenVpnProfile profile,
            X509CertificateCollection? clientCertificates = null,
            RemoteCertificateValidationCallback? serverCertificateValidation = null,
            IOpenVpnControlWrap? controlWrap = null,
            OpenVpnReconnectOptions? reconnectOptions = null)
        {
            _profile = profile ?? throw new ArgumentNullException(nameof(profile));
            _clientCertificates = clientCertificates;
            _serverCertificateValidation = serverCertificateValidation;
            _controlWrap = controlWrap;
            _reconnectOptions = reconnectOptions;
            Capabilities = BuildCapabilities(_profile);
        }

        /// <inheritdoc/>
        public string Name => "openvpn";

        /// <inheritdoc/>
        /// <remarks>
        /// Profile-aware: <c>dev tun</c> outputs bare IP (<see cref="VpnLinkLayer.L3Ip"/>, single host); <c>dev tap</c>
        /// bridges Ethernet frames through the userspace L2 fabric (<c>OpenVpnTapChannel</c> → <c>EthernetAdapter</c>),
        /// so it advertises <see cref="VpnLinkLayer.L2Ethernet"/> + <see cref="MultiHostModel.L2BroadcastDomain"/> (L2.8).
        /// </remarks>
        public VpnDriverCapabilities Capabilities { get; }

        static VpnDriverCapabilities BuildCapabilities(OpenVpnProfile profile)
        {
            bool tap = profile.Device == OpenVpnDeviceType.Tap;
            return new VpnDriverCapabilities
            {
                // tun-mode → bare IP, single host; tap-mode → Ethernet frames over the L2 broadcast domain (EthernetAdapter).
                LinkLayer = tap ? VpnLinkLayer.L2Ethernet : VpnLinkLayer.L3Ip,
                SupportsMultiHost = tap,
                MultiHostModel = tap ? MultiHostModel.L2BroadcastDomain : MultiHostModel.None,
                UsesPpp = false,                                               // PUSH_REPLY config, not PPP
                TransportKinds = VpnTransportKind.Udp | VpnTransportKind.Tcp,
                SecurityKinds = VpnSecurityKind.Tls,                            // TLS control channel + AEAD data channel
                AuthMethods = VpnAuthMethod.Certificate | VpnAuthMethod.UserPassword,
                AddressAssignment = AddressAssignment.ConfigPush,
            };
        }

        /// <inheritdoc/>
        public async Task<IVpnConnection> ConnectAsync(VpnEndpoint endpoint, VpnCredentials credentials, CancellationToken cancellationToken = default)
        {
            if (endpoint is null) throw new ArgumentNullException(nameof(endpoint));
            if (credentials is null) throw new ArgumentNullException(nameof(credentials));

            var factory = new OpenVpnSocketTransportFactory(_profile.Protocol);
            var connection = new OpenVpnConnection(endpoint.Host, endpoint.Port, factory,
                optionsString: BuildOccOptions(_profile),
                device: _profile.Device,
                username: credentials.Username,
                password: credentials.Password,
                clientCertificates: _clientCertificates,
                serverCertificateValidation: _serverCertificateValidation,
                controlWrap: _controlWrap ?? BuildControlWrap(_profile),
                reconnectOptions: _reconnectOptions,
                addressFamilyPreference: endpoint.AddressFamilyPreference,
                tunMtu: _profile.TunMtu ?? 1500);
            try
            {
                await connection.ConnectAsync(cancellationToken).ConfigureAwait(false);

                var session = new OpenVpnVpnSession(connection.PacketChannel, connection.Config);
                connection.Reconnected += info => session.ApplyReconnect(info, connection.Config);
                return new OpenVpnVpnConnection(connection, session);
            }
            catch
            {
                await connection.DisposeAsync().ConfigureAwait(false);
                throw;
            }
        }

        // tls-crypt (fixed direction) wins over tls-auth; both built from the profile's inline static key (file-path
        // keys: pass a pre-built wrap via the ctor). No directive ⇒ control packets ride the wire verbatim.
        static IOpenVpnControlWrap? BuildControlWrap(OpenVpnProfile profile)
        {
            if (profile.TlsCrypt?.Inline is string tlsCrypt)
                return new OpenVpnTlsCryptWrap(OpenVpnStaticKey.Parse(tlsCrypt), isServer: false);
            if (profile.TlsAuth?.Inline is string tlsAuth)
            {
                OpenVpnKeyDirection direction = profile.KeyDirection switch
                {
                    0 => OpenVpnKeyDirection.Normal,
                    1 => OpenVpnKeyDirection.Inverse,
                    _ => OpenVpnKeyDirection.Bidirectional,
                };
                return new OpenVpnTlsAuthWrap(OpenVpnStaticKey.Parse(tlsAuth), direction, ParseHash(profile.Auth));
            }
            return null;
        }

        static HashAlgorithmName ParseHash(string? auth) => auth?.ToUpperInvariant() switch
        {
            "SHA256" => HashAlgorithmName.SHA256,
            "SHA384" => HashAlgorithmName.SHA384,
            "SHA512" => HashAlgorithmName.SHA512,
            _ => HashAlgorithmName.SHA1, // OpenVPN's tls-auth default
        };

        // A representative OCC options string for key-method-2. Strict --opt-verify matching is rarely enabled and is a
        // live-interop refinement (lab Q.1); most servers ignore it.
        static string BuildOccOptions(OpenVpnProfile profile)
        {
            string dev = profile.Device == OpenVpnDeviceType.Tap ? "tap" : "tun";
            string proto = profile.Protocol == OpenVpnProtocol.Tcp ? "TCPv4" : "UDPv4";
            string cipher = profile.Cipher ?? "AES-256-GCM";
            string auth = profile.Auth ?? "SHA1";
            return $"V4,dev-type {dev},link-mtu 1543,tun-mtu 1500,proto {proto},cipher {cipher},auth {auth},keysize 256,key-method 2,tls-client";
        }
    }
}
