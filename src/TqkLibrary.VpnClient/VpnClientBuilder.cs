using System.Net.Security;
using System.Security.Cryptography.X509Certificates;
using TqkLibrary.VpnClient.Abstractions.Drivers.Interfaces;
using TqkLibrary.VpnClient.Drivers.Ikev2;
using TqkLibrary.VpnClient.Drivers.L2tpIpsec;
using TqkLibrary.VpnClient.Drivers.OpenVpn;
using TqkLibrary.VpnClient.Drivers.Sstp;
using TqkLibrary.VpnClient.Drivers.WireGuard;
using TqkLibrary.VpnClient.OpenVpn.Config;
using TqkLibrary.VpnClient.WireGuard.Config;

namespace TqkLibrary.VpnClient
{
    /// <summary>Fluent builder that registers protocol drivers and produces a <see cref="VpnClient"/>.</summary>
    public sealed class VpnClientBuilder
    {
        readonly Dictionary<string, IVpnProtocolDriver> _drivers = new();

        /// <summary>Registers a driver (keyed by its <see cref="IVpnProtocolDriver.Name"/>).</summary>
        public VpnClientBuilder AddDriver(IVpnProtocolDriver driver)
        {
            _drivers[driver.Name] = driver;
            return this;
        }

        /// <summary>Registers the MS-SSTP driver with auto-reconnect enabled by default.</summary>
        public VpnClientBuilder UseSstp() => AddDriver(new SstpDriver());

        /// <summary>Registers the MS-SSTP driver with explicit auto-reconnect options (e.g. to disable it).</summary>
        public VpnClientBuilder UseSstp(SstpReconnectOptions reconnectOptions) => AddDriver(new SstpDriver(reconnectOptions));

        /// <summary>Registers the MS-SSTP driver with a TLS server-certificate validation callback (default behavior accepts any cert).</summary>
        public VpnClientBuilder UseSstp(RemoteCertificateValidationCallback certificateValidationCallback)
            => AddDriver(new SstpDriver(certificateValidationCallback: certificateValidationCallback));

        /// <summary>Registers the MS-SSTP driver with explicit auto-reconnect options and a TLS server-certificate validation callback.</summary>
        public VpnClientBuilder UseSstp(SstpReconnectOptions reconnectOptions, RemoteCertificateValidationCallback certificateValidationCallback)
            => AddDriver(new SstpDriver(reconnectOptions, certificateValidationCallback));

        /// <summary>Registers the L2TP/IPsec driver (IKEv1 PSK + NAT-T) with auto-reconnect enabled by default.</summary>
        public VpnClientBuilder UseL2tpIpsec() => AddDriver(new L2tpIpsecDriver());

        /// <summary>Registers the L2TP/IPsec driver with explicit auto-reconnect options (e.g. to disable it).</summary>
        public VpnClientBuilder UseL2tpIpsec(L2tpIpsecReconnectOptions reconnectOptions) => AddDriver(new L2tpIpsecDriver(reconnectOptions));

        /// <summary>Registers the L2TP/IPsec driver with explicit auto-reconnect and IKE/L2TP timeout options.</summary>
        public VpnClientBuilder UseL2tpIpsec(L2tpIpsecReconnectOptions reconnectOptions, L2tpIpsecTimeoutOptions timeoutOptions)
            => AddDriver(new L2tpIpsecDriver(reconnectOptions, timeoutOptions));

        /// <summary>Registers the IKEv2-native driver (RFC 7296 PSK + NAT-T, CP virtual IP, ESP tunnel mode) with auto-reconnect enabled by default.</summary>
        public VpnClientBuilder UseIkev2() => AddDriver(new Ikev2Driver());

        /// <summary>Registers the IKEv2-native driver with explicit auto-reconnect options (e.g. to disable it).</summary>
        public VpnClientBuilder UseIkev2(Ikev2ReconnectOptions reconnectOptions) => AddDriver(new Ikev2Driver(reconnectOptions));

        /// <summary>Registers the OpenVPN driver (community-server compatible: UDP/TCP, tun-mode, NCP AEAD) from a parsed profile.</summary>
        public VpnClientBuilder UseOpenVpn(OpenVpnProfile profile) => AddDriver(new OpenVpnDriver(profile));

        /// <summary>Registers the OpenVPN driver with client certificates and an optional server-certificate validation callback.</summary>
        public VpnClientBuilder UseOpenVpn(OpenVpnProfile profile, X509CertificateCollection? clientCertificates,
            RemoteCertificateValidationCallback? serverCertificateValidation = null, OpenVpnReconnectOptions? reconnectOptions = null)
            => AddDriver(new OpenVpnDriver(profile, clientCertificates, serverCertificateValidation, reconnectOptions: reconnectOptions));

        /// <summary>Registers the WireGuard driver (UDP, Noise_IKpsk2, static point-to-point config) with auto-reconnect enabled by default.</summary>
        public VpnClientBuilder UseWireGuard(WireGuardConfig config) => AddDriver(new WireGuardDriver(config));

        /// <summary>Registers the WireGuard driver with explicit auto-reconnect options (e.g. to disable it).</summary>
        public VpnClientBuilder UseWireGuard(WireGuardConfig config, WireGuardReconnectOptions reconnectOptions)
            => AddDriver(new WireGuardDriver(config, reconnectOptions));

        /// <summary>Builds the client.</summary>
        public VpnClient Build() => new VpnClient(_drivers);
    }
}
