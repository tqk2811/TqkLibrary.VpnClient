using System.Net.Security;
using TqkLibrary.Vpn.Abstractions.Drivers.Interfaces;
using TqkLibrary.Vpn.Drivers.L2tpIpsec;
using TqkLibrary.Vpn.Drivers.Sstp;

namespace TqkLibrary.Vpn
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

        /// <summary>Builds the client.</summary>
        public VpnClient Build() => new VpnClient(_drivers);
    }
}
