using TqkLibrary.Vpn.Abstractions.Drivers.Interfaces;
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

        /// <summary>Registers the MS-SSTP driver.</summary>
        public VpnClientBuilder UseSstp() => AddDriver(new SstpDriver());

        /// <summary>Builds the client.</summary>
        public VpnClient Build() => new VpnClient(_drivers);
    }
}
