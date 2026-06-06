using TqkLibrary.Vpn.Abstractions.Drivers;
using TqkLibrary.Vpn.Abstractions.Drivers.Interfaces;
using TqkLibrary.Vpn.Abstractions.Drivers.Models;

namespace TqkLibrary.Vpn
{
    /// <summary>The library entry point: holds the registered protocol drivers and opens connections.</summary>
    public sealed class VpnClient
    {
        readonly IReadOnlyDictionary<string, IVpnProtocolDriver> _drivers;

        internal VpnClient(IReadOnlyDictionary<string, IVpnProtocolDriver> drivers) => _drivers = drivers;

        /// <summary>The registered protocol names (e.g. "sstp").</summary>
        public IEnumerable<string> Protocols => _drivers.Keys;

        /// <summary>Connects using the named protocol's driver.</summary>
        public Task<IVpnConnection> ConnectAsync(string protocol, VpnEndpoint endpoint, VpnCredentials credentials, CancellationToken cancellationToken = default)
        {
            if (!_drivers.TryGetValue(protocol, out IVpnProtocolDriver? driver))
                throw new NotSupportedException($"No VPN driver registered for protocol '{protocol}'. Registered: {string.Join(", ", _drivers.Keys)}.");

            return driver.ConnectAsync(endpoint, credentials, cancellationToken);
        }

        /// <summary>The capabilities of a registered driver.</summary>
        public VpnDriverCapabilities GetCapabilities(string protocol) => _drivers[protocol].Capabilities;
    }
}
