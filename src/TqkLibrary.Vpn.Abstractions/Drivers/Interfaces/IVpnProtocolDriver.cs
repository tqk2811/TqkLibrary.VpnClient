using TqkLibrary.Vpn.Abstractions.Drivers.Models;

namespace TqkLibrary.Vpn.Abstractions.Drivers.Interfaces
{
    /// <summary>
    /// The single plugin entry point for a VPN protocol. The façade discovers drivers, reads their
    /// <see cref="Capabilities"/>, then calls <see cref="ConnectAsync"/>.
    /// </summary>
    public interface IVpnProtocolDriver
    {
        /// <summary>Stable identifier, e.g. "sstp", "l2tp-ipsec".</summary>
        string Name { get; }

        /// <summary>What this driver can do (link layer, transports, security, auth, elevation needs...).</summary>
        VpnDriverCapabilities Capabilities { get; }

        /// <summary>Connects to <paramref name="endpoint"/>, authenticating with <paramref name="credentials"/>.</summary>
        Task<IVpnConnection> ConnectAsync(
            VpnEndpoint endpoint,
            VpnCredentials credentials,
            CancellationToken cancellationToken = default);
    }
}
